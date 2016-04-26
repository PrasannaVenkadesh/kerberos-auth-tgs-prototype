#!/usr/bin/env python2.7

"""
License: GNU GPL V3
Copyleft License
"""

import json
import random
import string
import base64
import sqlite3
from Crypto.Cipher import AES
from datetime import datetime
from flask import Flask, jsonify, request

app = Flask(__name__)

initial_vector = "secretsecretsecr"

@app.route('/authenticate', methods=['POST'])
def authentication_server():
    if request.method == 'POST':

        # fetch all the values sent from the client
        user_name = request.json.get('userid')
        service_name = request.json.get('service_id')
        nw_addr = request.json.get('nw_addr')
        lifetime_of_tgt = request.json.get('lifetime_of_tgt')
        
        # check if the user_id exists in the kdc database
        db_connection = sqlite3.connect('kdc.db')
        db_cursor = db_connection.cursor()
        db_cursor.execute("Select secret_key from users where username='%s' limit 1" % user_name)
        query_result = db_cursor.fetchone()

        # if user id exists, fetch user secret key and
        # generate a random session key for TGS
        if query_result:
            user_secret_key = query_result[0]
            user_tgs_session_key = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(16)])[0:16]

        # fetch tgs_secret_key
        db_cursor.execute("select secret_key from services where service_name='tgs' limit 1")
        tgs_secret_key = db_cursor.fetchone()[0]


        # create payload to encrypt and send
        auth_ack_payload = {"service_id": str(service_name), "timestamp": str(datetime.now()), 
                "lifetime": str(lifetime_of_tgt), "tgs_session_key": str(user_tgs_session_key)}

        tgt_payload = {"user_id": str(user_name), "service_id": str(service_name), "timestamp": str(datetime.now()), 
                "nw_addr": str(nw_addr), "lifetime": str(lifetime_of_tgt), "tgs_session_key": str(user_tgs_session_key)}

        """
        Authentication acknowledgement should be encrypted using client's shared
        secret key, before sending it to the client (AES - Symmetric Key). The client
        should be able to decrypt this section.
        """
        auth_encryption_suite = AES.new(user_secret_key, AES.MODE_CFB, initial_vector)
        auth_ack = auth_encryption_suite.encrypt(str(auth_ack_payload))

        """
        The client should produce this ticket granting ticket to the Ticket Granting
        Server in order to obtain the actual ticket for the service it looks for. So
        the client shouldn't be able to modify this section. In order to achieve that,
        we are encrypting this data with Ticket Granting Server's shared key with the
        Authentication Server.
        """
        tgt_encryption_suite = AES.new(tgs_secret_key, AES.MODE_CFB, initial_vector)
        tgt = tgt_encryption_suite.encrypt(str(tgt_payload))
        
        # close the open database cursor and connection
        db_cursor.close()
        db_connection.close()

        print "Acknowledgement and Ticket Granting Ticket sent to %s" % str(nw_addr)
        
        # send acknowledge and ticket granting ticket to client as json response
        return jsonify({"ack": base64.b64encode(auth_ack), "tgt": base64.b64encode(tgt)})

@app.route('/ticket', methods=['POST'])
def ticket_granting_server():
    if request.method == 'POST':
    
        # fetch all the values sent from the client
        authenticator = base64.b64decode(request.json.get('authenticator'))
        ticket_granting_ticket_encrypted = base64.b64decode(request.json.get('ticket_granting_ticket'))
        tg_request = request.json.get('ticket_granting_request')
        
        #print ("Authenticator: ", authenticator)
        #print ("Ticket Granting Ticket: ", ticket_granting_ticket_encrypted)
        #print ("Ticket Granting Request: ", tg_request)
        
        # clean the recevied raw data to process it further
        json_format = tg_request.replace("'", "\"")
        tg_request = json.loads(json_format)
        
        # Check if the service requested by the user is present in the KDC database
        # open connection and cursor to db
        db_connection = sqlite3.connect('kdc.db')
        db_cursor = db_connection.cursor()
        
        # query the db for the service name
        db_cursor.execute("SELECT secret_key FROM services WHERE service_name='%s' LIMIT 1" % tg_request.get('service_id'))
        service_secret_key = db_cursor.fetchone()[0]
        
        if service_secret_key:
            """
            TGS need to decrypt the ticket granting ticket offered to the client by
            Authentication Server. Note, since this ticket can only be decrypted by
            TGS's secret key, not even the client can know what is inside this. So
            we need to fetch this key from the kdc database.
            """
            db_cursor.execute("SELECT secret_key from services where service_name='tgs' limit 1")
            tgs_secret_key = db_cursor.fetchone()[0]
            
            if tgs_secret_key:
                tgs_dec_suite = AES.new(tgs_secret_key, AES.MODE_CFB, initial_vector)
                ticket_granting_ticket_plain = tgs_dec_suite.decrypt(ticket_granting_ticket_encrypted)
                
                # converting the data from sting to python dictionary
                json_format = ticket_granting_ticket_plain.replace("'", "\"")
                ticket_granting_ticket = json.loads(json_format)
                print "Received TGT from Client obtained from Authentication Server"
                print ticket_granting_ticket
            else:
                print "Tgs secret key or service not found"
                
            
            """
            TGS also need to decrypt the authenticator message from the client node.
            Remember, this message was encrypted using the TGS_SESSION_KEY obtained by the
            client from the Authentication Server. This TGS knows the TGS_SESSION_KEY from
            the above decryption. Now we can make use of the same to decrypt this message.
            """
            auth_dec_suite = AES.new(ticket_granting_ticket.get('tgs_session_key'), AES.MODE_CFB, initial_vector)
            authenticator_plain = auth_dec_suite.decrypt(authenticator)
            
            # converting the data from string to python dictionary
            json_format = authenticator_plain.replace("'", "\"")
            authenticator_dict = json.loads(json_format)
            
            # compare the user_id from authenticator as well as tgt
            if authenticator_dict.get('user_id') == ticket_granting_ticket.get('user_id'):
                auth_timestamp = datetime.strptime(authenticator_dict.get('timestamp'), "%Y-%m-%d %H:%M:%S.%f")
                tgt_timestamp = datetime.strptime(ticket_granting_ticket.get('timestamp'), "%Y-%m-%d %H:%M:%S.%f")
                elapsed_time_in_hours = divmod((auth_timestamp - tgt_timestamp).seconds, 3600)[0]
                
                # compare the difference between timestamp authenticator - tgt (threshold is 2 minutes)
                if True:
                    # check if tgt is expired using the lifetime value of the ticket
                    # difference of current timestamp - tgt timestamp < lifetime of ticket
                    # check if it is already cached, if not cache it to avoid replay attacks
                    # generate service session key
                    service_session_key = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(16)])[0:16]
                    
                    # prepare the service payload for client
                    service_payload = {"user_id": str(authenticator_dict.get('user_id')), 
                                       "service_id": str(tg_request.get('server_id')),
                                       "timestamp": str(datetime.now()), "lifetime_of_ticket": "2", 
                                       "service_session_key": str(service_session_key)}
                    
                    # encrypt the service payload using service_secret_key
                    service_enc_suite = AES.new(service_secret_key, AES.MODE_CFB, initial_vector)
                    service_ticket_encrypted = service_enc_suite.encrypt(str(service_payload))
                    
                    # prepare the tgs payload for client
                    tgs_ack_payload = {"service_id": str(tg_request.get('service_id')), 
                                       "timestamp": str(datetime.now()), "lifetime_of_ticket": "2", 
                                       "service_session_key": str(service_session_key)}
                    
                    # encrypt the tgs payload using tgs session key
                    tgs_enc_suite = AES.new(ticket_granting_ticket.get('tgs_session_key'), AES.MODE_CFB, initial_vector)
                    tgs_ack_encrypted = tgs_enc_suite.encrypt(str(tgs_ack_payload))
                    
                    # close the open database cursor and connection
                    db_cursor.close()
                    db_connection.close()
                    
                    print "TGS Ack and Service Ticket sent to client"
                    return jsonify({"tgs_ack_ticket": base64.b64encode(tgs_ack_encrypted), 
                                    "service_ticket": base64.b64encode(service_ticket_encrypted)})
            else:
                return jsonify({"message": "Access Denied"})


if __name__ == '__main__':
    app.run(debug=True, port=8989)
