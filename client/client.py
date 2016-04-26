#!/usr/bin/env python2.7

"""
License: GNU GPL V3
Copyleft License
"""

import json
import base64
import socket
import requests
from time import sleep
from Crypto.Cipher import AES
from datetime import datetime

initial_vector = "secretsecretsecr"

if __name__ == '__main__':

    """
    Phase 1: Contact the Authentication Server by providing the user id or client id
    along with the service (here, tgs) id to obtain ticket for.
    """
    # get ip address of this client
    network_address = socket.gethostbyname(socket.gethostname())

    # construct the payload to send to authenticate server
    user_name = raw_input("Enter user id to authenticate with: ")
    payload = {"userid": str(user_name), "service_id": "tgs", "nw_addr": str(network_address), "lifetime_of_tgt": "2"}

    # send payload and fetch response from the authentication server
    print "-" * 40
    print ("Authenticating with the server...")
    as_response = requests.post("http://localhost:8989/authenticate", json=payload)
    
    sleep(2)

    if as_response.status_code == 200:
        print "Successfully Authenticated."
        print "-" * 40
        
        # decode the received data
        ack_sent = base64.b64decode(as_response.json().get('ack'))
        ticket_granting_ticket = as_response.json().get('tgt')
        
        # prompt for user secret key to decrypt the message
        user_secret_key = raw_input("Your Secret Key To Decrypt: ")
        
        # decrypt the acknowledgement section using user secret key
        ack_dec_suite = AES.new(user_secret_key, AES.MODE_CFB, initial_vector)
        ack_plain = ack_dec_suite.decrypt(ack_sent)

        # convert string type to dictionary type
        json_acceptable_format = ack_plain.replace("'", "\"")
        ack_plain = json.loads(json_acceptable_format)
        
        print "-" * 40
        print "Acknowledgement from Authentication Server"
        print ack_plain
        
        sleep(2)
        
        print "\nTicket Granting Ticket from Authentication Server"
        print ticket_granting_ticket
        print "-" * 40


    """
    Phase 2: Contact ticket granting server with the ticket granting
    ticket obtained from Authentication Server along with the id of the
    service to which the client is requesting ticket from the Ticket
    Granting Server.
    """
    # construct the auth payload to send to tgs
    auth_payload = {"user_id": str(user_name), "timestamp": str(datetime.now())}
    
    # encrypt the payload with tgs session key
    auth_enc_suite = AES.new(ack_plain.get('tgs_session_key'), AES.MODE_CFB, initial_vector)
    auth_cipher = auth_enc_suite.encrypt(str(auth_payload))
    
    # prompt user for the service id
    service_id = raw_input("Service ID: ")
    
    # construct the ticket grant request for service payload
    tgr_payload = {"service_id": service_id, "lifetime_of_ticket": "2"}
    
    # payloads put together to send to ticket granting sever
    payload = {"authenticator": base64.b64encode(auth_cipher), "ticket_granting_request": str(tgr_payload),
               "ticket_granting_ticket": ticket_granting_ticket}
    
    print "Contacting Ticket Granting Server..."        
    tgs_response = requests.post("http://localhost:8989/ticket", json=payload)
    
    sleep(1)
    
    if tgs_response.status_code == 200:
        print "Ticket Granted!"
        print "-" * 40
        
        # decode the ticket which can be read by the client
        tgs_ack_ticket = base64.b64decode(tgs_response.json().get('tgs_ack_ticket'))
        service_ticket = tgs_response.json().get('service_ticket')
        
        tgs_ack_dec_suite = AES.new(ack_plain.get('tgs_session_key'), AES.MODE_CFB, initial_vector)
        tgs_ack_ticket_plain = tgs_ack_dec_suite.decrypt(tgs_ack_ticket)
        
        print "Acknowledgement from Ticket Granting Server"
        print tgs_ack_ticket_plain
        
        sleep(2)
        
        print "\nService Ticket from Ticket Granting Server"
        print service_ticket
