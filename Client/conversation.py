from message import Message
import base64
from time import sleep
from threading import Thread

import pickle
from Crypto import Random
from Crypto.Random import random
from Crypto.PublicKey import ElGamal, RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Util import number
from Crypto.Hash import SHA

MESSAGE_CODE = '00'
PUB_KEY_BROADCAST = '01'
DH_INIT = '10'
DH_RESPONSE = '11'
DH_CONFIRM = '12'
SYM_KEY = '13'

p_size = 256

class Conversation:
    '''
    Represents a conversation between participants
    '''
    def __init__(self, c_id, manager):
        '''
        Constructor
        :param c_id: ID of the conversation (integer)
        :param manager: instance of the ChatManager class
        :return: None
        '''
        self.id = c_id  # ID of the conversation
        self.all_messages = []  # all retrieved messages of the conversation
        self.printed_messages = []
        self.last_processed_msg_id = 0  # ID of the last processed message
        from chat_manager import ChatManager
        assert isinstance(manager, ChatManager)
        self.manager = manager # chat manager for sending messages
        self.run_infinite_loop = True
        self.msg_process_loop = Thread(
            target=self.process_all_messages
        ) # message processing loop
        self.msg_process_loop.start()
        self.msg_process_loop_started = True
        self.collected_keys= {}
        self.DH_sender_params = None

    def append_msg_to_process(self, msg_json):
        '''
        Append a message to the list of all retrieved messages

        :param msg_json: the message in JSON encoding
        :return:
        '''
        self.all_messages.append(msg_json)

    def append_msg_to_printed_msgs(self, msg):
        '''
        Append a message to the list of printed messages

        :param msg: an instance of the Message class
        :return:
        '''
        assert isinstance(msg, Message)
        self.printed_messages.append(msg)

    def exit(self):
        '''
        Called when the application exits, breaks the infinite loop of message processing

        :return:
        '''
        self.run_infinite_loop = False
        if self.msg_process_loop_started == True:
            self.msg_process_loop.join()

    def process_all_messages(self):
        '''
        An (almost) infinite loop, that iterates over all the messages received from the server
        and passes them for processing

        The loop is broken when the application is exiting
        :return:
        '''
        while self.run_infinite_loop:
            for i in range(0, len(self.all_messages)):
                current_msg = self.all_messages[i]
                msg_raw = ""
                msg_id = 0
                owner_str = ""
                try:
                    # Get raw data of the message from JSON document representing the message
                    msg_raw = base64.decodestring(current_msg["content"])
                    # Base64 decode message
                    msg_id = int(current_msg["message_id"])
                    # Get the name of the user who sent the message
                    owner_str = current_msg["owner"]
                except KeyError as e:
                    print "Received JSON does not hold a message"
                    continue
                except ValueError as e:
                    print "Message ID is not a valid number:", current_msg["message_id"]
                    continue
                if msg_id > self.last_processed_msg_id:
                    # If the message has not been processed before, process it
                    self.process_incoming_message(msg_raw=msg_raw,
                                                  msg_id=msg_id,
                                                  owner_str=owner_str)
                    # Update the ID of the last processed message to the current
                    self.last_processed_msg_id = msg_id
                sleep(0.01)

    def setup_conversation(self):
        '''
        Prepares the conversation for usage
        :return:
        '''

        my_keys = pickle.load(open("./res/%s_RSA_keys.p" % self.manager.user_name, "rb"))
        my_pub = PUB_KEY_BROADCAST + '|' + my_keys.publickey().exportKey()

        print 'sending pub key', my_pub
        self.process_outgoing_message(
            msg_raw=my_pub,
            originates_from_console=False
        )
        print "sent"
        print 'creating thread'

        thread = Thread(target = self.collect_keys)
        thread.start()

        while thread.isAlive():
            print 'Waiting for users to join chatroom'
            sleep(1.0)

        print 'thread ended'

        creator = self.manager.get_conversation_creator()

        print 'generating keys'
        DH_params = ElGamal.generate(p_size, Random.new().read)
        print 'generated'
        if self.manager.user_name == creator:
            print 'in if statement'
            # send first DH parameter to all users
            DH_msg1 = DH_INIT + '|' + str(DH_params.y) + '|' + str(DH_params.g) + '|' + str(DH_params.p)
            print DH_msg1
            self.process_outgoing_message(
                msg_raw=DH_msg1,
                originates_from_console=False
            )
            # Wait for BCDs responses
            # while self.DH_receiver_params is None:
            #     sleep(0.1)
        else:
            print 'in else'
            # Wait for all the recivers to get firts DH message
            while self.DH_sender_params is None:
                print 'sleeping'
                sleep(0.01)
            # received parameters from A
            y_a, g_a, p_a = self.DH_sender_params
            # create response with B's parameters
            DH_msg2 = DH_RESPONSE + '|' + str(DH_params.y) + '|' + str(DH_params.g) + '|' + str(DH_params.p)
            # sign A's parameters
            signature = self.sign(str(y_a) + '|' + str(g_a) + '|' + str(p_a))
            # append signature
            DH_msg2 += '|' + signature
            # send response
            self.process_outgoing_message(msg_raw=DH_msg2,originates_from_console=False)
            print 'Receiver: ' + str(y_a) + '|' + str(g_a) + '|' + str(p_a)


        # You can use this function to initiate your key exchange
        # Useful stuff that you may need:
        # - name of the current user: self.manager.user_name
        # - list of other users in the converstaion: list_of_users = self.manager.get_other_users()
        # You may need to send some init message from this point of your code
        # you can do that with self.process_outgoing_message("...") or whatever you may want to send here...

        # Since there is no crypto in the current version, no preparation is needed, so do nothing
        # replace this with anything needed for your key exchange
        pass

    # NOTE can collect keys via process_incoming_message
    def collect_keys(self):
        chat_participants = self.manager.get_other_users()

        while len(chat_participants)+1 != len(self.collected_keys):
            # loop through all messages of convo
            for i in range(len(self.all_messages)):
                msg = self.all_messages[i]
                # decode message
                raw = base64.decodestring(base64.decodestring(msg['content'])).split('|')
                # if message is a key broadcast, add it to the list
                if raw[0] == PUB_KEY_BROADCAST:
                    self.collected_keys[msg["owner"]] = RSA.importKey(raw[1])
            sleep(1.0)
        print self.collected_keys, 'collected keys'

    def sign(self,msg):
        h = SHA.new()
        h.update(msg)
        keystr = self.manager.key_object.exportKey('PEM')
        # signer object constructed with RSA object chat manager
        signer = PKCS1_PSS.new(RSA.importKey(keystr))
        return signer.sign(h)


    def process_incoming_message(self, msg_raw, msg_id, owner_str):
        '''
        Process incoming messages
        :param msg_raw: the raw message
        :param msg_id: ID of the message
        :param owner_str: user name of the user who posted the message
        :param user_name: name of the current user
        :param print_all: is the message part of the conversation history?
        :return: None
        '''

        # process message here
		# example is base64 decoding, extend this with any crypto processing of your protocol
        decoded_msg = base64.decodestring(msg_raw)

        message_parts = decoded_msg.split('|')

        if message_parts[0] == MESSAGE_CODE:
            # print message and add it to the list of printed messages
            self.print_message(
                msg_raw=decoded_msg,
                owner_str=owner_str
            )
        elif message_parts[0] == DH_INIT:
            print "INIT", message_parts
            self.DH_sender_params = message_parts[1::]

    def process_outgoing_message(self, msg_raw, originates_from_console=False):
        '''
        Process an outgoing message before Base64 encoding

        :param msg_raw: raw message
        :return: message to be sent to the server
        '''

        # if the message has been typed into the console, record it, so it is never printed again during chatting
        if originates_from_console == True:
            # message is already seen on the console
            m = Message(
                owner_name=self.manager.user_name,
                content=msg_raw
            )
            self.printed_messages.append(m)

        # process outgoing message here
		# example is base64 encoding, extend this with any crypto processing of your protocol
        encoded_msg = base64.encodestring(msg_raw)

        # post the message to the conversation
        self.manager.post_message_to_conversation(encoded_msg)

    def print_message(self, msg_raw, owner_str):
        '''
        Prints the message if necessary

        :param msg_raw: the raw message
        :param owner_str: name of the user who posted the message
        :return: None
        '''
        # Create an object out of the message parts
        msg = Message(content=msg_raw,
                      owner_name=owner_str)
        # If it does not originate from the current user or it is part of conversation history, print it
        if msg not in self.printed_messages:
            print msg
            # Append it to the list of printed messages
            self.printed_messages.append(msg)

    def __str__(self):
        '''
        Called when the conversation is printed with the print or str() instructions
        :return: string
        '''
        for msg in self.printed_messages:
            print msg

    def get_id(self):
        '''
        Returns the ID of the conversation
        :return: string
        '''
        return self.id

    def get_last_message_id(self):
        '''
        Returns the ID of the most recent message
        :return: number
        '''
        return len(self.all_messages)
