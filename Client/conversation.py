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
from Crypto.Util.number import GCD
from Crypto.Cipher import AES
from AESCipher import AESCipher

MESSAGE_CODE = '00'
PUB_KEY_BROADCAST = '01'
DH_INIT = '10'
DH_RESPONSE = '11'
DH_CONFIRM = '12'
SYM_KEY = '13'

WINDOW = 5

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
        self.DH_params = None
        self.sender_key_obj = None
        self.y_b = None
        self.DH_sender_params = None
        self.DH_receiver_params = {}
        self.DH_confirm_params = None
        self.shared_K = None
        self.creator = None
        self.symm_key = None
        self.send_counter = None
        self.counter_table = None


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

        self.process_outgoing_message(
            msg_raw=my_pub,
            originates_from_console=False
        )

        thread = Thread(target = self.collect_keys)
        thread.start()

        while thread.isAlive():
            print 'Waiting for other users to join chatroom'
            sleep(2.0)

        self.creator = self.manager.get_conversation_creator()
        self.init_msg_counters()

        try:
            # Try to open file containing symmetric keys
            with open("./res/%s_symm_keys.p" % self.manager.user_name, "rb") as keyfile:
                symm_keys = pickle.load(keyfile)
            # Check if current chat has symm key established
            if self.id in symm_keys:
                self.symm_key = symm_keys[self.id]
                pass
            # If not, and user is creator, initiate DH
            elif self.manager.user_name == self.creator:
                self.initiate_DH()
        except (OSError, IOError) as e:
            # If file doesn't exist, creator initiates DH
            if self.manager.user_name == self.creator:
                self.initiate_DH()

        print 'Conversation set up. Begin chatting \n\n'

        # You can use this function to initiate your key exchange
        # Useful stuff that you may need:
        # - name of the current user: self.manager.user_name
        # - list of other users in the converstaion: list_of_users = self.manager.get_other_users()
        # You may need to send some init message from this point of your code
        # you can do that with self.process_outgoing_message("...") or whatever you may want to send here...

        # Since there is no crypto in the current version, no preparation is needed, so do nothing
        # replace this with anything needed for your key exchange
        pass

    #initializes the counters
    def init_msg_counters(self):
        try:
            with open("./res/%s_counter_table.p" % self.manager.user_name, "rb") as counterfile:
                table = pickle.load(counterfile)
                if self.id in table:
                    self.send_counter, self.counter_table = table[self.id]
                else:
                    self.counter_table = {}
                    for user in self.get_other_users:
                        self.counter_table[user] = 0
                    self.send_counter = 0
                    table[self.id] = (self.send_counter, self.counter_table)
        except (OSError, IOError) as e:
            with open("./res/%s_counter_table.p" % self.manager.user_name, "wb") as counterfile:
                self.counter_table = {}
                for user in self.manager.get_other_users():
                    self.counter_table[user] = 0
                self.send_counter = 0
                table = {}
                table[self.id] = (self.send_counter, self.counter_table)
                pickle.dump(table, counterfile)


    def initiate_DH(self):
        # send first DH parameter to all users
        print 'Generating Diffie-Hellman parameters'
        self.DH_params = ElGamal.generate(p_size, Random.new().read)
        print 'Generated'
        params_string = str(self.DH_params.y) + '|' + str(self.DH_params.g) + '|' + str(self.DH_params.p)
        DH_msg1 = DH_INIT + '|' + params_string
        self.process_outgoing_message(
            msg_raw=DH_msg1,
            originates_from_console=False
        )
        self.symm_key = number.long_to_bytes(random.StrongRandom().getrandbits(128))
        self.save_symm_key()

    def save_symm_key(self):
        try:
            with open("./res/%s_symm_keys.p" % self.manager.user_name, "rb") as keyfile:
                symm_keys = pickle.load(keyfile)
            # we have the file, add new symm_key
            symm_keys[self.id] = self.symm_key
        except (OSError, IOError) as e:
            # don't have the file, create it
            with open("./res/%s_symm_keys.p" % self.manager.user_name, "wb") as keyfile:
                symm_keys = {self.id: self.symm_key}
                pickle.dump(symm_keys,keyfile)


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

    def sign(self,msg):
        h = SHA.new()
        h.update(msg)
        keystr = self.manager.key_object.exportKey('PEM')
        # signer object constructed with RSA object chat manager
        signer = PKCS1_PSS.new(RSA.importKey(keystr))
        return base64.encodestring(signer.sign(h))

    def verify(self, pub_key_obj, sig, msg):
        h = SHA.new()
        h.update(msg)
        keystr = pub_key_obj.exportKey('PEM')
        verifier = PKCS1_PSS.new(RSA.importKey(keystr))
        return verifier.verify(h, base64.decodestring(sig))

    def ECB_encrypt(self,plaintext,key):
        cipher = AES.new(str(key), AES.MODE_ECB)
        ciphertext = cipher.encrypt(plaintext)
        return base64.encodestring(ciphertext)

    def ECB_decrypt(self,ciphertext,key):
        ciphertext = base64.decodestring(ciphertext)
        cipher = AES.new(str(key), AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext

    def chop(self,long_key):
        bytes = number.long_to_bytes(long_key)
        n = len(bytes)
        return bytes[:n/2]

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

        if message_parts[0] == MESSAGE_CODE and self.manager.user_name != owner_str:
            code, ciphertext, recv_counter, signature = message_parts
            str_to_verify = code + '|' + ciphertext + '|' + recv_counter
            # check signature of message code, ciphertext, and counter before proceeding
            assert self.verify(self.collected_keys[owner_str],signature,str_to_verify)
            # check that counter is within window for that user and update counter
            self.update_recv_ctr(recv_counter,owner_str)
            cipher = AESCipher(self.symm_key)
            decoded_msg = cipher.decrypt(ciphertext)
            # print message and add it to the list of printed messages
            self.print_message(
                msg_raw=decoded_msg,
                owner_str=owner_str
            )
        # STAGE 1: Executed by receivers. creator has initiated DH protocol, and parties BCD send responses
        elif message_parts[0] == DH_INIT and self.manager.user_name != owner_str:
            # print 'received DH_INIT'
            # compute private and public keys
            # received parameters from A
            y_a, g, p = map(int,message_parts[1::])
            # generate private DH parameter x of BCD
            while True:
                x_b = random.StrongRandom().randint(1, p-1)
                if GCD(x_b, p-1) == 1: break
            # create ElGamal key from the parameters of A
            self.sender_key_obj = ElGamal.construct((p, g, y_a))
            # calculate shared key and BCD private key
            c = self.sender_key_obj.encrypt(1, x_b)
            self.y_b = c[0]
            self.shared_K = c[1]
            # sign received pub key
            # create response with B's parameters
            DH_msg2 = DH_RESPONSE + '|' + str(self.y_b) + '|' + str(self.sender_key_obj.g) + '|' + str(self.sender_key_obj.p)
            # sign A's parameters
            my_signature = self.sign(str(y_a) + '|' + str(g) + '|' + str(p))
            # append signature
            DH_msg2 += '|' + my_signature
            # send msg_code + parameters
            self.process_outgoing_message(msg_raw=DH_msg2, originates_from_console=False)
        # STAGE 2: A receives and processes each response, and sends confirmation message with symm key
        elif message_parts[0] == DH_RESPONSE and self.manager.user_name != owner_str and self.manager.user_name == self.creator:
            # print 'received DH_RESPONSE'
            # verify signature
            params_string = str(self.DH_params.y) + '|' + str(self.DH_params.g) + '|' + str(self.DH_params.p)
            y_b, g, p, sig = message_parts[1::]
            assert self.verify(self.collected_keys[owner_str], sig, params_string)
            # create ElGamal key from the parameters of Bob
            constr_key_obj_B = ElGamal.construct((int(p), int(g), int(y_b)))
            c = constr_key_obj_B.encrypt(1, self.DH_params.x)
            shared_K = c[1]
            # sign and send A and B's public parameters and the symmetric key
            sig = self.sign(str(self.DH_params.y) + '|' + str(y_b))
            # symmetric key is encrypted with the shared secret in AES, ECB mode
            # print 'Symmetric key: ', self.symm_key
            encoded_symm_key = self.ECB_encrypt(self.symm_key, self.chop(shared_K))
            DH_msg3 = DH_CONFIRM + '|' + sig + '|' + encoded_symm_key + '|' + owner_str
            self.process_outgoing_message(
                msg_raw=DH_msg3,
                originates_from_console=False
            )
        # STAGE 3: Executed by receiver. Verify signed public keys, and decrypt symm key
        elif message_parts[0] == DH_CONFIRM and self.manager.user_name != owner_str:
            # check if message was intended for recipient
            sig_sender, enc_symm_key, intended_recipient =  message_parts[1::]
            if self.manager.user_name == intended_recipient:
                # print 'intended recipient recieved DH_CONFIRM'
                self.sender_key_obj
                str_to_verify = str(self.sender_key_obj.y) + '|' + str(self.y_b)
                sender_pub = self.collected_keys[self.creator]
                # print 'verifying signature'
                assert self.verify(sender_pub, sig_sender, str_to_verify)
                # decrypt encoded symm key
                self.symm_key = self.ECB_decrypt(enc_symm_key, self.chop(self.shared_K))
                self.save_symm_key()
                # write symm key to disk. chat_id mapped to symm_key
                # print 'Symmetric Key: ', self.symm_key


    def process_outgoing_message(self, msg_raw, originates_from_console=False):
        '''
        Process an outgoing message before Base64 encoding

        :param msg_raw: raw message
        :return: message to be sent to the server
        '''


        # if the message has been typed into the console, record it, so it is never printed again during chatting
        if originates_from_console == True:
            self.update_send_ctr()
            # message is already seen on the console
            cipher = AESCipher(self.symm_key)
            encrypted_msg =  cipher.encrypt(msg_raw)

            str_to_sign = MESSAGE_CODE + '|' + encrypted_msg + '|' + str(self.send_counter)
            sig = self.sign(str_to_sign)
            msg_raw = str_to_sign +'|'+ sig
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

    def update_send_ctr(self):
        self.send_counter += 1
        table = {}
        with open('./res/%s_counter_table.p' % self.manager.user_name, 'rb') as counterfile:
            table = pickle.load(counterfile)
        table[self.id] = (self.send_counter, table[self.id][1])
        with open('./res/%s_counter_table.p' % self.manager.user_name, 'wb') as counterfile:
            pickle.dump(table,counterfile)
        pass

    def update_recv_ctr(self, new_ctr, user):
        new_ctr = int(new_ctr)
        receiver_counter = self.counter_table[user]
        if (receiver_counter - WINDOW < new_ctr < receiver_counter + WINDOW):
            #accept
            return
        elif new_ctr > receiver_counter + WINDOW:
            #accept and extend counter
            self.counter_table[user] = new_ctr
        else:
            raise IOError # Invalid packet recieved

        table = {}
        with open('./res/%s_counter_table.p', 'rb') as counterfile:
            table = pickle.load(counterfile)
        table[self.id] = (table[self.id][0], self.counter_table)
        with open('./res/%s_counter_table.p', 'wb') as counterfile:
            pickle.dump(table,counterfile)
        pass


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