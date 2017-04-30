from config import *
import urllib2
import json
from conversation import Conversation
from message import Message, MessageEncoder
from time import sleep

import pickle
from Crypto import Random
from Crypto.Random import random
from Crypto.PublicKey import ElGamal
from Crypto.Util import number

from menu import menu

from threading import Thread

import base64


state = INIT  # initial state for the application
has_requested_messages = False  # history of the next conversation will need to be downloaded and printed
p_size = 256

class ChatManager:
    '''
    Class responsible for driving the application
    '''
    def __init__(self, user_name="", password=""):
        '''
        Constructor
        :param user_name: user name of the current user
        :param password: password of the current user
        :return: instance
        '''
        self.cookie = ""  # cookie, the result of successful login, has to be included in all requests to the server
        self.is_logged_in = False  # flag, was the login process successful?
        self.current_conversation = None  # object representing the current selected conversation
        self.last_msg_id = "0"  # ID of the last message downloaded for the current conversation
        self.get_msgs_thread = Thread(
            target=self.get_messages_of_conversation
        )  # thread, retrieves messages from the server
        self.user_name = user_name  # user name of the current user
        self.password = password  # password of the current user
        self.get_msgs_thread_started = False  # message retrieval has not been started

    def login_user(self):
        '''
        Logs the current user in
        :return: None
        '''
        print "Logging in..."
        # create JSON document of user credentials
        user_data = json.dumps({
            "user_name": self.user_name,
            "password": self.password
        })
        try:
            # Send user credentials to the server
            req = urllib2.Request("http://" + SERVER + ":" + SERVER_PORT + "/login", data=user_data)
            r = urllib2.urlopen(req)
            headers = r.info().headers
            cookie_found = False
            # Search for the cookie in the response headers
            for header in headers:
                if "Set-Cookie" in header:
                    self.cookie = header.split("Set-Cookie: ")[1].split(";")[0]
                    cookie_found = True
            if cookie_found == True:
                # Cookie found, login successful
                self.is_logged_in = True
                self.generate_pub_priv()
                print "Login successful"
            else:
                # No cookie, login unsuccessful
                self.user_name = ""
                self.password = ""
                print "Login unsuccessful, did not receive cookie from server"
        except urllib2.HTTPError as e:
            # HTTP error happened, the response status is not 200 (OK)
            print "Unable to log in, server returned HTTP", e.code, e.msg
            self.user_name = ""
            self.password = ""
            self.is_logged_in = False
        except urllib2.URLError as e:
            # Other kinds of errors related to the network
            print "Unable to log in, reason:", e.message
            self.user_name = ""
            self.password = ""
            self.is_logged_in = False

    def generate_pub_priv(self):
        try:
            # Try to open file containing my personal/private keys
            pub_private = pickle.load(open("./res/%s_key_pair.p" % self.user_name, "rb"))
        except (OSError, IOError) as e:
            # If exception, generate these keys and write to pickle file
            pub_private = {}
            # NOTE possible to store entire object and avoid long calcs
            params = ElGamal.generate(p_size, Random.new().read)
            pub_private['public'] = params.y
            pub_private['private'] = params.x
            pub_private['p'] = params.p
            pub_private['g'] = params.g
            pickle.dump(pub_private, open("./res/%s_key_pair.p" % self.user_name, "wb"))


    def create_conversation(self):
        '''
        Requests the creation of a new conversation on the server
        :return: None
        '''
        global state
        # Allowed only, if user is logged in
        if self.is_logged_in:
            try:
                # Query server for users to invite
                req = urllib2.Request("http://" + SERVER + ":" + SERVER_PORT + "/users")
                req.add_header("Cookie", self.cookie)
                r = urllib2.urlopen(req)
                users = json.loads(r.read())
            except urllib2.HTTPError as e:
                print "Unable to create conversation, server returned HTTP", e.code, e.msg
                return
            except urllib2.URLError as e:
                print "Unable to create conversation, reason:", e.message
                return
            # Print potential participants
            print "Available users:"
            for user in users:
                try:
                    if user["user_name"] != self.user_name:
                        # save
                        print "\t", user["user_name"]
                except KeyError as e:
                    print "Invalid JSON document: no user_name field"
            # Waiting for user input specifying participants
            participants = ""
            try:
                participants = raw_input("Please type the user names of participants separated by \";\": ")
            except Exception:
                pass
            participant_list = []
            if participants != "":
                # Create a list of participants
                participant_list = participants.split(";")
            # Add current user to the participant list
            participant_list.append(self.user_name)
            data = json.dumps({
                "participants": json.dumps(participant_list)
            })
            print "Creating new conversation..."
            try:
                # Send conversation create request to the server (participants are POSTed)
                req = urllib2.Request("http://" + SERVER + ":" + SERVER_PORT + "/conversations/create", data=data)
                # Cookie has to included with every request
                req.add_header("Cookie", self.cookie)
                r = urllib2.urlopen(req)
            except urllib2.HTTPError as e:
                print "Unable to create conversation, server returned HTTP", e.code, e.msg
                return
            except urllib2.URLError as e:
                print "Unable to create conversation, reason:", e.message
                return
            print "Conversation created"
        else:
            print "Please log in before creating new conversations"
            state = INIT

    def get_other_users(self):
        '''
        Retrieves members of the current conversations
        :return: participants, a list of member names
        '''
        global state
        # Allowed only, if user is logged in
        if self.is_logged_in:
            try:
                # Querying the server for the conversations of the current user (user is a participant)
                req = urllib2.Request("http://" + SERVER + ":" + SERVER_PORT + "/conversations")
                # Include Cookie
                req.add_header("Cookie", self.cookie)
                r = urllib2.urlopen(req)
            except urllib2.HTTPError as e:
                print "Unable to download conversations, server returned HTTP", e.code, e.msg
                return
            except urllib2.URLError as e:
                print "Unable to download conversations, reason:", e.message
                return
            conversations = json.loads(r.read())
            # Print conversations with IDs and participant lists
            for c in conversations:
                conversation_id = c["conversation_id"]
                if conversation_id == self.current_conversation.get_id():
                    # Reached data of current conversation, extract participants
                    participants = []
                    for participant in c["participants"]:
                        if participant != self.user_name:
                            participants.append(participant)
                    return participants

        else:
            print "Please log in before accessing Your conversations"
            state = INIT


    def get_my_conversations(self):
        '''
        Retrieves all the conversations (their IDs and participant lists) that the current user is a participant of
        :return: None
        '''
        global state
        # Allowed only, if user is logged in
        if self.is_logged_in:
            try:
                # Querying the server for the conversations of the current user (user is a participant)
                req = urllib2.Request("http://" + SERVER + ":" + SERVER_PORT + "/conversations")
                # Include Cookie
                req.add_header("Cookie", self.cookie)
                r = urllib2.urlopen(req)
            except urllib2.HTTPError as e:
                print "Unable to download conversations, server returned HTTP", e.code, e.msg
                return
            except urllib2.URLError as e:
                print "Unable to download conversations, reason:", e.message
                return
            conversations = json.loads(r.read())
            # Print conversations with IDs and participant lists
            for c in conversations:
                conversation_id = c["conversation_id"]
                print "Conversation", conversation_id, "has the following members:"
                for participant in c["participants"]:
                    print "\t", participant
        else:
            print "Please log in before accessing Your conversations"
            state = INIT

    def get_messages_of_conversation(self):
        '''
        Retrieves messages of the current conversation from the server (almost infinite loop)
        :return: None
        '''
        global state, has_requested_messages
        # Allowed only, if user is logged in and the application is not currently exiting
        while self.is_logged_in == True and state != STOP:
            if state == IN_CONVERSATION:
                try:
                    # If we are in a conversation, download messages that have not been seen in the current conv.
                    req = urllib2.Request("http://" + SERVER + ":" + SERVER_PORT + "/conversations/" +
                                          str(self.current_conversation.get_id()) +
                                          "/" + str(self.current_conversation.get_last_message_id()))
                    # Include cooke
                    req.add_header("Cookie", self.cookie)
                    r = urllib2.urlopen(req)
                    msgs = json.loads(r.read())
                except urllib2.HTTPError as e:
                    print "Unable to download messages, server returned HTTP", e.code, e.msg
                    self.get_msgs_thread_started = False
                    continue
                except urllib2.URLError as e:
                    print "Unable to download messages, reason: ", e.message
                    self.get_msgs_thread_started = False
                    continue
                # Process incoming messages
                for m in msgs:
                    self.current_conversation.append_msg_to_process(m)
                has_requested_messages = True
            sleep(MSG_QUERY_INTERVAL) # Query for new messages every X seconds

    def post_message_to_conversation(self, msg_raw):
        '''
        Posts a single message to the current conversation on the server
        :param msg_raw: the raw message to be sent
        :return: None
        '''
        global has_requested_messages
        # While the conversation history is being retrieved, postpone message sending
        while has_requested_messages is not True:
            sleep(0.01)
        try:
            # Process outgoing message
            msg = Message(content=base64.encodestring(msg_raw),
                          owner_name=self.user_name)
            # Send the message
            req = urllib2.Request("http://" + SERVER + ":" + SERVER_PORT + "/conversations/" +
                                  str(self.current_conversation.get_id()),
                                  data=json.dumps(msg, cls=MessageEncoder))
            # Include cookie
            req.add_header("Cookie", self.cookie)
            r = urllib2.urlopen(req)
        except urllib2.HTTPError as e:
            print "Unable to post message, server returned HTTP", e.code, e.msg
        except urllib2.URLError as e:
            print "Unable to post message, reason: ", e.message

    def read_user_input(self):
        '''
        Waits for message in a conversation and posts it to the current conversation on the server
        :return: None
        '''
        global state
        # Allowed only, if user is logged in
        if self.is_logged_in:
            while state == IN_CONVERSATION:
                try:
                    # While in a conversation, read the message (user input from the console)
                    msg_raw = raw_input()
                    print "\n"
                    # Send the message to the server
                    self.current_conversation.process_outgoing_message(
                        msg_raw=msg_raw,
                        originates_from_console=True
                    )
                except EOFError:
                    # User has not provided any input, but waiting for the input was interrupted
                    continue
                except KeyboardInterrupt:
                    continue
        else:
            print "Please log in before sending messages"
            state = INIT

    def run(self):
        '''
        Implements a state machine, calls methods based on the current state of the application
        :return: None
        '''
        global state
        self.login_user()
        # Allowed only if the current is logged in
        if self.is_logged_in == True:
            print "Welcome"
            # Start thread which retrieves messages from the server (won't do anything until in a conversation)
            self.get_msgs_thread.start()
            self.get_msgs_thread_started = True
            print "Press Ctrl+Break (on Windows) or Ctrl+z (on Unix and Mac) to bring up menu"
            # Run a state machine
            while True:
                if state == CREATE_CONVERSATION:
                    # User wants to create a conversation
                    self.create_conversation()
                    # Creation finished, go back to the initial state
                    state = INIT
                elif state == SELECT_CONVERSATION:
                    # User wants to enter a conversation
                    try:
                        # Read the conversation ID supplied by the user
                        conversation_id = raw_input("Which conversation do you wish to join? ")
                        # Check whether the supplied ID is valid
                        req = urllib2.Request("http://" + SERVER + ":" + SERVER_PORT + "/conversations/" +
                                              conversation_id + "/")
                        # Include cookie
                        req.add_header("Cookie", self.cookie)
                        r = urllib2.urlopen(req)
                        try:
                            c_id = int(conversation_id)
                        except ValueError as e:
                            print "Entered conversation ID is not a number"
                            continue
                        self.current_conversation = Conversation(c_id, self)
                        # NOTE moved below about 15 lines down
                        # self.current_conversation.setup_conversation()
                    except urllib2.HTTPError as e:
                        print "Unable to determine validity of conversation ID, server returned HTTP", e.code, e.msg
                        continue
                    except urllib2.URLError as e:
                        print "Unable to determine validity of conversation ID, reason: ", e.message
                        continue
                    except EOFError:
                        # User has not provided any input, but waiting for the input was interrupted
                        continue
                    except KeyboardInterrupt:
                        continue
                    # Enter the conversation (message retrieval thread becomes active)
                    state = IN_CONVERSATION
                    # NOTE see note above
                    self.current_conversation.setup_conversation()
                    # Read messages from the console
                    self.read_user_input()
                elif state == STOP:
                    # Application is exiting
                    return
                try:
                    sleep(0.1)  # may get interrupted by signal handling
                except IOError:
                    continue
                except KeyboardInterrupt:
                    continue

    def stop(self):
        '''
        Cleans up when the application exists
        :return: None
        '''
        global state
        print "\n", "Shutting down..."
        # Signal message retrieval thread to terminate
        state = STOP
        # The message retrieval thread may not have started
        if self.get_msgs_thread_started == True:
            # If it was started, wait for it to terminate
            self.get_msgs_thread.join(MSG_QUERY_INTERVAL + 1)
        if self.current_conversation:
            self.current_conversation.exit()
        print "Bye!"

    def enter_menu(self, signum, frame):
        '''
        Handles interaction between the application and the user in the menu

        This function is an asynchronous event handler which reacts to CRTL+z (on Linux/Mac) or CTRL+BREAK (on Windows)
        :param signum: number of the signal from the OS which triggered the invocation of this function
        :param frame: the current stack frame
        :return: None
        '''
        global state, has_requested_messages
        # Set the state of the state machine
        state = IN_MENU
        print "\nYour " \
              "active conversations:"
        # Conversation was left, history of the next conversation will need to be downloaded again
        has_requested_messages = False
        # Get the conversations of the current user
        self.get_my_conversations()
        # Display the menu
        menu.display()
        selected_option = 0
        try:
            # Read the menu item selection ID entered by the user
            selected_option = raw_input()
        except RuntimeError:
            # raw_input() will raise RuntimeError f interrupted by OS signal
            print "Error detected while waiting for user input, multiple attempts to enter menu?"
            return
        except KeyboardInterrupt:
            return
        if selected_option == "1":
            # User wants to create a conversation, drive the state machine there
            state = CREATE_CONVERSATION
        elif selected_option == "2":
            # User wants to enter a conversations, drive the state machine there
            state = SELECT_CONVERSATION
        elif selected_option == "3":
            state = STOP
            self.stop()
            exit()
        else:
            print "Invalid selection"
