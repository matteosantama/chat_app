import copy
from RegisteredUsers import RegisteredUsers
from Conversation import Conversation


class ChatManager:
    def __init__(self):
        """
        Initializes the chat manager.
        """
        self.active_users = []
        self.active_conversations = []

    def login_user(self, user_name, password):
        """
        Logs in a user.
        :param user_name: the user name of the user.
        :param password: the password of the user.
        :return: the user object representing the logged in user.
        """

        # search for the user among the registered users.
        current_user = None
        for user in RegisteredUsers:
            if user["user_name"] == user_name and user["password"] == password:
                current_user = copy.deepcopy(user)
                break
        if current_user:
            # check for user if already logged in
            already_logged_in = False
            for user in self.active_users:
                if user['user_name'] == current_user['user_name']:
                    already_logged_in = True

            if not already_logged_in:
                # delete user pwd
                current_user["password"] = ""
                self.active_users.append(current_user)

        return current_user

    def get_all_active_users(self):
        """
        :return: All active users.
        """
        return self.active_users

    @staticmethod
    def get_all_users():
        """
        :return: All registered users.
        """
        return RegisteredUsers

    def create_conversation(self, participant_list):
        """
        Creates a new conversation with the specified participants.
        :param participant_list: the users participating in the conversation
        """

        # check participants if they exists
        print "Checking participants...", participant_list

        # check each user if it is valid
        for participant in participant_list:
            valid_user = False
            for user in RegisteredUsers:
                if participant == user['user_name']:
                    valid_user = True
            if not valid_user:
                print "Invalid user found at conversation creation. Breaking..."
                raise Exception("Invalid user found at creating new conversation!")

        # check if min 2 user exist
        if len(participant_list) < 2:
            print "Not enough user!"
            raise Exception("Not enough user!")

        print "Creating new conversation..."
        new_conversation = Conversation(participant_list)
        self.active_conversations.append(new_conversation)

    def get_conversation(self, conversation_id):
        """
        Find a conversation based on the conversation id.
        :param conversation_id: the id of the searched conversation
        :return: the conversation object
        """
        for conversation in self.active_conversations:
            if unicode(str(conversation.conversation_id)) == conversation_id:
                return conversation
        print "Searched conversation not found! Conversation ID: " + conversation_id

    def get_my_conversations(self, user_name):
        """
        Returns all conversations for the specified user
        :param user_name: the user whose conversations are searched
        :return: list of conversations
        """
        my_conversations = []
        for conversation in self.active_conversations:
            for user in conversation.participants:
                if user == user_name:
                    my_conversations.append(conversation)
        return my_conversations

    @staticmethod
    def post_message_to_conversation(conversation, owner_id, message):
        """
        Post a message to a conversation
        :param conversation: the conversation object of the conversation
        :param owner_id: the user id of the owner of the message
        :param message: the text content of the message
        """
        conversation.add_message(owner_id, message)

    @staticmethod
    def get_message_in_conversation_since(conversation, last_message_id):
        """
        Get all the latest messages since the specified index.
        :param conversation: the conversation object of the conversation
        :param last_message_id: last seen message id
        :return: list of messages in the conversation
        """
        return conversation.get_messages_since(last_message_id)
