import random
import base64
from Message import Message


class Conversation:
    def __init__(self, participants):
        self.participants = participants  # list of Users
        self.conversation_id = random.randint(1, 10000)
        self.messages = []  # list of Messages

    def add_user(self, user):
        """
        Adds a user to the conversation.
        :param user: the new user to be added to the conversation
        """
        self.participants.append(user)

    def get_messages_since(self, last_message_id):
        """
        Returns all messages from this conversation since the specified id.
        :param last_message_id: the id of the last seen message
        :return: list of all new messages since the last_messages_id value.
        """
        result = []

        if last_message_id is None:
            result = self.messages

        else:
            for message in self.messages:
                if message.message_id > int(last_message_id):
                    result.append(message)

        return result

    def add_message(self, owner, content):
        """
        Adds a new message to the conversation.
        :param owner: the user id of the message owner
        :param content: the text content of the message
        """
        print "Adding new message for user: " + owner + " with content: " + base64.b64decode(content)
        if len(self.messages) == 0:
            new_id = 1
        else:
            new_id = self.messages[-1].message_id + 1
        new_message = Message(new_id, owner, content)

        self.messages.append(new_message)

    def __str__(self):
        return str(self.conversation_id) + " with: " + str(self.participants) + " with messages: " + str(self.messages)
