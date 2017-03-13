from user import User
from json import JSONEncoder


class Message():
    '''
    Represents a single message in a conversation
    '''

    def __init__(self, owner_name="", content=""):
        '''
        Constructor
        :param owner_name: user name of the user who created the message
        :param content: the raw message as a string
        :return: instance
        '''
        self.content = content
        self.owner = User(owner_name)

    def __str__(self):
        '''
        Called when the message is printed with the print or str() instructions
        :return: string
        '''
        return str(self.owner) + " " + self.content + "\n"

    def __eq__(self, other):
        assert isinstance(other, Message)
        return (self.content == other.content) and (self.owner.get_user_name() == other.owner.get_user_name())

    def __ne__(self, other):
        assert isinstance(other, Message)
        return not (self == other)

    def get_owner(self):
        '''
        Returns the user name of the user who created the message
        :return: string
        '''
        return self.owner

    def get_content(self):
        '''
        Returns the raw message contents
        :return: string
        '''
        return self.content

class MessageEncoder(JSONEncoder):
    '''
    Class responsible for JSON encoding instances of the Message class
    '''
    def default(self, o):
        '''
        Does the encoding
        :param o: should be an instance of the Message class
        :return: dict that can be serialized into JSON
        '''
        assert isinstance(o, Message)
        return {"content" : o.get_content()}