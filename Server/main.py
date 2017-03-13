import tornado.ioloop
import tornado.web
import json

from ChatManager import ChatManager


class Constants:
    def __init__(self):
        pass

    COOKIE_NAME = "ChatCookie"


class JsonHandler(tornado.web.RequestHandler):
    """
    Request handler where requests and responses speak JSON.
    """

    def data_received(self, chunk):
        pass

    def __init__(self, application, request, **kwargs):
        super(JsonHandler, self).__init__(application, request, **kwargs)
        # Set up response dictionary.
        self.response = dict()

    def prepare(self):
        # Incorporate request JSON into arguments dictionary.
        if self.request.body:
            try:
                json_data = json.loads(self.request.body)
                self.request.arguments.update(json_data)
            except ValueError:
                message = 'Unable to parse JSON.'
                self.send_error(400, message=message)  # Bad Request

    def set_default_headers(self):
        self.set_header('Content-Type', 'application/json')

    def write_error(self, status_code, **kwargs):
        if 'message' not in kwargs:
            if status_code == 405:
                kwargs['message'] = 'Invalid HTTP method.'
            else:
                kwargs['message'] = 'Unknown error.'

        self.response = kwargs
        self.write_json()

    def write_json(self):
        output = json.dumps(self.response)
        self.write(output)

    def check_for_logged_in_user(self):
        user_name = self.get_secure_cookie(Constants.COOKIE_NAME)
        if not user_name:
            print "Unauthenticated request: denying answer!"
            self.send_error(401)  # Bad Request
        return user_name


class MainHandler(tornado.web.RequestHandler):
    def data_received(self, chunk):
        pass

    def get(self):
        """
        Not used URL entry.
        Only registered for convenience.
        """
        print "Main function, redirecting to login..."
        self.redirect("/login")


class LoginHandler(JsonHandler):
    def data_received(self, chunk):
        pass

    def post(self):
        """
        Try to login the user.
        Registered users are stored in RegisteredUsers.py
        Upon successful login, the user is added to the active users list.
        Further user authentication happens through cookies.
        """
        user_name = self.request.arguments['user_name']
        password = self.request.arguments['password']
        current_user = cm.login_user(user_name, password)

        if current_user:
            if not self.get_secure_cookie(Constants.COOKIE_NAME):
                self.set_secure_cookie(Constants.COOKIE_NAME, user_name)
            print "User " + user_name + " successfully logged in!"
            self.set_status(200)
            self.finish()
        else:
            # authentication error
            self.set_status(401)
            self.finish()


class UsersHandler(JsonHandler):
    def data_received(self, chunk):
        pass

    def get(self):
        """
        Returns all registered user.
        Required for starting a new conversation.
        """

        print "Sending available users"
        users = cm.get_all_users()

        # Set JSON response
        self.response = users
        self.write_json()


class ConversationHandler(JsonHandler):
    def data_received(self, chunk):
        pass

    def get(self):
        """
        Returns all conversations for the logged in user.
        """

        # check user login
        user_name = self.check_for_logged_in_user()
        if not user_name:
            return

        print "Getting all conversations for user: " + user_name
        conversations = cm.get_my_conversations(user_name)
        user_conversations = []

        # transform the list of conversations
        for conversation in conversations:
            user_conversation = {'conversation_id': conversation.conversation_id,
                                 'participants': conversation.participants}
            user_conversations.append(user_conversation)

        self.write(json.dumps(user_conversations))


class ConversationCreateHandler(JsonHandler):
    def data_received(self, chunk):
        pass

    def post(self):
        """
        It creates a new conversation.
        Participant names are required in the json parameters.
        """

        # check user login
        user_name = self.check_for_logged_in_user()
        if not user_name:
            return

        try:
            # owner should be included as well!
            participants = self.request.arguments['participants']
            participants = json.loads(participants)
            cm.create_conversation(participants)
        except KeyError as e:
            print "KeyError during conversation creation!", e.message
            self.send_error(400, message=e.message)
            return
        except Exception as e:
            self.send_error(400, message=e.message)
            return

        self.set_status(200)
        self.finish()


class ConcreteConversationHandler(JsonHandler):

    def data_received(self, chunk):
        pass

    def get(self, conversation_id, last_message_id):
        """
        Sends back the messages since the last seen message for the client.
        :param conversation_id: the id of the conversation queried
        :param last_message_id: the id of the last message seen by the client
        :return: array of messages
        """

        # check user login
        user_name = self.check_for_logged_in_user()
        if not user_name:
            return

        print "Getting messages in conversation: " + str(conversation_id) + \
              " for user: " + user_name + \
              " since: " + str(last_message_id)

        conversation = cm.get_conversation(conversation_id)
        if not conversation:
            print "Conversation not found"
            self.send_error(500)
            return

        messages = conversation.get_messages_since(last_message_id)

        # Transforming the messages list for the chat client
        answer = []
        for message in messages:
            new_answer_item = dict()
            new_answer_item['content'] = message.content
            new_answer_item['message_id'] = message.message_id
            new_answer_item['owner'] = message.user_name
            answer.append(new_answer_item)

        # send JSON reply
        self.response = answer
        self.write_json()

    def post(self, conversation_id):
        """
        Process sent new messages.
        (Conversation id sent in URL parameter, message sent in POST body az JSON.
        :param conversation_id: the id of the conversation of the message
        """

        # check user login
        user_name = self.check_for_logged_in_user()
        if not user_name:
            return

        # getting the requested conversation
        conversation = cm.get_conversation(conversation_id)
        if not conversation:
            print "conversation not found"
            self.send_error(500)
            return

        # get the posted message
        try:
            # owner should be included as well!
            message = self.request.arguments['content']
            conversation.add_message(user_name, message)
        except KeyError as e:
            print "KeyError! Message content was not readable!", e.message
            self.send_error(400, message=e.message)
            return
        except Exception as e:
            print e.message
            self.send_error(400, message=e.message)
            return

        self.set_status(200)
        self.finish()


def init_app():
    """
    Initializes the Tornado web app.
    Registers the used URLs.
    """
    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/login", LoginHandler),
        (r"/users", UsersHandler),
        (r"/conversations", ConversationHandler),
        (r"/conversations/create", ConversationCreateHandler),
        (r"/conversations/([0-9]+)", ConcreteConversationHandler),
        (r"/conversations/([0-9]+)/([0-9]+)?", ConcreteConversationHandler)
    ],
        cookie_secret="6d41bbfe48ce3d078479feb364d98ecda2206edc"
    )


if __name__ == "__main__":
    cm = ChatManager()
    app = init_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()
