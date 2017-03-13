class Message:
    message_id = -1
    user_name = -1
    content = None

    def __init__(self, message_id, owner_name, content):
        self.message_id = message_id
        self.user_name = owner_name
        self.content = content

    def __str__(self):
        return "Message from: " + self.user_name + \
               " with content: " + self.content + \
               " with ID: " + str(self.message_id)
