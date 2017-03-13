# Connection to the chat server
SERVER      = '127.0.0.1'  # IP of the server
SERVER_PORT = '8888'          # port on which the server is running

# Check for new messages in conversation every X seconds
MSG_QUERY_INTERVAL = 1

# States of the application: in menu, ...
INIT                    = 0  # initial state
IN_MENU                 = 1  # in the menu (display, menu choice selection)
CREATE_CONVERSATION     = 2  # creation of a conversation state
SELECT_CONVERSATION     = 3  # entring a conversation state
IN_CONVERSATION         = 4  # chatting state
STOP                    = 5  # stopping state (application exits, triggered by CTRL+c)
