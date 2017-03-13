# chat manager
from chat_manager import ChatManager
# signals
import signal
# command line parameter
import sys
# file manipulations
import os.path
# loading user credentials from json files
import json


def main():
    # Check the existence of the user credential configuration file
    if len(sys.argv) < 2:
        print "Specify configuration file from which user credentials are to be read!"
        return
    if os.path.exists(sys.argv[1]) == False:
        print "Specified configuration file does not exists!"
        return
    credentials = {
        "user_name" : "",
        "password"  : ""
    }
    with open(sys.argv[1]) as credentials_file:
        # Load credentials
        credentials = json.load(credentials_file)
    try:
        # Initialize chat client with the provided credentials
        c = ChatManager(user_name=credentials["user_name"],
                        password=credentials["password"])
    except KeyError:
        # In case the JSON file is malformed
        print "Unable to get user credentials from JSON file"
        return
    # Register function of menu handling to specific signals from the OS
    try:
        signal.signal(signal.SIGBREAK, c.enter_menu) # for Windows: CRTL+BREAK
    except AttributeError:
        try:
            signal.signal(signal.SIGTSTP, c.enter_menu) # for Mac and Linux: CTRL+z
        except AttributeError:
            print "No signal could be registered for entering the menu"
            return
    c.run()

if __name__ == '__main__':
    main()
