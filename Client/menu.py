class Menu:
    def __init__(self, description, items=None):
        self.description = description
        self.items = dict([
            (unicode("1"), unicode('Create new conversation')),
            (unicode("2"), unicode('Enter a conversation')),
            (unicode("3"), unicode('Quit'))
        ])

    def display(self):
        print(self.description)
        for key in sorted(self.items.keys()):
            print "\t", key, " ", self.items[key]

menu = Menu("Choose preferred action:")