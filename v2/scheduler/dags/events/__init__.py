class BaseEvents(object):
    def __init__(self, old, new):
        self.old = old
        self.new = new

    def get_name(self):
        return self.__class__.__name__

    def execute(self):
        raise NotImplementedError
