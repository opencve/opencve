class BaseCheck(object):
    def __init__(self, cve_obj, cve_json):
        self.cve_obj = cve_obj
        self.cve_json = cve_json

    def get_name(self):
        return self.__class__.__name__

    def execute(self):
        raise NotImplementedError
