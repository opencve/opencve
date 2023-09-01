class Base:
    def handle(self):
        print("Analysing...")
        if not self.validate():
            return
        self.execute()

    def validate(self):
        raise NotImplemented

    def execute(self):
        raise NotImplemented

class A(Base):
    def validate(self):
        return True

    def execute(self):
        print("je suis execute")


a = A()
a.handle()        
