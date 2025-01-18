from abc import ABC, abstractmethod

class DatabaseHandler(ABC):
    def __init__(self):
        self.database = None
        
    @abstractmethod
    def connect(self, database_name: str):
        pass
    
    @abstractmethod
    def insert(self, query_template: str, data: dict):
        pass
    
    @abstractmethod
    def fetch(self, query: str, params: dict = None):
        pass
    
    @abstractmethod
    def close(self):
        pass