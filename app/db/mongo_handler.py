from pymongo import MongoClient
from ..config import Config
import logging

class MongoHandler:
    def __init__(self):
        self.client = None
        self.db = None

    def connect(self, database_name: str):
        """Connect to MongoDB"""
        try:
            self.client = MongoClient(Config.MONGODB_URI)
            self.db = self.client[database_name]
            logging.info(f"Connected to MongoDB database: {database_name}")
        except Exception as e:
            logging.error(f"MongoDB connection error: {str(e)}")
            raise

    def insert_one(self, collection: str, data: dict) -> str:
        """Insert one document"""
        result = self.db[collection].insert_one(data)
        return str(result.inserted_id)

    def find_one(self, collection: str, query: dict) -> dict:
        """Find one document"""
        return self.db[collection].find_one(query)

    def update_one(self, collection: str, query: dict, update: dict):
        """Update one document"""
        return self.db[collection].update_one(query, update)

    def delete_one(self, collection: str, query: dict):
        """Delete one document"""
        return self.db[collection].delete_one(query)

    def close(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            logging.info("MongoDB connection closed")