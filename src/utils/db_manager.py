import sqlite3
import os
import logging

logger = logging.getLogger("ThreatIntel.DB")

class DatabaseManager:
    def update_severity(self, indicator, severity):
        query = "UPDATE iocs SET severity = ? WHERE indicator = ?"
        try:
            self.conn.execute(query, (severity, indicator))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to update severity for {indicator}: {e}")
            
    def __init__(self, db_path="data/threat_intel.db"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.create_tables()

    def create_tables(self):
        query = """
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT UNIQUE,
            type TEXT,
            source TEXT,
            severity TEXT DEFAULT 'unknown',
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
        self.conn.execute(query)
        self.conn.commit()

    def add_ioc(self, indicator, ioc_type, source):
        query = "INSERT OR IGNORE INTO iocs (indicator, type, source) VALUES (?, ?, ?)"
        try:
            cursor = self.conn.execute(query, (indicator, ioc_type, source))
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
           
            logger.error(f"Failed to add IOC {indicator}: {e}")
            return False