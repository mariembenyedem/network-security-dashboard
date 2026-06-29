import sqlite3

connection = sqlite3.connect("database/security.db")

cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts(

id INTEGER PRIMARY KEY,

ip TEXT,

alert TEXT

)
""")

connection.commit()