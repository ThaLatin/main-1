import sqlite3
from werkzeug.security import generate_password_hash

connection = sqlite3.connect("messages.db")

cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    subject TEXT,
    message TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
)
""")

cursor.execute("""
    UPDATE users
    SET role = 'admin'
    WHERE username = 'admin'
""")

connection.commit()

try:
    cursor.execute("""
                 ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'
            """)
    connection.commit()

except sqlite3.OperationalError:
    pass

password_hash = generate_password_hash("1234")

cursor.execute("""
INSERT OR IGNORE INTO users (username, password)
VALUES (?, ?)
""", ("admin", password_hash))

connection.commit()

connection.close()



