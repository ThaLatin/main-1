import sqlite3


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

# Add status column to messages table
try:
    cursor.execute("""
        ALTER TABLE messages ADD COLUMN status TEXT DEFAULT 'unread'
    """)
    connection.commit()
except sqlite3.OperationalError:
    pass

# Add role column to users table
try:
    cursor.execute("""
        ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'
    """)
    connection.commit()
except sqlite3.OperationalError:
    pass

# Make sure the existing admin account has admin role
cursor.execute("""
    UPDATE users
    SET role = 'admin'
    WHERE username = 'admin'
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    attempts INTEGER NOT NULL DEFAULT 0,
    locked_until REAL DEFAULT 0
)
""")
connection.commit()
connection.close()