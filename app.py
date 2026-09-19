from flask import Flask, request, render_template, session, redirect, url_for, flash
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from email_validator import validate_email, EmailNotValidError
import sqlite3
import os
import time
import re

load_dotenv()

app = Flask(__name__)

app.config["DEBUG"] = os.getenv("DEBUG", "False").lower() == "true"

app.config["SESSION_COOKIE_SECURE"] = os.getenv(
    "SESSION_COOKIE_SECURE", "False"
).lower() == "true"

secret_key = os.getenv("SECRET_KEY")

if not secret_key:
    raise RuntimeError("SECRET_KEY is not set!")

app.secret_key = secret_key

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_NAME"] = "main_session"

app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

csrf = CSRFProtect(app)

def initialize_database():
    connection = sqlite3.connect("messages.db")
    cursor = connection.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        subject TEXT,
        message TEXT,
        status TEXT DEFAULT 'unread'
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user'
    )
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

initialize_database()


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com;"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response

def get_database():
    connection = sqlite3.connect("messages.db")
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection

def is_admin():
    if not session.get("logged_in"):
        return False

    connection = get_database()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT role FROM users WHERE username = ?",
        (session["username"],)
    )

    user = cursor.fetchone()

    connection.close()

    return bool (user and user["role"] == "admin")


@app.route("/")
def home():
    return render_template("index.html")

@app.route("/contact")
def contact_page():
    return render_template("contact.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/project")
def project():
    return render_template("project.html")

@app.route("/skills")
def skills():
    return render_template("skills.html")


@app.route("/contact", methods=["POST"])
def contact():

    name = request.form["name"].strip()
    email = request.form["email"].strip().lower()
    subject = request.form["subject"].strip()
    message = request.form["message"].strip()

    if not name.strip() or not email.strip():
        flash("Name and email are required!")
        return redirect(url_for("contact_page"))

    try:
        validated_email = validate_email(email)
        email = validated_email.normalized
    except EmailNotValidError:
        flash("Please enter a valid email address!")
        return redirect(url_for("contact_page"))

    if len(message.strip()) > 1000:
        flash("Message must be 1000 characters or less!")
        return redirect(url_for("contact_page"))

    if len(subject) > 200:
        flash("Subject must be 200 characters or less!")
        return redirect(url_for("contact_page"))

    if len(name) > 100:
        flash("Name must be 100 characters or less!")
        return redirect(url_for("contact_page"))

    if len(email) > 254:
        flash("Email must be 254 characters or less!")
        return redirect(url_for("contact_page"))

    connection = get_database()

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO messages (name, email, subject, message)
        VALUES (?, ?, ?, ?)
        """,
        (name, email, subject, message)
    )

    connection.commit()
    connection.close()

    return "Your message has been received!"

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]

        if len(username) < 3:
            flash("Username must be at least 3 characters long!")
            return redirect(url_for("register"))

        if len(username) > 50:
            flash("Username must be 50 characters or less!")
            return redirect(url_for("register"))

        if not re.fullmatch(r"[A-Za-z0-9_]+", username):
            flash("Username can only contain letters, numbers, and underscores!")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Password must be at least 6 characters long!")
            return redirect(url_for("register"))

        if len(password) > 128:
            flash("Password must be 128 characters or less!")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        connection = get_database()
        cursor = connection.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO users (username, password)
                VALUES (?, ?)
                """,
                (username, password_hash)
            )

            connection.commit()

        except sqlite3.IntegrityError:
            connection.close()
            flash("Username already exists. Please choose another one!")
            return redirect(url_for("register"))
        
        connection.close()

        flash("Account created successfully!")
        return redirect(url_for("register"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]

        # Check login attempts
        connection = get_database()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT * FROM login_attempts WHERE username = ?",
            (username,)
        )

        attempt_record = cursor.fetchone()

        connection.close()

        if attempt_record:
            attempts = attempt_record["attempts"]
        else:
            attempts = 0

        # Check lockout
        if attempts >= 5:
            lockout_time = attempt_record["locked_until"]

            if time.time() < lockout_time:
                flash("Too many failed login attempts. Please try again later.")
                return redirect(url_for("login"))

            # Lockout expired, reset attempts
            attempts = 0

            connection = get_database()
            cursor = connection.cursor()

            cursor.execute(
                """
                INSERT INTO login_attempts (username, attempts, locked_until)
                VALUES (?, 0, 0)
                ON CONFLICT(username)
                DO UPDATE SET attempts = 0, locked_until = 0
                """,
                (username,)
            )

            connection.commit()
            connection.close()

        # Find user
        connection = get_database()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )

        user = cursor.fetchone()

        connection.close()

        # Successful login
        if user and check_password_hash(user["password"], password):

            connection = get_database()
            cursor = connection.cursor()

            cursor.execute(
                "DELETE FROM login_attempts WHERE username = ?",
                (username,)
            )

            connection.commit()
            connection.close()

            session.clear()

            session["logged_in"] = True
            session["username"] = user["username"]
            session["role"] = user["role"]

            return redirect(url_for("messages"))

        # Failed login
        attempts += 1

        lockout_time = 0

        if attempts >= 5:
            lockout_time = time.time() + 300

        connection = get_database()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO login_attempts (username, attempts, locked_until)
            VALUES (?, ?, ?)
            ON CONFLICT(username)
            DO UPDATE SET
                attempts = excluded.attempts,
                locked_until = excluded.locked_until
            """,
            (username, attempts, lockout_time)
        )

        connection.commit()
        connection.close()

        flash("Wrong username or password!")
        return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/logout", methods=['post'])
def logout():
    session.clear()
    flash("You have been logged out")
    return redirect(url_for("login"))

@app.route("/messages")
def messages():
    if not is_admin():
        flash("You are not authorized to access this page!")
        return redirect(url_for("login"))

    connection = get_database()
    cursor = connection.cursor()

    search = request.args.get("search", "")
    status = request.args.get("status", "")

    if status not in ("", "unread", "read"):
        status = ""

    query = """
        SELECT * FROM messages
        WHERE (
            name LIKE ?
            OR email LIKE ?
            OR subject LIKE ?
            OR message LIKE ?
        )
    """

    params = [
        f"%{search}%",
        f"%{search}%",
        f"%{search}%",
        f"%{search}%"
    ]

    if status:
        query += " AND status = ?"
        params.append(status)

    cursor.execute(query, params)

    messages = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM messages
        WHERE status = 'unread'
    """)

    unread_messages = cursor.fetchone()[0]

    connection.close()

    return render_template(
        "messages.html",
        messages=messages,
        total_users=total_users,
        unread_messages=unread_messages
    )

@app.route("/delete-message/<int:message_id>", methods=["POST"])
def delete_message(message_id):
    if message_id <= 0:
        flash("Message not found")
        return redirect(url_for("messages"))
    
    if not is_admin():
        flash("You are not authorized to access this page!")
        return redirect(url_for("login"))

    connection = get_database()
    cursor = connection.cursor()

    cursor.execute(
        "DELETE FROM messages WHERE id = ?",
        (message_id,)
    )

    

    if cursor.rowcount == 0:
        connection.close()
        flash("Message not found")
        return redirect(url_for("messages"))

    connection.commit()
    connection.close()

    flash("Message deleted successfully!")
    return redirect(url_for("messages")) 

@app.route("/view-message/<int:message_id>")
def view_message(message_id):
    if message_id <= 0:
        flash("Message not found.")
        return redirect(url_for("messages"))
    
    if not is_admin():
        flash("You are not authorized to access this page!")
        return redirect(url_for("login"))

    connection = get_database()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT * FROM messages WHERE id = ?",
        (message_id,)
    )

    message_data = cursor.fetchone()

    if not message_data:
        connection.close()
        flash("Message not found.")
        return redirect(url_for("messages"))

    # Mark the message as read
    cursor.execute(
        """
        UPDATE messages
        SET status = 'read'
        WHERE id = ?
        """,
        (message_id,)
    )

    connection.commit()

    cursor.execute(
        "SELECT * FROM messages WHERE id = ?",
        (message_id,)
    )

    message_data = cursor.fetchone()
    
    connection.close()

    return render_template(
        "view_message.html",
        message=message_data
    )

@app.route("/edit-message/<int:message_id>", methods=["GET", "POST"])
def edit_message(message_id):
    if message_id <= 0:
        flash("Message not found.")
        return redirect(url_for("messages"))
    
    if not is_admin():
        flash("You are not authorized to access this page!")
        return redirect(url_for("login"))

    connection = get_database()
    cursor = connection.cursor()

    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        subject = request.form["subject"].strip()
        message = request.form["message"].strip()

        if not name or not email:
            flash("Name and email are required!")
            connection.close()
            return redirect(url_for("edit_message", message_id=message_id))

        try:
            validated_email = validate_email(email)
            email = validated_email.normalized
        except EmailNotValidError:
            flash("Please enter a valid email address!")
            connection.close()
            return redirect(url_for("edit_message", message_id=message_id))

        if len(message) > 1000:
            flash("Message must be 1000 characters or less!")
            connection.close()
            return redirect(url_for("edit_message", message_id=message_id))

        if len(subject) > 200:
            flash("Subject must be 200 characters or less!")
            connection.close()
            return redirect(url_for("edit_message", message_id=message_id))

        if len(name) > 100:
            flash("Name must be 100 characters or less!")
            connection.close()
            return redirect(url_for("edit_message", message_id=message_id))

        if len(email) > 254:
            flash("Email must be 254 characters or less!")
            connection.close()
            return redirect(url_for("edit_message", message_id=message_id))

        cursor.execute(
            """
            UPDATE messages
            SET name = ?, email = ?, subject = ?, message = ?
            WHERE id = ?
            """,
            (name, email, subject, message, message_id)
        )

        connection.commit()
        connection.close()

        flash("Message updated successfully!")
        return redirect(url_for("messages"))

    cursor.execute(
        "SELECT * FROM messages WHERE id = ?",
        (message_id,)
    )

    message_data = cursor.fetchone()

    if not message_data:
        flash("Message not found")
        connection.close()
        return redirect(url_for("messages"))
    
    connection.close()

    return render_template(
        "edit_message.html",
        message=message_data
    )  

@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404

@app.errorhandler(403)
def forbidden(error):
    return render_template("403.html"), 403

@app.errorhandler(500)
def internal_server_error(error):
    return render_template("500.html"), 500

@app.errorhandler(413)
def request_too_large(error):
    return render_template("413.html"), 413



if __name__ == "__main__":
    app.run(debug=app.config["DEBUG"])

