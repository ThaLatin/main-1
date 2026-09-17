from flask import Flask, request, render_template, session, redirect, url_for, flash
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import sqlite3
import os

load_dotenv()

app = Flask(__name__)

secret_key = os.getenv("SECRET_KEY")

if not secret_key:
    raise RuntimeError("SECRET_KEY is not set!")

app.secret_key = secret_key

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

csrf = CSRFProtect(app)



def get_database():
    connection = sqlite3.connect("messages.db")
    connection.row_factory = sqlite3.Row
    return connection


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

@app.route("/test-database")
def test_database():
    connection = get_database()

    cursor = connection.cursor()

    cursor.execute("SELECT * FROM messages")

    messages = cursor.fetchall()

    connection.close()

    return str([dict(message) for message in messages])

@app.route("/contact", methods=["POST"])
def contact():

    name = request.form["name"]
    email = request.form["email"]
    subject = request.form["subject"]
    message = request.form["message"]

    if not name or not email:
        flash("Name and email are required!")
        return redirect(url_for("contact_page"))

    if "@" not in email:
        flash("Please enter a valid email address!")
        return redirect(url_for("contact_page"))

    if len(message) > 1000:
        flash("Message must be 1000 characters or less!")
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
        username = request.form["username"]
        password = request.form["password"]

        if len(username) < 3:
            flash("Username must be at least 3 character long!")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Password must be at least 6 charater long!")
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

        flash("message")
        return redirect(url_for("register"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        connection = get_database()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )

        user = cursor.fetchone()

        connection.close()

        if user and check_password_hash(user["password"], password):
            session["logged_in"] = True
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("messages"))

        flash("Wrong username or password!")
        return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out")
    return redirect(url_for("login"))

@app.route("/messages")
def messages():

    if not session.get("logged_in"):
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        flash("You are not authorized to access this page!")
        return redirect(url_for("login"))

    connection = get_database()

    cursor = connection.cursor()

    cursor.execute("SELECT * FROM messages")

    messages = cursor.fetchall()

    connection.close()

    return render_template("messages.html", messages=messages)

@app.route("/delete-message/<int:message_id>", methods=["POST"])
def delete_message(message_id):
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    if session.get("role") != "admin":
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

@app.route("/edit-message/<int:message_id>", methods=["GET", "POST"])
def edit_message(message_id):
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        flash("You are not authorized to access this page!")
        return redirect(url_for("login"))

    connection = get_database()
    cursor = connection.cursor()

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        subject = request.form["subject"]
        message = request.form["message"]

        if not name or not email:
            flash("Name and email are required!")
            connection.close()
            return redirect(url_for("edit_message", message_id=message_id))

        if "@" not in email:
            flash("Please enter a valid email address!")
            connection.close()
            return redirect(url_for("edit_message", message_id=message_id))

        if len(message) > 1000:
            flash("Message must be 1000 characters or less!")
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

@app.route("/test-users")
def test_users():
    connection = get_database()
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()

    connection.close()

    return str([dict(user) for user in users])


if __name__ == "__main__":
    app.run(debug=True)

