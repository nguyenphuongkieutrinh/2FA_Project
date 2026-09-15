from flask import Flask, render_template, request, redirect
import sqlite3
import pyotp
import qrcode
import io
import base64
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)


def init_db():
    conn = sqlite3.connect("database.db")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT,
            two_fa_enabled INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


@app.route("/", methods=["GET", "POST"])
def register():
    message = ""

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        password_hash = generate_password_hash(password)

        try:
            conn = sqlite3.connect("database.db")
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
            conn.commit()
            conn.close()

            message = "Registration successful!"

        except sqlite3.IntegrityError:
            message = "Username already exists."

    return render_template("register.html", message=message)


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        user = conn.execute(
            "SELECT password_hash, totp_secret, two_fa_enabled FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user[0], password):
            if user[2] == 1:
                return redirect("/verify_otp?username=" + username)

            message = "Password authentication successful!"
        else:
            message = "Invalid username or password."

    return render_template("login.html", message=message)


@app.route("/setup_2fa", methods=["GET", "POST"])
def setup_2fa():
    username = request.args.get("username")

    conn = sqlite3.connect("database.db")

    user = conn.execute(
        "SELECT id, totp_secret FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if not user:
        conn.close()
        return "User not found."

    user_id = user[0]
    secret = user[1]

    if not secret:
        secret = pyotp.random_base32()

        conn.execute(
            "UPDATE users SET totp_secret = ? WHERE id = ?",
            (secret, user_id)
        )
        conn.commit()

    conn.close()

    totp = pyotp.TOTP(secret)

    uri = totp.provisioning_uri(
        name=username,
        issuer_name="2FA System"
    )

    qr = qrcode.make(uri)

    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")

    qr_code = base64.b64encode(buffer.getvalue()).decode()

    message = ""

    if request.method == "POST":
        otp = request.form["otp"]

        if totp.verify(otp):
            conn = sqlite3.connect("database.db")
            conn.execute(
                "UPDATE users SET two_fa_enabled = 1 WHERE id = ?",
                (user_id,)
            )
            conn.commit()
            conn.close()

            message = "2FA setup successful!"
        else:
            message = "Invalid OTP code."

    return render_template(
        "setup_2fa.html",
        qr_code=qr_code,
        message=message
    )


@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    username = request.args.get("username")
    message = ""

    conn = sqlite3.connect("database.db")

    user = conn.execute(
        "SELECT totp_secret FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    conn.close()

    if not user:
        return "User not found."

    secret = user[0]

    if request.method == "POST":
        otp = request.form["otp"]

        totp = pyotp.TOTP(secret)

        if totp.verify(otp):
            message = "Login successful! 2FA verification passed."
        else:
            message = "Invalid or expired OTP."

    return render_template("verify_otp.html", message=message)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
