import re
import time
import hmac
import sqlite3
import hashlib
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, session

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DB_NAME = "users.db"
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16


def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until REAL,
                created_at REAL NOT NULL
            )
        """)
        conn.commit()


def normalize_username(username: str) -> str:
    return username.strip().lower()


def validate_username(username: str) -> bool:
    if not username:
        return False
    if len(username) < 3 or len(username) > 50:
        return False
    return bool(re.fullmatch(r"[a-zA-Z0-9._-]+", username))


def validate_password_strength(password: str):
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must include at least one number."
    if not re.search(r"[^\w\s]", password):
        return False, "Password must include at least one special character."
    return True, "Password is strong."


def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = normalize_username(request.form.get("username", ""))
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not validate_username(username):
            flash("Invalid username. Use 3-50 characters: letters, numbers, ., _, -", "error")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        valid, message = validate_password_strength(password)
        if not valid:
            flash(message, "error")
            return render_template("register.html")

        salt = secrets.token_bytes(SALT_SIZE)
        password_hash = hash_password(password, salt)

        try:
            with get_db_connection() as conn:
                conn.execute("""
                    INSERT INTO users (username, password_hash, salt, failed_attempts, locked_until, created_at)
                    VALUES (?, ?, ?, 0, NULL, ?)
                """, (username, password_hash.hex(), salt.hex(), time.time()))
                conn.commit()

            flash("Account created successfully. Please log in.", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("That username is already taken.", "error")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = normalize_username(request.form.get("username", ""))
        password = request.form.get("password", "")

        if not validate_username(username):
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        with get_db_connection() as conn:
            user = conn.execute("""
                SELECT id, username, password_hash, salt, failed_attempts, locked_until
                FROM users
                WHERE username = ?
            """, (username,)).fetchone()

            if not user:
                flash("Invalid username or password.", "error")
                return render_template("login.html")

            now = time.time()

            if user["locked_until"] is not None and now < user["locked_until"]:
                remaining = int(user["locked_until"] - now)
                flash(f"Account temporarily locked. Try again in {remaining} seconds.", "error")
                return render_template("login.html")

            salt = bytes.fromhex(user["salt"])
            computed_hash = hash_password(password, salt).hex()

            if hmac.compare_digest(computed_hash, user["password_hash"]):
                conn.execute("""
                    UPDATE users
                    SET failed_attempts = 0, locked_until = NULL
                    WHERE id = ?
                """, (user["id"],))
                conn.commit()

                session["user_id"] = user["id"]
                session["username"] = user["username"]

                flash("Login successful.", "success")
                return redirect(url_for("dashboard"))

            failed_attempts = user["failed_attempts"] + 1
            locked_until = None

            if failed_attempts >= MAX_FAILED_ATTEMPTS:
                locked_until = now + LOCKOUT_SECONDS
                failed_attempts = 0

            conn.execute("""
                UPDATE users
                SET failed_attempts = ?, locked_until = ?
                WHERE id = ?
            """, (failed_attempts, locked_until, user["id"]))
            conn.commit()

            if locked_until:
                flash("Too many failed attempts. Account locked for 5 minutes.", "error")
            else:
                flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session.get("username"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)