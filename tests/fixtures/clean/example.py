import hashlib
import subprocess


def lookup(cursor, user_name):
    cursor.execute("SELECT * FROM users WHERE name = ?", (user_name,))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run_tool():
    return subprocess.run(["tool", "--version"], check=True)


API_KEY = "replace-me-with-a-real-secret"
