"""Sample file with security issues for PyCQ analyzer testing."""

import os
import subprocess
import pickle
import sqlite3
import hashlib
from urllib.parse import parse_qs


# CWE-78: OS Command Injection
def execute_command(command_input):
    """Execute a system command (unsafe)."""
    # Unsafe: command injection vulnerability
    os.system("echo " + command_input)

    # Another command injection vulnerability
    subprocess.call("grep " + command_input + " /var/log/system.log", shell=True)

    return "Command executed"


# CWE-798: Use of Hard-coded Credentials
def connect_to_database():
    """Connect to database with hardcoded credentials."""
    username = "admin"
    password = "super_secret_password"  # Hard-coded password

    connection_string = f"Server=database.example.com;Database=app_db;User Id={username};Password={password};"
    return connection_string


# CWE-22: Path Traversal
def read_file(filename):
    """Read a file with path traversal vulnerability."""
    # Unsafe: path traversal vulnerability
    try:
        with open(filename, "r") as file:
            return file.read()
    except Exception as e:
        return f"Error: {str(e)}"


# CWE-89: SQL Injection
def get_user(username):
    """Get user from database with SQL injection vulnerability."""
    # Unsafe: SQL injection vulnerability
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Vulnerable to SQL injection
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)

    result = cursor.fetchall()
    cursor.close()
    conn.close()

    return result


# CWE-327: Use of a Broken or Risky Cryptographic Algorithm
def hash_password(password):
    """Hash a password using weak algorithm."""
    # Unsafe: Using MD5 which is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


# CWE-502: Deserialization of Untrusted Data
def load_object(serialized_data):
    """Deserialize data unsafely."""
    # Unsafe: deserializing untrusted data
    return pickle.loads(serialized_data)


# CWE-79: Cross-site Scripting (XSS)
def generate_html(user_input):
    """Generate HTML with XSS vulnerability."""
    # Unsafe: XSS vulnerability
    return f"<div>Welcome, {user_input}!</div>"


# CWE-352: Cross-Site Request Forgery (CSRF)
def process_request(request_data):
    """Process a request without CSRF protection."""
    # No CSRF token validation
    user_id = request_data.get("user_id")
    action = request_data.get("action")

    if action == "delete":
        return f"Deleting user {user_id}"
    elif action == "update":
        return f"Updating user {user_id}"
    return "Unknown action"


# CWE-120: Buffer Copy without Checking Size of Input
def copy_data(source, destination, length):
    """Copy data without proper bounds checking (conceptual in Python)."""
    # This is more for illustration as Python handles buffers automatically
    # but the concept exists in the code logic
    for i in range(length):
        if i < len(destination):  # This check is often missing in C/C++ code
            destination[i] = source[i]
    return destination


# CWE-601: URL Redirection to Untrusted Site
def redirect_to_url(url_param):
    """Redirect to URL without validation."""
    # Unsafe: Open redirect vulnerability
    return f"Redirecting to: {url_param}"
