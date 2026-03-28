import sqlite3
import subprocess
import hashlib
import pickle
import os

# ===========================
# SAST kwetsbaarheden (SonarQube)
# ===========================

# 1. Hardcoded credentials (Security Hotspot)
DB_PASSWORD = "admin123"
SECRET_KEY = "supersecretkey123"
API_KEY = "sk-1234567890abcdef"

# 2. SQL Injection
def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # FOUT: directe string concatenatie = SQL injection
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()

# 3. Command Injection
def ping_host(host):
    # FOUT: user input direct in shell commando
    result = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)
    return result.stdout

# 4. Insecure hashing (MD5 is broken)
def hash_password(password):
    # FOUT: MD5 is cryptografisch onveilig
    return hashlib.md5(password.encode()).hexdigest()

# 5. Insecure deserialization
def load_data(data):
    # FOUT: pickle.loads op onbetrouwbare data
    return pickle.loads(data)

# 6. Path traversal
def read_file(filename):
    # FOUT: geen validatie van bestandspad
    with open("/var/data/" + filename, "r") as f:
        return f.read()

# ===========================
# Hoofd applicatie
# ===========================

def main():
    print("Hello, World!")
    print("Welkom bij de kwetsbare demo applicatie")

    # Simuleer een gebruiker opzoeken
    user = get_user("admin")
    print(f"Gebruiker gevonden: {user}")

    # Simuleer wachtwoord hashing
    hashed = hash_password("mijnwachtwoord")
    print(f"Wachtwoord hash: {hashed}")

if __name__ == "__main__":
    main()