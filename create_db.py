import sqlite3
from config import Config

# ==========================================
# CONNECT TO DATABASE
# ==========================================

connection = sqlite3.connect(Config.DATABASE)

cursor = connection.cursor()

# ==========================================
# USERS TABLE
# ==========================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS users(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    fullname TEXT NOT NULL,

    email TEXT UNIQUE NOT NULL,

    phone TEXT NOT NULL,

    username TEXT UNIQUE NOT NULL,

    password TEXT NOT NULL,

    status TEXT DEFAULT 'Active',

    verified INTEGER DEFAULT 0,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

)
""")

# ==========================================
# ADMINS TABLE
# ==========================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS admins(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT UNIQUE NOT NULL,

    password TEXT NOT NULL,

    role TEXT DEFAULT 'Admin'

)
""")

# ==========================================
# LOGIN LOGS
# ==========================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS login_logs(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT,

    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    ip_address TEXT,

    status TEXT

)
""")


cursor.execute("""
CREATE TABLE IF NOT EXISTS download_logs(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT,

    file_name TEXT,

    ip_address TEXT,

    download_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP

)
""")


# ==========================================
# FILES TABLE
# ==========================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS files(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT,

    original_filename TEXT,

    encrypted_filename TEXT,

    file_size INTEGER,

    upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    sha256_hash TEXT

    verification_status TEXT DEFAULT 'Not Verifird'

)
""")

# ==========================================
# FILE KEYS TABLE
# ==========================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS file_keys(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    file_id INTEGER,

    aes_key TEXT,

    iv TEXT

)
""")

# ==========================================
# SECURITY LOGS TABLE
# ==========================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS security_logs(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT,

    activity TEXT,

    ip_address TEXT,

    log_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP

)
""")

# ==========================================
# ALERTS TABLE
# ==========================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT,

    alert_type TEXT,

    description TEXT,

    alert_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP

)
""")

# ==========================================
# OTP TABLE
# ==========================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS otp(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    email TEXT,

    otp TEXT,

    expiry_time TEXT

)
""")

# ==========================================
# SESSIONS TABLE
# ==========================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS sessions(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT,

    session_token TEXT,

    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    expiry_time TEXT

)
""")

# ==========================================
# INSERT DEFAULT ADMIN
# ==========================================

cursor.execute("""
INSERT OR IGNORE INTO admins
(
    username,
    password,
    role
)
VALUES
(
    'admin',
    'admin123',
    'Admin'
)
""")

# ==========================================
# SAVE CHANGES
# ==========================================

connection.commit()

connection.close()

# ==========================================
# SUCCESS MESSAGE
# ==========================================

print("=" * 50)
print("Cloud Security Database Created Successfully")
print("Default Admin")
print("Username : admin")
print("Password : admin123")
print("=" * 50)