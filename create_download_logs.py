import sqlite3

conn = sqlite3.connect("cloud_security.db")

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS download_logs
(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    file_name TEXT,
    ip_address TEXT,
    download_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()
conn.close()

print("Download Logs table created successfully.")