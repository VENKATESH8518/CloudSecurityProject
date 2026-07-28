import sqlite3

# Change this if your database has a different name
database = "cloud_security.db"

conn = sqlite3.connect(database)
cursor = conn.cursor()

try:
    cursor.execute("""
        ALTER TABLE files
        ADD COLUMN verification_status TEXT DEFAULT 'Not Verified'
    """)

    conn.commit()
    print("verification_status column added successfully.")

except Exception as e:
    print("Error:", e)

finally:
    conn.close()