import sqlite3

conn = sqlite3.connect("cloud_security.db")
conn.row_factory = sqlite3.Row

cursor = conn.cursor()

cursor.execute("""
SELECT original_filename, sha256_hash
FROM files
""")

rows = cursor.fetchall()

print("=" * 60)
print("FILES AND SHA-256 HASHES")
print("=" * 60)

for row in rows:
    print(dict(row))

conn.close()