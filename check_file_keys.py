import sqlite3
from config import Config

connection = sqlite3.connect(Config.DATABASE)
connection.row_factory = sqlite3.Row

cursor = connection.cursor()

print("=" * 60)
print("FILES TABLE")
print("=" * 60)

cursor.execute("SELECT * FROM files")

for row in cursor.fetchall():
    print(dict(row))

print("\n")

print("=" * 60)
print("FILE_KEYS TABLE")
print("=" * 60)

cursor.execute("SELECT * FROM file_keys")

rows = cursor.fetchall()

if len(rows) == 0:
    print("No records found.")
else:
    for row in rows:
        print(dict(row))

connection.close()