import sqlite3

# Connect to the local SQLite file
conn = sqlite3.connect('securevision.db')
cursor = conn.cursor()

# Query SQLite's internal master table to list all created tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

print("Tables found in database: ", [table[0] for table in tables])
conn.close()
