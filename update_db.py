# update_db.py
import sqlite3

conn = sqlite3.connect("exam.db")
cur = conn.cursor()

# Add time_limit column if it doesn't exist
try:
    cur.execute("ALTER TABLE questions ADD COLUMN time_limit INTEGER DEFAULT 1800")
    print("Added time_limit column to questions table")
except sqlite3.OperationalError as e:
    if "duplicate column name" in str(e):
        print("time_limit column already exists")
    else:
        print(f"Error: {e}")

# Update existing questions with default time limit
cur.execute("UPDATE questions SET time_limit = 1800 WHERE time_limit IS NULL")
print("Updated existing questions with default time limit")

conn.commit()
conn.close()
print("Database updated successfully")
