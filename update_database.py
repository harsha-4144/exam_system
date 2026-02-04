# file: update_database.py
import sqlite3

print("Updating your database...")

# Connect to your database
conn = sqlite3.connect("exam.db")
cur = conn.cursor()

# Add missing columns if they don't exist
try:
    cur.execute("ALTER TABLE submissions ADD COLUMN verdict TEXT DEFAULT 'PASS'")
    print("� Added 'verdict' column to submissions table")
except:
    print("� 'verdict' column already exists")

try:
    cur.execute("ALTER TABLE submissions ADD COLUMN score INTEGER DEFAULT 100")
    print("� Added 'score' column to submissions table")
except:
    print("� 'score' column already exists")

try:
    cur.execute("ALTER TABLE submissions ADD COLUMN timestamp DATETIME DEFAULT CURRENT_TIMESTAMP")
    print("� Added 'timestamp' column to submissions table")
except:
    print("� 'timestamp' column already exists")

try:
    cur.execute("ALTER TABLE questions ADD COLUMN time_limit INTEGER DEFAULT 1800")
    print("� Added 'time_limit' column to questions table")
except:
    print("� 'time_limit' column already exists")

# Update existing data
cur.execute("UPDATE submissions SET verdict = 'PASS', score = 100 WHERE verdict IS NULL")
print("� Updated existing submissions data")

# Add some test data if needed
cur.execute("SELECT COUNT(*) FROM submissions")
count = cur.fetchone()[0]
if count == 0:
    # Add sample submissions for testing
    cur.execute("INSERT INTO submissions (user_id, question_id, verdict, score) VALUES (2, 1, 'PASS', 100)")
    cur.execute("INSERT INTO submissions (user_id, question_id, verdict, score) VALUES (2, 2, 'FAIL', 50)")
    print("� Added test submission data")

conn.commit()
conn.close()

print("\n? Database updated successfully!")
print("You can now use all the admin features.")
