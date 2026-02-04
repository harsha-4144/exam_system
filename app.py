from flask import Flask, render_template, request, redirect, session
import sqlite3
import subprocess
import os
import resource
import tempfile
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "exam-secret-key"

def db():
    return sqlite3.connect("exam.db")

def is_logged_in():
    return "user_id" in session

def is_admin():
    return session.get("username") == "admin"

# ---------- SECURITY ----------

BLOCKED_KEYWORDS = [
    "import os",
    "import sys",
    "import subprocess",
    "import socket",
    "open(",
    "exec(",
    "eval("
]

def is_code_safe(code):
    for k in BLOCKED_KEYWORDS:
        if k in code:
            return False, k
    return True, None

def limit_resources():
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_AS, (64 * 1024 * 1024, 64 * 1024 * 1024))

# ---------- AUTH ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = db()
        cur = conn.cursor()
        cur.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()

        if not row:
            error = "Invalid username"
        else:
            user_id, hashed = row
            if not hashed or not check_password_hash(hashed, password):
                error = "Invalid password"
            else:
                session["user_id"] = user_id
                session["username"] = username
                return redirect("/")

    return render_template("login.html", error=error)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return "Username and password required"

        hashed = generate_password_hash(password)

        conn = db()
        cur = conn.cursor()

        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            conn.close()
            return "User already exists. Please login."

        cur.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed)
        )
        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ---------- CORE ----------

@app.route("/")
def questions():
    if "user_id" not in session:
        return redirect("/login")

    conn = db()
    cur = conn.cursor()

    cur.execute("""
        SELECT q.id, q.title,
        EXISTS (
            SELECT 1 FROM submissions s
            WHERE s.question_id = q.id
              AND s.user_id = ?
        ) AS completed
        FROM questions q
        ORDER BY q.id
    """, (session["user_id"],))

    questions = cur.fetchall()
    conn.close()

    return render_template(
        "questions.html",
        questions=questions,
        user=session["username"],
        admin=is_admin()
    )

@app.route("/question/<int:qid>")
def exam_page(qid):
    if not is_logged_in():
        return redirect("/login")

    conn = db()
    cur = conn.cursor()

    # Fetch question with time_limit
    cur.execute(
        "SELECT title, description, time_limit FROM questions WHERE id = ?",
        (qid,)
    )
    q = cur.fetchone()

    # Fetch FIRST TWO test cases as examples
    cur.execute(
        """
        SELECT input, expected_output
        FROM test_cases
        WHERE question_id = ? AND is_example = 1
        ORDER BY id ASC
        """,
        (qid,)
    )
    examples = cur.fetchall()

    conn.close()

    # Convert time_limit to minutes for display
    time_limit_minutes = q[2] // 60 if q[2] else 30

    return render_template(
        "exam.html",
        question_id=qid,
        title=q[0],
        description=q[1],
        examples=examples,
        time_limit=q[2],  # Pass in seconds
        time_limit_minutes=time_limit_minutes  # Pass in minutes for display
    )

@app.route("/run", methods=["POST"])
def run_code():
    if not is_logged_in():
        return {"output": "Not logged in"}, 401

    question_id = request.form.get("question_id")
    code = request.form.get("code")

    if not code:
        return {"output": "No code provided"}

    safe, keyword = is_code_safe(code)
    if not safe:
        return {"output": f"Blocked keyword detected: {keyword}"}

    conn = db()
    cur = conn.cursor()
    cur.execute("""
        SELECT input, expected_output
        FROM test_cases
        WHERE question_id = ?
        ORDER BY id ASC
        LIMIT 1
    """, (question_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return {"output": "No test cases found"}

    inp, expected = row

    try:
        with tempfile.NamedTemporaryFile(suffix=".py", delete=True) as f:
            f.write(code.encode())
            f.flush()

            r = subprocess.run(
                ["python3", f.name],
                input=inp,
                capture_output=True,
                text=True,
                timeout=2,
                preexec_fn=limit_resources
            )

            if r.returncode != 0:
                return {"output": r.stderr or "Runtime error"}

            return {
                "output": r.stdout.strip(),
                "expected": expected.strip()
            }

    except subprocess.TimeoutExpired:
        return {"output": "TIME LIMIT EXCEEDED"}

@app.route("/submit", methods=["POST"])
def submit():
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]
    question_id = int(request.form.get("question_id"))
    code = request.form.get("code") or ""

    # ---------- SAFETY CHECK ----------
    safe, keyword = is_code_safe(code)
    if not safe:
        return render_template(
            "result.html",
            verdict="REJECTED",
            error=f"Blocked keyword detected: {keyword}",
            results=[],
            passed=0,
            total=0,
            score=0,
            question_id=question_id
        )

    # ---------- LOAD TEST CASES ----------
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT input, expected_output FROM test_cases WHERE question_id = ? AND is_example = 0",
        (question_id,)
    )
    tests = cur.fetchall()
    conn.close()

    results = []
    passed_count = 0
    total_tests = len(tests)

    # ---------- EXECUTION ----------
    try:
        with tempfile.NamedTemporaryFile(suffix=".py", delete=True) as f:
            f.write(code.encode())
            f.flush()

            for i, (inp, exp) in enumerate(tests, start=1):
                r = subprocess.run(
                    ["python3", f.name],
                    input=inp,
                    text=True,
                    capture_output=True,
                    timeout=2,
                    preexec_fn=limit_resources
                )

                actual = r.stdout.strip() if r.stdout else ""

                if r.returncode == 0 and actual == exp.strip():
                    status = "PASS"
                    passed_count += 1
                else:
                    status = "FAIL"

                results.append({
                    "id": i,
                    "input": inp,
                    "expected": exp.strip(),
                    "actual": actual,
                    "status": status
                })

    except subprocess.TimeoutExpired:
        return render_template(
            "result.html",
            verdict="TIMEOUT",
            results=[],
            passed=0,
            total=total_tests,
            score=0,
            question_id=question_id
        )

    # ---------- FINAL VERDICT ----------
    verdict = "PASS" if passed_count == total_tests else "FAIL"
    score = int((passed_count / total_tests) * 100) if total_tests else 0

    # ---------- SAVE SUBMISSION ----------
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO submissions (user_id, question_id, verdict, score) VALUES (?, ?, ?, ?)",
        (user_id, question_id, verdict, score)
    )
    conn.commit()
    conn.close()

    # ---------- RESULT PAGE ----------
    return render_template(
        "result.html",
        verdict=verdict,
        total=total_tests,
        passed=passed_count,
        score=score,
        results=results,
        question_id=question_id
    )

# ---------- ADMIN ----------

@app.route("/admin/dashboard")
def admin_dashboard():
    if not is_logged_in() or not is_admin():
        return redirect("/")
    
    conn = db()
    cur = conn.cursor()
    
    # Get statistics
    cur.execute("SELECT COUNT(*) FROM questions")
    total_questions = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM submissions")
    total_submissions = cur.fetchone()[0]
    
    # Get recent questions with time_limit
    cur.execute("""
        SELECT q.id, q.title, COUNT(t.id) as test_count, q.time_limit
        FROM questions q
        LEFT JOIN test_cases t ON t.question_id = q.id
        GROUP BY q.id
        ORDER BY q.id DESC
        LIMIT 5
    """)
    recent_questions = cur.fetchall()
    
    # Calculate success rate
    cur.execute("SELECT COUNT(*) FROM submissions WHERE verdict = 'PASS'")
    passed = cur.fetchone()[0]
    success_rate = int((passed / total_submissions * 100)) if total_submissions > 0 else 0
    
    conn.close()
    
    stats = {
        'total_questions': total_questions,
        'total_users': total_users,
        'total_submissions': total_submissions,
        'questions_this_month': min(5, total_questions),
        'new_users': min(3, total_users),
        'submissions_today': min(10, total_submissions),
        'success_rate': success_rate
    }
    
    return render_template(
        "admin_dashboard.html",
        stats=stats,
        recent_questions=recent_questions
    )

@app.route("/admin/questions")
def admin_questions():
    if not is_logged_in() or not is_admin():
        return redirect("/")

    conn = db()
    cur = conn.cursor()

    cur.execute("""
        SELECT q.id, q.title, COUNT(t.id)
        FROM questions q
        LEFT JOIN test_cases t ON t.question_id = q.id
        GROUP BY q.id
        ORDER BY q.id
    """)
    questions = cur.fetchall()
    conn.close()

    return render_template("admin_questions.html", questions=questions)

@app.route("/admin/delete/<int:qid>", methods=["POST"])
def delete_question(qid):
    if not is_logged_in() or not is_admin():
        return redirect("/")

    conn = db()
    cur = conn.cursor()

    # Delete test cases first
    cur.execute("DELETE FROM test_cases WHERE question_id = ?", (qid,))
    # Delete submissions related to this question
    cur.execute("DELETE FROM submissions WHERE question_id = ?", (qid,))
    # Delete the question
    cur.execute("DELETE FROM questions WHERE id = ?", (qid,))

    conn.commit()
    conn.close()

    return redirect("/admin/questions")

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not is_logged_in() or not is_admin():
        return redirect("/")

    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        marks = request.form.get("marks", 10)
        time_limit = int(request.form.get("time_limit", 30)) * 60  # Convert minutes to seconds
        inputs = request.form.getlist("input[]")
        outputs = request.form.getlist("output[]")
        examples = request.form.getlist("is_example[]")

        conn = db()
        cur = conn.cursor()

        # Insert question with time_limit
        cur.execute(
            "INSERT INTO questions (title, description, marks, time_limit) VALUES (?, ?, ?, ?)",
            (title, description, marks, time_limit)
        )
        qid = cur.lastrowid

        # Insert test cases
        for i in range(len(inputs)):
            is_example = 1 if str(i) in examples else 0
            
            cur.execute(
                """
                INSERT INTO test_cases (question_id, input, expected_output, is_example)
                VALUES (?, ?, ?, ?)
                """,
                (qid, inputs[i], outputs[i], is_example)
            )

        conn.commit()
        conn.close()

        return redirect("/admin/questions")

    return render_template("admin.html")

@app.route("/admin/edit/<int:qid>", methods=["GET", "POST"])
def edit_question(qid):
    if not is_logged_in() or not is_admin():
        return redirect("/")

    conn = db()
    cur = conn.cursor()

    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        time_limit = int(request.form.get("time_limit", 30)) * 60
        inputs = request.form.getlist("input[]")
        outputs = request.form.getlist("output[]")
        examples = request.form.getlist("is_example[]")

        # Update question
        cur.execute(
            "UPDATE questions SET title = ?, description = ?, time_limit = ? WHERE id = ?",
            (title, description, time_limit, qid)
        )

        # Remove old test cases
        cur.execute("DELETE FROM test_cases WHERE question_id = ?", (qid,))

        # Insert new test cases
        for i in range(len(inputs)):
            is_example = 1 if str(i) in examples else 0
            
            cur.execute(
                """
                INSERT INTO test_cases (question_id, input, expected_output, is_example)
                VALUES (?, ?, ?, ?)
                """,
                (qid, inputs[i], outputs[i], is_example)
            )

        conn.commit()
        conn.close()

        return redirect("/admin/questions")

    # GET: load existing data
    cur.execute(
        "SELECT title, description, time_limit FROM questions WHERE id = ?",
        (qid,)
    )
    question = cur.fetchone()

    cur.execute(
        """SELECT input, expected_output, is_example
        FROM test_cases
        WHERE question_id = ?
        ORDER BY id
        """,
        (qid,)
    )
    test_cases = cur.fetchall()

    conn.close()

    return render_template(
        "admin_edit.html",
        question=question,
        test_cases=test_cases,
        qid=qid
    )

@app.route("/admin/users")
def admin_users():
    if not is_logged_in() or not is_admin():
        return redirect("/")
    
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users ORDER BY id")
    users = cur.fetchall()
    conn.close()
    
    return render_template("admin_users.html", users=users)

# ---------- ADMIN USER REPORTS ----------

@app.route("/admin/user_reports")
def admin_user_reports():
    if not is_logged_in() or not is_admin():
        return redirect("/")
    
    conn = db()
    cur = conn.cursor()
    
    # Get all users with their submission stats
    # FIXED: Use COALESCE to handle NULL values when users have no submissions
    cur.execute("""
        SELECT 
            u.id, 
            u.username, 
            COALESCE(COUNT(s.id), 0) as total_submissions,
            COALESCE(SUM(CASE WHEN s.verdict = 'PASS' THEN 1 ELSE 0 END), 0) as passed,
            COALESCE(AVG(s.score), 0) as avg_score
        FROM users u
        LEFT JOIN submissions s ON s.user_id = u.id
        GROUP BY u.id, u.username
        ORDER BY u.username
    """)
    users_data = cur.fetchall()
    
    # Format the data
    user_stats = []
    for user in users_data:
        user_id, username, total, passed, avg_score = user
        avg_score = round(avg_score, 1)
        success_rate = int((passed / total * 100)) if total > 0 else 0
        
        user_stats.append({
            'id': user_id,
            'username': username,
            'total_submissions': total,
            'passed': passed,
            'avg_score': avg_score,
            'success_rate': success_rate
        })
    
    conn.close()
    
    return render_template("admin_user_reports.html", users=user_stats)

@app.route("/admin/user_reports/<int:user_id>")
def admin_user_detail(user_id):
    if not is_logged_in() or not is_admin():
        return redirect("/")
    
    conn = db()
    cur = conn.cursor()
    
    # Get user info
    cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    
    if not user:
        conn.close()
        return "User not found", 404
    
    username = user[0]
    
    # Get user's submissions with question details
    cur.execute("""
        SELECT 
            q.title, 
            s.verdict, 
            s.score,
            s.timestamp,
            s.question_id
        FROM submissions s
        JOIN questions q ON s.question_id = q.id
        WHERE s.user_id = ?
        ORDER BY s.timestamp DESC
    """, (user_id,))
    
    submissions = cur.fetchall()
    
    # Calculate statistics
    total_submissions = len(submissions)
    passed = sum(1 for s in submissions if s[1] == 'PASS')
    success_rate = int((passed / total_submissions * 100)) if total_submissions > 0 else 0
    avg_score = round(sum(s[2] for s in submissions) / total_submissions, 1) if total_submissions > 0 else 0
    
    # Get all questions to show completion status
    cur.execute("SELECT id, title FROM questions ORDER BY id")
    all_questions = cur.fetchall()
    
    # Get which questions user has attempted
    cur.execute("SELECT DISTINCT question_id FROM submissions WHERE user_id = ?", (user_id,))
    attempted_questions = [row[0] for row in cur.fetchall()]
    
    question_status = []
    for qid, title in all_questions:
        status = "Attempted" if qid in attempted_questions else "Not Attempted"
        question_status.append({
            'id': qid,
            'title': title,
            'status': status
        })
    
    conn.close()
    
    return render_template(
        "admin_user_detail.html",
        user_id=user_id,
        username=username,
        submissions=submissions,
        total_submissions=total_submissions,
        passed=passed,
        success_rate=success_rate,
        avg_score=avg_score,
        question_status=question_status
    )

@app.route("/admin/reports")
def admin_reports():
    if not is_logged_in() or not is_admin():
        return redirect("/")
    
    conn = db()
    cur = conn.cursor()
    
    # Get submission statistics - FIXED: using correct table structure
    cur.execute("""
        SELECT 
            u.username, 
            q.title, 
            COALESCE(s.verdict, 'NO SUBMISSION') as verdict,
            COALESCE(s.score, 0) as score,
            COALESCE(s.timestamp, 'N/A') as timestamp
        FROM users u
        CROSS JOIN questions q
        LEFT JOIN submissions s ON s.user_id = u.id AND s.question_id = q.id
        ORDER BY s.timestamp DESC, u.username, q.title
        LIMIT 100
    """)
    submissions = cur.fetchall()
    
    # Get unique users and questions for filters
    cur.execute("SELECT DISTINCT username FROM users ORDER BY username")
    unique_users = [row[0] for row in cur.fetchall()]
    
    cur.execute("SELECT DISTINCT title FROM questions ORDER BY title")
    unique_questions = [row[0] for row in cur.fetchall()]
    
    # Calculate statistics
    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0]
    
    # Calculate success rate (only for actual submissions)
    cur.execute("SELECT COUNT(*) FROM submissions WHERE verdict = 'PASS'")
    passed = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM submissions")
    total_subs = cur.fetchone()[0]
    success_rate = int((passed / total_subs * 100)) if total_subs > 0 else 0
    
    # Calculate average score
    cur.execute("SELECT AVG(score) FROM submissions WHERE score IS NOT NULL")
    avg_score_result = cur.fetchone()[0]
    avg_score = round(avg_score_result, 1) if avg_score_result else 0
    
    conn.close()
    
    return render_template(
        "admin_reports.html",
        submissions=submissions,
        unique_users=unique_users,
        unique_questions=unique_questions,
        total_users=total_users,
        success_rate=success_rate,
        avg_score=avg_score
    )

@app.route("/report")
def report():
    if not is_logged_in():
        return redirect("/login")
    
    conn = db()
    cur = conn.cursor()
    
    # Get user's submission summary
    cur.execute("""
        SELECT q.title, 
               CASE 
                   WHEN s.verdict IS NULL THEN 'NO ATTEMPT'
                   ELSE s.verdict 
               END as verdict,
               COALESCE(s.score, 0) as score
        FROM questions q
        LEFT JOIN submissions s ON s.question_id = q.id AND s.user_id = ?
        ORDER BY q.id
    """, (session["user_id"],))
    
    rows = cur.fetchall()
    total = sum(r[2] for r in rows if r[2] and r[1] != 'NO ATTEMPT') if rows else 0
    
    conn.close()
    
    return render_template("report.html", rows=rows, total=total)

# ... (all your existing code remains the same until the end) ...

if __name__ == "__main__":
    # Get port from environment variable or use 5000
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
