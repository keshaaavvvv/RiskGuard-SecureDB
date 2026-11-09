import os, json, re
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from analyzer import analyze_sql

load_dotenv()
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "change-this-before-deployment")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///riskguard.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="student")
    student_id = db.Column(db.Integer, db.ForeignKey("student.id"), nullable=True)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reg_no = db.Column(db.String(40), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    department = db.Column(db.String(120), nullable=False)
    year = db.Column(db.String(20), default="3")
    section = db.Column(db.String(20), default="A")
    email = db.Column(db.String(255), unique=True, nullable=False)
    attendance = db.Column(db.Integer, default=0)
    risks = db.relationship("RiskAssessment", backref="student", cascade="all, delete-orphan")

class RiskAssessment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("student.id"), nullable=False)
    title = db.Column(db.String(180), nullable=False)
    category = db.Column(db.String(80), nullable=False, default="Cyber Security")
    description = db.Column(db.Text, default="")
    probability = db.Column(db.Integer, nullable=False)
    impact = db.Column(db.Integer, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(30), default="Open")
    owner = db.Column(db.String(120), default="")
    mitigation = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    query_text = db.Column(db.Text, nullable=False)
    findings_json = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User")

def severity_for(score):
    if score < 5: return "Low"
    if score <= 9: return "Medium"
    if score <= 16: return "High"
    return "Critical"

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapped(*args, **kwargs):
        user = db.session.get(User, session["user_id"])
        if not user or user.role != "admin":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))
        return fn(*args, **kwargs)
    return wrapped

@app.context_processor
def inject_user():
    user = db.session.get(User, session.get("user_id")) if session.get("user_id") else None
    return {"current_user": user}

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not email or len(password) < 10:
            flash("Enter all fields. Password must be at least 10 characters.", "danger")
            return render_template("register.html")
        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "danger")
            return render_template("register.html")
        # Public registration can only create student accounts.
        student = Student.query.filter_by(email=email).first()
        user = User(email=email, password_hash=generate_password_hash(password), role="student",
                    student_id=student.id if student else None)
        db.session.add(user); db.session.commit()
        flash("Account created. If your student profile exists, it has been linked; otherwise ask an administrator to link it.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, request.form.get("password", "")):
            session.clear()
            session["user_id"] = user.id
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = db.session.get(User, session["user_id"])
    if user.role == "admin":
        students = Student.query.count()
        risks = RiskAssessment.query.all()
        return render_template("dashboard.html", user=user, students=students, risks=risks,
                               total=len(risks), open_count=sum(r.status == "Open" for r in risks),
                               high_count=sum(r.severity == "High" for r in risks),
                               critical_count=sum(r.severity == "Critical" for r in risks))
    student = db.session.get(Student, user.student_id) if user.student_id else None
    risks = student.risks if student else []
    return render_template("dashboard.html", user=user, student=student, risks=risks,
                           students=1 if student else 0, total=len(risks),
                           open_count=sum(r.status == "Open" for r in risks),
                           high_count=sum(r.severity == "High" for r in risks),
                           critical_count=sum(r.severity == "Critical" for r in risks))

@app.route("/students")
@admin_required
def students():
    q = request.args.get("q", "").strip()
    query = Student.query
    if q:
        like = f"%{q}%"
        query = query.filter(db.or_(Student.name.ilike(like), Student.reg_no.ilike(like),
                                    Student.department.ilike(like), Student.email.ilike(like)))
    return render_template("students.html", students=query.order_by(Student.name).all(), q=q)

@app.route("/students/new", methods=["GET", "POST"])
@admin_required
def new_student():
    if request.method == "POST":
        try:
            attendance = int(request.form.get("attendance", 0))
            if not 0 <= attendance <= 100: raise ValueError()
            student = Student(reg_no=request.form["reg_no"].strip(), name=request.form["name"].strip(),
                              department=request.form["department"].strip(), year=request.form.get("year","3"),
                              section=request.form.get("section","A"), email=request.form["email"].strip().lower(),
                              attendance=attendance)
            db.session.add(student); db.session.commit()
            flash("Student profile created.", "success")
            return redirect(url_for("students"))
        except (KeyError, ValueError):
            db.session.rollback()
            flash("Check the fields. Attendance must be 0–100 and registration number/email must be unique.", "danger")
        except Exception:
            db.session.rollback()
            flash("Could not save profile. Check for duplicate registration number or email.", "danger")
    return render_template("student_form.html")

@app.route("/students/<int:sid>/link", methods=["POST"])
@admin_required
def link_student(sid):
    student = db.get_or_404(Student, sid)
    email = request.form.get("email", "").strip().lower()
    user = User.query.filter_by(email=email, role="student").first()
    if not user:
        flash("No student account found for that email.", "danger")
    elif User.query.filter_by(student_id=sid).first():
        flash("Another account is already linked to this student profile.", "danger")
    else:
        user.student_id = student.id
        db.session.commit()
        flash("Student account linked.", "success")
    return redirect(url_for("students"))

@app.route("/risks/new", methods=["GET", "POST"])
@admin_required
def new_risk():
    students_list = Student.query.order_by(Student.name).all()
    if request.method == "POST":
        try:
            p, i = int(request.form["probability"]), int(request.form["impact"])
            if not (1 <= p <= 5 and 1 <= i <= 5): raise ValueError()
            score = p * i
            risk = RiskAssessment(student_id=int(request.form["student_id"]),
                title=request.form["title"].strip(), category=request.form.get("category","Cyber Security"),
                description=request.form.get("description","").strip(), probability=p, impact=i,
                score=score, severity=severity_for(score), status=request.form.get("status","Open"),
                owner=request.form.get("owner","").strip(), mitigation=request.form.get("mitigation","").strip())
            db.session.add(risk); db.session.commit()
            flash(f"Assessment saved with score {score} ({risk.severity}).", "success")
            return redirect(url_for("dashboard"))
        except Exception:
            db.session.rollback()
            flash("Unable to save. Ensure a student is selected and probability/impact are 1–5.", "danger")
    return render_template("risk_form.html", students=students_list)

@app.route("/scanner", methods=["GET", "POST"])
@login_required
def scanner():
    result = None
    query_text = ""
    if request.method == "POST":
        query_text = request.form.get("query_text", "")[:12000]
        if not query_text.strip():
            flash("Paste a SQL query or application query-construction snippet.", "warning")
        else:
            result = analyze_sql(query_text)
            scan = Scan(user_id=session["user_id"], query_text=query_text,
                        findings_json=json.dumps(result))
            db.session.add(scan); db.session.commit()
    return render_template("scanner.html", result=result, query_text=query_text)

@app.route("/history")
@login_required
def history():
    user = db.session.get(User, session["user_id"])
    scans = Scan.query.filter_by(user_id=user.id).order_by(Scan.created_at.desc()).limit(50).all()
    return render_template("history.html", scans=scans)

@app.route("/api/scan", methods=["POST"])
@login_required
def api_scan():
    payload = request.get_json(silent=True) or {}
    query_text = str(payload.get("query", ""))[:12000]
    if not query_text.strip():
        return jsonify({"error":"query is required"}), 400
    return jsonify(analyze_sql(query_text))

def seed():
    db.create_all()
    # Seed demo data only when the database has no students.
    if Student.query.count() == 0:
        s1 = Student(reg_no="RG-2026-001", name="Asha Kumar", department="Computer Science",
                     year="3", section="A", email="asha.demo@example.test", attendance=86)
        s2 = Student(reg_no="RG-2026-002", name="Dev Shah", department="Information Technology",
                     year="2", section="B", email="dev.demo@example.test", attendance=72)
        db.session.add_all([s1, s2]); db.session.commit()
        db.session.add_all([
            RiskAssessment(student_id=s1.id, title="Unsafe SQL query construction", category="Cyber Security",
                description="A code review identified possible query concatenation.", probability=3, impact=4,
                score=12, severity="High", status="Open", owner="Security Team",
                mitigation="Use parameterized queries, least-privilege DB credentials, and regression tests."),
            RiskAssessment(student_id=s2.id, title="Student data exposure", category="Privacy",
                description="Broad data retrieval could expose more records than required.", probability=2, impact=4,
                score=8, severity="Medium", status="In Progress", owner="Application Team",
                mitigation="Limit selected columns and enforce authorization at the data-access layer.")
        ]); db.session.commit()

with app.app_context():
    seed()
    # Bootstrap admin only when explicitly configured; never ship a known default password.
    admin_email, admin_password = os.getenv("ADMIN_EMAIL"), os.getenv("ADMIN_PASSWORD")
    if admin_email and admin_password and not User.query.filter_by(email=admin_email.lower()).first():
        db.session.add(User(email=admin_email.lower(), password_hash=generate_password_hash(admin_password), role="admin"))
        db.session.commit()

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
