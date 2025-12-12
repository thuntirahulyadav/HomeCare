from datetime import datetime
import random
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory, session
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///hcare.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "your-secret-key-change-in-production"  # For session encryption

db = SQLAlchemy(app)
BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR


# Patients table
class Patient(db.Model):
    __tablename__ = "patients"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(256), nullable=False, default=generate_password_hash("pass123"))
    age = db.Column(db.Integer)  # Patient age
    role = db.Column(db.String(32), nullable=False, default="patient")
    preferred_date = db.Column(db.String(32))  # e.g., "2024-05-20"
    preferred_time = db.Column(db.String(32))  # e.g., "10:00 AM - 12:00 PM"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# Doctors table
class Doctor(db.Model):
    __tablename__ = "doctors"
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    specialization = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(32), nullable=False, default="doctor")
    password = db.Column(db.String(256), nullable=False, default=generate_password_hash("pass123"))
    code = db.Column(db.String(64))  # e.g., doctor code or badge ID
    status = db.Column(db.String(32), nullable=False, default="active", index=True)  # active/inactive
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# Requests table (appointment requests)
class Request(db.Model):
    __tablename__ = "requests"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=True, index=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey("doctors.id"), nullable=False, index=True)
    patient_name = db.Column(db.String(120), nullable=False)
    patient_age = db.Column(db.Integer, nullable=False)
    patient_address = db.Column(db.String(255))
    problem = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(32), nullable=False, default="pending")  # pending/assigned/completed
    preferred_date = db.Column(db.String(32), nullable=False)
    preferred_time = db.Column(db.String(32), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    patient = db.relationship("Patient", backref="requests")
    doctor = db.relationship("Doctor", backref="requests")


# History table (completed appointments)
class History(db.Model):
    __tablename__ = "history"
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey("requests.id"), nullable=False, index=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey("doctors.id"), nullable=False, index=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False, index=True)
    notes = db.Column(db.Text)
    status = db.Column(db.String(32), nullable=False, default="completed")
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)

    request = db.relationship("Request", backref="history_entry", uselist=False)
    doctor = db.relationship("Doctor")
    patient = db.relationship("Patient")


# Notifications table
class Notification(db.Model):
    __tablename__ = "notifications"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    message = db.Column(db.Text, nullable=False)
    notif_type = db.Column(db.String(64), default="info")  # info/warning/success
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)





@app.route("/auth/login", methods=["POST"])
def auth_login():
    """Basic email/password check against patients and doctors tables. Creates a session."""
    data = request.get_json(force=True)
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    user = Patient.query.filter_by(email=email).first()
    source = "patient"
    if user and not check_password_hash(user.password, password):
        user = None
    if not user:
        user = Doctor.query.filter_by(email=email).first()
        source = "doctor"
        if user and not check_password_hash(user.password, password):
            user = None

    if not user:
        return jsonify({"error": "invalid credentials"}), 401

    role = getattr(user, "role", "patient")
    user_id = getattr(user, "user_id", getattr(user, "doctor_id", None))
    
    # Create session to track user
    session["user_id"] = user_id
    session["email"] = email
    session["role"] = role
    session["source"] = source
    session["name"] = user.name
    
    return jsonify(
        {
            "status": "ok",
            "role": role,
            "source": source,
            "name": user.name,
            "id": user_id,
        }
    )


@app.route("/auth/register", methods=["POST"])
def auth_register():
    """Register a patient (default role patient). Reject if email exists in patients or doctors."""
    data = request.get_json(force=True)
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    age = data.get("age")

    if not name or not email or not password:
        return jsonify({"error": "name, email, password are required"}), 400

    # uniqueness across patients and doctors
    if Patient.query.filter_by(email=email).first() or Doctor.query.filter_by(email=email).first():
        return jsonify({"error": "email already exists"}), 409

    new_patient = Patient(
        user_id=f"P{int(datetime.utcnow().timestamp())}",
        name=name,
        email=email,
        password=generate_password_hash(password),
        age=int(age) if age else None,
        role="patient",
    )
    db.session.add(new_patient)
    db.session.commit()
    return jsonify({"status": "ok", "message": "registered", "name": name, "email": email}), 201


@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    """Logout user by clearing session."""
    session.clear()
    return jsonify({"status": "ok", "message": "logged out"}), 200


@app.route("/auth/session", methods=["GET"])
def check_session():
    """Check if user is logged in and return session info."""
    if "user_id" in session:
        return jsonify({
            "logged_in": True,
            "user_id": session.get("user_id"),
            "email": session.get("email"),
            "name": session.get("name"),
            "role": session.get("role"),
            "source": session.get("source")
        }), 200
    return jsonify({"logged_in": False}), 401


@app.route("/patient/profile/<user_id>", methods=["GET"])
def get_patient_profile(user_id):
    """Get patient profile data."""
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    patient = Patient.query.filter_by(user_id=user_id).first()
    if not patient:
        return jsonify({"error": "Patient not found"}), 404
    
    return jsonify({
        "id": patient.id,
        "name": patient.name,
        "email": patient.email,
        "age": patient.age,
        "role": patient.role
    }), 200


def seed_database():
    """Seed the database with sample patients, doctors, and admin."""
    # Check if data already exists
    if Patient.query.first() is not None:
        print("✓ Database already seeded. Skipping...")
        return

    # Sample Patients
    sample_patients = [
        Patient(
            user_id="P001",
            name="John Doe",
            email="john.doe@example.com",
            password=generate_password_hash("pass123"),
            role="patient",
            preferred_date="2025-01-15",
            preferred_time="10:00 AM - 12:00 PM",
        ),
        Patient(
            user_id="P002",
            name="Sarah Wilson",
            email="sarah.wilson@example.com",
            password=generate_password_hash("pass123"),
            role="patient",
            preferred_date="2025-01-16",
            preferred_time="02:00 PM - 04:00 PM",
        ),
        Patient(
            user_id="P003",
            name="Michael Chen",
            email="michael.chen@example.com",
            password=generate_password_hash("pass123"),
            role="patient",
            preferred_date="2025-01-17",
            preferred_time="05:00 PM - 07:00 PM",
        ),
        Patient(
            user_id="P004",
            name="Emma Thompson",
            email="emma.thompson@example.com",
            password=generate_password_hash("pass123"),
            role="patient",
            preferred_date="2025-01-18",
            preferred_time="10:00 AM - 12:00 PM",
        ),
    ]

    # Sample Doctors
    sample_doctors = [
        Doctor(
            doctor_id="D001",
            name="Dr. John Smith",
            email="dr.john.smith@hospital.com",
            specialization="Physiotherapist",
            role="doctor",
            password=generate_password_hash("pass123"),
            code=str(random.randint(1000, 9999)),
            status="active",
        ),
        Doctor(
            doctor_id="D002",
            name="Dr. Sarah Lee",
            email="dr.sarah.lee@hospital.com",
            specialization="Physiotherapist",
            role="doctor",
            password=generate_password_hash("pass123"),
            code=str(random.randint(1000, 9999)),
            status="active",
        ),
        Doctor(
            doctor_id="D003",
            name="Dr. Michael Williams",
            email="dr.michael.williams@hospital.com",
            specialization="Physiotherapist",
            role="doctor",
            password=generate_password_hash("pass123"),
            code=str(random.randint(1000, 9999)),
            status="active",
        ),
        Doctor(
            doctor_id="D004",
            name="Dr. Emily Brown",
            email="dr.emily.brown@hospital.com",
            specialization="Physiotherapist",
            role="doctor",
            password=generate_password_hash("pass123"),
            code=str(random.randint(1000, 9999)),
            status="active",
        ),
    ]

    # Sample Admin
    admin = Doctor(
        doctor_id="ADMIN001",
        name="Admin Manager",
        email="admin@hospital.com",
        specialization="Administration",
        role="admin",
        password=generate_password_hash("pass123"),
        code=str(random.randint(1000, 9999)),
        status="active",
    )

    # Add all to session and commit
    for patient in sample_patients:
        db.session.add(patient)
    for doctor in sample_doctors:
        db.session.add(doctor)
    db.session.add(admin)

    db.session.commit()
    print("✓ Database seeded with 4 patients, 4 doctors, and 1 admin")


@app.route("/doctors/add", methods=["POST"])
def add_doctor():
    """Add a new doctor to the database with auto-generated ID and code."""
    data = request.get_json(force=True)
    name = data.get("name")
    email = data.get("email")
    specialization = data.get("specialization", "Physiotherapist")
    status = data.get("status", "active")
    password = data.get("password", "pass123")

    if not all([name, email]):
        return jsonify({"error": "Name and email are required"}), 400

    # Check if email already exists
    if Doctor.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 409

    # Auto-generate doctor_id (next sequential ID)
    last_doctor = Doctor.query.order_by(Doctor.id.desc()).first()
    next_id = (last_doctor.id + 1) if last_doctor else 1
    doctor_id = f"D{next_id:03d}"

    # Auto-generate 4-digit random code
    code = str(random.randint(1000, 9999))

    new_doctor = Doctor(
        doctor_id=doctor_id,
        code=code,
        name=name,
        email=email,
        specialization=specialization,
        status=status,
        role="doctor",
        password=generate_password_hash(password),
    )
    db.session.add(new_doctor)
    db.session.commit()
    return jsonify({"status": "ok", "message": "Doctor added successfully", "doctor_id": doctor_id, "code": code, "name": name}), 201


@app.route("/doctors", methods=["GET"])
def list_doctors():
    """List doctors. Optional query param `active=true` to filter active doctors."""
    active = request.args.get("active")
    include_admin = request.args.get("include_admin")
    query = Doctor.query
    # By default do not return admin users (admin role is internal)
    if not (include_admin and include_admin.lower() in ("1", "true", "yes")):
        query = query.filter(Doctor.role != "admin")
    if active and active.lower() in ("1", "true", "yes"):
        query = query.filter_by(status="active")
    doctors = query.order_by(Doctor.name).all()
    result = []
    for d in doctors:
        result.append(
            {
                "id": d.id,
                "doctor_id": d.doctor_id,
                "name": d.name,
                "email": d.email,
                "specialization": d.specialization,
                "code": d.code,
                "status": d.status,
            }
        )
    return jsonify(result)


@app.route("/appointments", methods=["POST"])
def create_appointment():
    """Submit a new appointment request. Gets patient_id from session, doctor_id from doctor selection."""
    # Check if user is logged in
    if "user_id" not in session:
        return jsonify({"error": "User must be logged in to create an appointment"}), 401
    
    data = request.get_json(force=True)
    patient_name = data.get("patient_name", "").strip()
    patient_age = data.get("patient_age")
    patient_address = data.get("patient_address", "").strip()
    problem = data.get("problem", "").strip()
    preferred_date = data.get("preferred_date", "").strip()
    preferred_time = data.get("preferred_time", "").strip()
    doctor_id = data.get("doctor_id")

    # Validate required fields
    if not patient_name or not patient_age or not problem or not preferred_date or not preferred_time or not doctor_id:
        missing = []
        if not patient_name:
            missing.append("patient_name")
        if not patient_age:
            missing.append("patient_age")
        if not problem:
            missing.append("problem")
        if not preferred_date:
            missing.append("preferred_date")
        if not preferred_time:
            missing.append("preferred_time")
        if not doctor_id:
            missing.append("doctor_id")
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    try:
        patient_age = int(patient_age)
        doctor_id = int(doctor_id)
    except (ValueError, TypeError):
        return jsonify({"error": "patient_age and doctor_id must be numbers"}), 400

    # Get patient ID from session
    user_id = session.get("user_id")
    patient = Patient.query.filter_by(user_id=user_id).first()
    patient_id = patient.id if patient else None

    # Verify doctor exists
    doctor = Doctor.query.filter_by(id=doctor_id).first()
    if not doctor:
        return jsonify({"error": f"Doctor with ID {doctor_id} not found"}), 404

    try:
        new_request = Request(
            patient_name=patient_name,
            patient_age=patient_age,
            patient_address=patient_address,
            problem=problem,
            preferred_date=preferred_date,
            preferred_time=preferred_time,
            status="pending",
            patient_id=patient_id,
            doctor_id=doctor_id,
        )
        db.session.add(new_request)
        db.session.commit()
        return jsonify({"status": "ok", "message": "Appointment request submitted successfully", "request_id": new_request.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500


@app.route("/appointments", methods=["GET"])
def list_appointments():
    """List all appointment requests."""
    requests_list = Request.query.order_by(Request.created_at.desc()).all()
    result = []
    for req in requests_list:
        result.append(
            {
                "id": req.id,
                "patient_name": req.patient_name,
                "patient_age": req.patient_age,
                "patient_address": req.patient_address,
                "problem": req.problem,
                "status": req.status,
                "doctor_name": req.doctor.name if req.doctor else "Unassigned",
                "preferred_date": req.preferred_date,
                "preferred_time": req.preferred_time,
                "created_at": req.created_at.strftime("%b %d, %Y") if req.created_at else "",
            }
        )
    return jsonify(result)


@app.route("/patient/statistics", methods=["GET"])
def get_patient_statistics():
    """Get appointment statistics for logged-in patient."""
    if "user_id" not in session:
        return jsonify({"error": "User not logged in"}), 401
    
    user_id = session.get("user_id")
    patient = Patient.query.filter_by(user_id=user_id).first()
    
    if not patient:
        return jsonify({"error": "Patient not found"}), 404
    
    # Get all requests for this patient
    all_requests = Request.query.filter_by(patient_id=patient.id).all()
    pending_requests = Request.query.filter_by(patient_id=patient.id, status="pending").all()
    completed_requests = Request.query.filter_by(patient_id=patient.id, status="completed").all()
    
    return jsonify({
        "total_requests": len(all_requests),
        "pending_count": len(pending_requests),
        "completed_count": len(completed_requests)
    })


@app.route("/patient/appointments", methods=["GET"])
def get_patient_appointments():
    """Get appointments for logged-in patient."""
    if "user_id" not in session:
        return jsonify({"error": "User not logged in"}), 401
    
    user_id = session.get("user_id")
    patient = Patient.query.filter_by(user_id=user_id).first()
    
    if not patient:
        return jsonify({"error": "Patient not found"}), 404
    
    appointments = Request.query.filter_by(patient_id=patient.id).order_by(Request.created_at.desc()).all()
    result = []
    for apt in appointments:
        result.append({
            "id": apt.id,
            "patient_name": apt.patient_name,
            "problem": apt.problem,
            "doctor_name": apt.doctor.name if apt.doctor else "Unassigned",
            "preferred_date": apt.preferred_date,
            "preferred_time": apt.preferred_time,
            "status": apt.status,
            "created_at": apt.created_at.strftime("%b %d, %Y") if apt.created_at else "",
        })
    return jsonify(result)


@app.route("/patient/history", methods=["GET"])
def get_patient_history():
    """Get completed appointments history for logged-in patient."""
    if "user_id" not in session:
        return jsonify({"error": "User not logged in"}), 401
    
    user_id = session.get("user_id")
    patient = Patient.query.filter_by(user_id=user_id).first()
    
    if not patient:
        return jsonify({"error": "Patient not found"}), 404
    
    # Get completed appointments from Request table
    completed_appointments = Request.query.filter_by(
        patient_id=patient.id,
        status="completed"
    ).order_by(Request.created_at.desc()).all()
    
    print(f"DEBUG: Patient ID: {patient.id}, Found {len(completed_appointments)} completed appointments")
    
    result = []
    for apt in completed_appointments:
        result.append({
            "id": apt.id,
            "doctor_name": apt.doctor.name if apt.doctor else "Unknown",
            "problem": apt.problem,
            "status": apt.status,
            "completed_at": apt.created_at.strftime("%b %d, %Y") if apt.created_at else "",
        })
    return jsonify(result)


# Serve frontend files
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    """
    Serve static frontend files so hitting http://127.0.0.1:5000 shows index.html.
    """
    target = (FRONTEND_DIR / path).resolve()
    # Prevent path traversal
    if not str(target).startswith(str(FRONTEND_DIR)):
        return "Not Found", 404

    if path and target.exists() and target.is_file():
        return send_from_directory(FRONTEND_DIR, path)
    return send_from_directory(FRONTEND_DIR, "index.html")


if __name__ == "__main__":
    with app.app_context():
        db.drop_all()  # Drop existing tables to start fresh
        db.create_all()
        print("✓ Database tables created")
        seed_database()
    app.run(debug=True)

