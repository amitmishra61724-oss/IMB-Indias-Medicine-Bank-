import os
import sqlite3
from datetime import datetime, timedelta
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, g)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from database import get_db, init_db, is_expiring_soon, is_expired
import json
import uuid
import random

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "imb-india-medicine-bank-flask-2024")
app.config["UPLOAD_FOLDER"] = os.path.join("static", "uploads", "medicines")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
LOCATION_ALIASES = {
    "mum": "mumbai",
    "mumbai": "mumbai",
    "bby": "mumbai",
    "bom": "mumbai",
    "del": "delhi",
    "delhi": "delhi",
    "nd": "new delhi",
    "new delhi": "new delhi",
    "blr": "bengaluru",
    "bangalore": "bengaluru",
    "bengaluru": "bengaluru",
    "hyd": "hyderabad",
    "hyderabad": "hyderabad",
    "pune": "pune",
    "pnq": "pune",
    "chn": "chennai",
    "madras": "chennai",
    "chennai": "chennai",
    "kol": "kolkata",
    "calcutta": "kolkata",
    "kolkata": "kolkata",
}


def allowed_image(filename):
    if not filename or "." not in filename:
        return False
    return filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def parse_positive_int(value):
    try:
        number = int(value)
        return number if number > 0 else None
    except (TypeError, ValueError):
        return None


def create_and_send_otp(user_id, purpose):
    otp = f"{random.randint(100000, 999999)}"
    expires_at = (datetime.now() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    db = get_db()
    db.execute("UPDATE otps SET is_used=1 WHERE user_id=? AND purpose=? AND is_used=0", (user_id, purpose))
    db.execute(
        "INSERT INTO otps (user_id, purpose, otp_code, expires_at) VALUES (?,?,?,?)",
        (user_id, purpose, otp, expires_at)
    )
    db.commit()
    db.close()
    # Demo-mode delivery (replace with SMS/Email API in production)
    flash(f"Your OTP is {otp}. It is valid for 5 minutes.", "info")


def complete_authentication(user):
    session["user_id"] = user["id"]
    session["role"] = user["role"]
    session["name"] = user["name"]
    session.pop("pending_user_id", None)
    session.pop("pending_purpose", None)


def normalize_location(text):
    value = (text or "").strip().lower()
    if not value:
        return ""
    return LOCATION_ALIASES.get(value, value)


def location_matches(query, city, pickup_location):
    q = normalize_location(query)
    city_text = (city or "").lower()
    pickup_text = (pickup_location or "").lower()
    if not q:
        return True
    if q in city_text or q in pickup_text:
        return True
    for alias, canonical in LOCATION_ALIASES.items():
        if q == alias and canonical in city_text:
            return True
    return False


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login to continue.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                flash("Please login to continue.", "warning")
                return redirect(url_for("login"))
            if session.get("role") not in roles:
                flash("Access denied.", "danger")
                return redirect(url_for("home"))
            return f(*args, **kwargs)
        return decorated
    return decorator


def get_current_user():
    if "user_id" not in session:
        return None
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    db.close()
    return user


@app.context_processor
def inject_user():
    return {"current_user": get_current_user()}


# ─── AUTH ────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    db = get_db()
    total_donors = db.execute("SELECT COUNT(*) FROM users WHERE role='donor'").fetchone()[0]
    total_medicines = db.execute("SELECT COUNT(*) FROM medicines").fetchone()[0]
    total_fulfilled = db.execute("SELECT COUNT(*) FROM requests WHERE status='fulfilled'").fetchone()[0]
    recent = db.execute("""
        SELECT m.*, u.name as donor_name FROM medicines m
        JOIN users u ON m.donor_id = u.id
        WHERE m.status='available' ORDER BY m.created_at DESC LIMIT 4
    """).fetchall()
    db.close()
    return render_template("home.html",
                           total_donors=total_donors,
                           total_medicines=total_medicines,
                           total_fulfilled=total_fulfilled,
                           recent=recent)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "imb"}), 200


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "receiver")
        phone = request.form.get("phone", "").strip()
        city = request.form.get("city", "").strip()
        address = request.form.get("address", "").strip()

        if not all([name, email, password, city]):
            flash("Please fill all required fields.", "danger")
            return render_template("register.html")
        if role not in ["donor", "receiver"]:
            flash("Invalid role.", "danger")
            return render_template("register.html")
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template("register.html")

        db = get_db()
        existing = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            db.close()
            flash("Email already registered.", "danger")
            return render_template("register.html")

        pw_hash = generate_password_hash(password)
        cur = db.execute(
            "INSERT INTO users (name, email, password_hash, role, phone, city, address) VALUES (?,?,?,?,?,?,?)",
            (name, email, pw_hash, role, phone or None, city, address or None)
        )
        db.commit()
        user_id = cur.lastrowid
        db.close()

        session["pending_user_id"] = user_id
        session["pending_purpose"] = "register"
        create_and_send_otp(user_id, "register")
        flash("Account created. Verify OTP to continue.", "success")
        return redirect(url_for("verify_otp"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        db.close()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid email or password.", "danger")
            return render_template("login.html")

        session["pending_user_id"] = user["id"]
        session["pending_purpose"] = "login"
        create_and_send_otp(user["id"], "login")
        flash("OTP sent. Please verify to login.", "success")
        return redirect(url_for("verify_otp"))

    return render_template("login.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    pending_user_id = session.get("pending_user_id")
    purpose = session.get("pending_purpose")
    if not pending_user_id or not purpose:
        flash("No OTP verification pending. Please login/register first.", "warning")
        return redirect(url_for("login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (pending_user_id,)).fetchone()
    if not user:
        db.close()
        session.pop("pending_user_id", None)
        session.pop("pending_purpose", None)
        flash("User not found.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        otp_input = request.form.get("otp", "").strip()
        otp_row = db.execute(
            """SELECT * FROM otps
               WHERE user_id=? AND purpose=? AND is_used=0
               ORDER BY created_at DESC LIMIT 1""",
            (pending_user_id, purpose)
        ).fetchone()
        if not otp_row:
            db.close()
            flash("OTP not found. Please resend OTP.", "danger")
            return render_template("verify_otp.html", user=user, purpose=purpose)

        now = datetime.now()
        expires = datetime.strptime(otp_row["expires_at"], "%Y-%m-%d %H:%M:%S")
        if now > expires:
            db.close()
            flash("OTP expired. Please resend OTP.", "danger")
            return render_template("verify_otp.html", user=user, purpose=purpose)

        if otp_input != otp_row["otp_code"]:
            db.close()
            flash("Invalid OTP. Please try again.", "danger")
            return render_template("verify_otp.html", user=user, purpose=purpose)

        db.execute("UPDATE otps SET is_used=1 WHERE id=?", (otp_row["id"],))
        db.commit()
        db.close()
        complete_authentication(user)
        flash(f"Welcome, {user['name']}! OTP verified successfully.", "success")
        if user["role"] == "admin":
            return redirect(url_for("admin_users"))
        if user["role"] == "donor":
            return redirect(url_for("donate"))
        return redirect(url_for("search"))

    db.close()
    return render_template("verify_otp.html", user=user, purpose=purpose)


@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    pending_user_id = session.get("pending_user_id")
    purpose = session.get("pending_purpose")
    if not pending_user_id or not purpose:
        flash("No OTP session found. Please login/register again.", "warning")
        return redirect(url_for("login"))
    create_and_send_otp(pending_user_id, purpose)
    flash("A new OTP has been sent.", "info")
    return redirect(url_for("verify_otp"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


# ─── MEDICINES ────────────────────────────────────────────────────────────────

@app.route("/search")
def search():
    query = request.args.get("q", "").strip()
    city = request.args.get("city", "").strip()
    db = get_db()

    sql = """
        SELECT m.*, u.name as donor_name, u.phone as donor_phone, u.city as donor_city
        FROM medicines m JOIN users u ON m.donor_id = u.id
        WHERE m.status='available'
    """
    params = []
    if query:
        sql += " AND (m.name LIKE ? OR m.generic_name LIKE ?)"
        params += [f"%{query}%", f"%{query}%"]
    sql += " ORDER BY m.created_at DESC"

    medicines = db.execute(sql, params).fetchall()
    if city:
        medicines = [m for m in medicines if location_matches(city, m["city"], m["pickup_location"])]

    city_rows = db.execute("SELECT DISTINCT city FROM medicines ORDER BY city ASC").fetchall()
    db.close()

    cart_ids = set()
    if "user_id" in session:
        db2 = get_db()
        items = db2.execute("SELECT medicine_id FROM cart WHERE user_id=?", (session["user_id"],)).fetchall()
        db2.close()
        cart_ids = {r["medicine_id"] for r in items}

    return render_template("search.html", medicines=medicines, query=query, city=city,
                           city_suggestions=[r["city"] for r in city_rows],
                           cart_ids=cart_ids, is_expiring_soon=is_expiring_soon)


@app.route("/api/location-suggestions")
def location_suggestions():
    q = normalize_location(request.args.get("q", ""))
    db = get_db()
    cities = [r["city"] for r in db.execute("SELECT DISTINCT city FROM medicines ORDER BY city ASC").fetchall()]
    db.close()
    merged = {c.lower(): c for c in cities}
    for canonical in set(LOCATION_ALIASES.values()):
        merged.setdefault(canonical.lower(), canonical.title())
    all_values = list(merged.values())
    if not q:
        return jsonify({"suggestions": all_values[:8]})
    scored = [city for city in all_values if q in city.lower() or city.lower().startswith(q)]
    return jsonify({"suggestions": scored[:8]})


@app.route("/donate", methods=["GET", "POST"])
@login_required
@role_required("donor")
def donate():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        generic_name = request.form.get("generic_name", "").strip()
        quantity = request.form.get("quantity", "0")
        unit = request.form.get("unit", "").strip()
        expiry_date = request.form.get("expiry_date", "").strip()
        condition = request.form.get("condition", "sealed")
        description = request.form.get("description", "").strip()
        pickup_location = request.form.get("pickup_location", "").strip()
        city = request.form.get("city", "").strip()
        medicine_image = request.files.get("medicine_image")

        qty = parse_positive_int(quantity)
        if not all([name, qty, unit, expiry_date, condition, pickup_location, city]):
            flash("Please fill all required fields.", "danger")
            return render_template("donate.html")
        if len(city) < 2 or len(pickup_location) < 8:
            flash("Please enter proper city and full pickup address/location details.", "danger")
            return render_template("donate.html")

        if is_expired(expiry_date):
            flash("Cannot donate expired medicine. Expiry date is in the past.", "danger")
            return render_template("donate.html")

        image_filename = None
        if medicine_image and medicine_image.filename:
            if not allowed_image(medicine_image.filename):
                flash("Invalid image type. Allowed: PNG, JPG, JPEG, WEBP.", "danger")
                return render_template("donate.html")
            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
            safe_name = secure_filename(medicine_image.filename)
            ext = safe_name.rsplit(".", 1)[1].lower()
            image_filename = f"{uuid.uuid4().hex}.{ext}"
            medicine_image.save(os.path.join(app.config["UPLOAD_FOLDER"], image_filename))

        db = get_db()
        db.execute(
            """INSERT INTO medicines (name, generic_name, quantity, unit, expiry_date, condition,
               description, image_filename, pickup_location, city, donor_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (name, generic_name or None, qty, unit, expiry_date,
             condition, description or None, image_filename, pickup_location, city, session["user_id"])
        )
        db.commit()
        db.close()

        warning = ""
        if is_expiring_soon(expiry_date):
            warning = " Note: This medicine expires within 30 days."
        flash(f"Medicine listed successfully!{warning}", "success" if not warning else "warning")
        return redirect(url_for("my_donations"))

    return render_template("donate.html")


@app.route("/my-donations")
@login_required
@role_required("donor")
def my_donations():
    db = get_db()
    medicines = db.execute(
        "SELECT * FROM medicines WHERE donor_id=? ORDER BY created_at DESC",
        (session["user_id"],)
    ).fetchall()
    db.close()
    return render_template("my_donations.html", medicines=medicines, is_expiring_soon=is_expiring_soon)


@app.route("/delete-medicine/<int:med_id>", methods=["POST"])
@login_required
def delete_medicine(med_id):
    db = get_db()
    med = db.execute("SELECT * FROM medicines WHERE id=?", (med_id,)).fetchone()
    if not med:
        db.close()
        flash("Medicine not found.", "danger")
        return redirect(url_for("my_donations"))
    if med["donor_id"] != session["user_id"] and session.get("role") != "admin":
        db.close()
        flash("Access denied.", "danger")
        return redirect(url_for("my_donations"))

    if med["image_filename"]:
        image_path = os.path.join(app.config["UPLOAD_FOLDER"], med["image_filename"])
        if os.path.exists(image_path):
            os.remove(image_path)

    db.execute("DELETE FROM medicines WHERE id=?", (med_id,))
    db.commit()
    db.close()
    flash("Medicine listing removed.", "success")
    if session.get("role") == "admin":
        return redirect(url_for("admin_medicines"))
    return redirect(url_for("my_donations"))


# ─── REQUESTS ─────────────────────────────────────────────────────────────────

@app.route("/request-medicine/<int:med_id>", methods=["POST"])
@login_required
@role_required("receiver")
def request_medicine(med_id):
    is_emergency = 1 if request.form.get("is_emergency") else 0
    notes = request.form.get("notes", "").strip()

    db = get_db()
    med = db.execute("SELECT * FROM medicines WHERE id=?", (med_id,)).fetchone()
    if not med:
        db.close()
        flash("Medicine not found.", "danger")
        return redirect(url_for("search"))

    existing = db.execute(
        """SELECT id FROM requests
           WHERE medicine_id=? AND receiver_id=? AND status IN ('pending','approved','fulfilled')
           ORDER BY created_at DESC LIMIT 1""",
        (med_id, session["user_id"])
    ).fetchone()
    if existing:
        db.close()
        flash("You already requested this medicine.", "info")
        return redirect(url_for("my_requests"))

    if med["status"] != "available":
        db.close()
        flash("Medicine not available.", "danger")
        return redirect(url_for("search"))

    if med["donor_id"] == session["user_id"]:
        db.close()
        flash("You cannot request your own medicine listing.", "warning")
        return redirect(url_for("search"))

    db.execute(
        "INSERT INTO requests (medicine_id, receiver_id, donor_id, is_emergency, notes) VALUES (?,?,?,?,?)",
        (med_id, session["user_id"], med["donor_id"], is_emergency, notes or None)
    )
    db.execute("UPDATE medicines SET status='reserved' WHERE id=?", (med_id,))
    db.commit()
    db.close()

    if is_emergency:
        flash("Emergency request sent! The donor will be notified urgently.", "warning")
    else:
        flash("Request sent to donor successfully!", "success")
    return redirect(url_for("my_requests"))


@app.route("/my-requests")
@login_required
@role_required("receiver")
def my_requests():
    db = get_db()
    reqs = db.execute("""
        SELECT r.*, m.name as medicine_name, m.expiry_date, m.city as medicine_city,
               u.name as donor_name, u.phone as donor_phone
        FROM requests r
        JOIN medicines m ON r.medicine_id = m.id
        JOIN users u ON r.donor_id = u.id
        WHERE r.receiver_id=?
        ORDER BY r.is_emergency DESC, r.created_at DESC
    """, (session["user_id"],)).fetchall()
    db.close()
    return render_template("my_requests.html", requests=reqs)


@app.route("/acknowledge-request/<int:req_id>", methods=["POST"])
@login_required
@role_required("receiver")
def acknowledge_request(req_id):
    ack_message = request.form.get("ack_message", "").strip()
    if not ack_message:
        flash("Please add a short acknowledgement message.", "danger")
        return redirect(url_for("my_requests"))

    db = get_db()
    req = db.execute(
        "SELECT * FROM requests WHERE id=? AND receiver_id=?",
        (req_id, session["user_id"])
    ).fetchone()
    if not req:
        db.close()
        flash("Request not found.", "danger")
        return redirect(url_for("my_requests"))
    if req["status"] != "fulfilled":
        db.close()
        flash("Acknowledgement can only be sent for fulfilled requests.", "warning")
        return redirect(url_for("my_requests"))

    db.execute(
        """UPDATE requests
           SET receiver_acknowledged=1, ack_message=?, acknowledged_at=datetime('now')
           WHERE id=?""",
        (ack_message, req_id)
    )
    db.commit()
    db.close()
    flash("Acknowledgement sent to donor. Thank you!", "success")
    return redirect(url_for("my_requests"))


@app.route("/incoming-requests")
@login_required
@role_required("donor")
def incoming_requests():
    db = get_db()
    reqs = db.execute("""
        SELECT r.*, m.name as medicine_name, m.expiry_date, m.city as medicine_city,
               u.name as receiver_name, u.phone as receiver_phone, u.city as receiver_city
        FROM requests r
        JOIN medicines m ON r.medicine_id = m.id
        JOIN users u ON r.receiver_id = u.id
        WHERE r.donor_id=?
        ORDER BY r.is_emergency DESC, r.created_at DESC
    """, (session["user_id"],)).fetchall()
    db.close()
    return render_template("incoming_requests.html", requests=reqs)


@app.route("/update-request/<int:req_id>", methods=["POST"])
@login_required
def update_request(req_id):
    new_status = request.form.get("status")
    allowed = ["approved", "rejected", "fulfilled"]
    if new_status not in allowed:
        flash("Invalid status.", "danger")
        return redirect(url_for("incoming_requests"))

    db = get_db()
    req = db.execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()
    if not req:
        db.close()
        flash("Request not found.", "danger")
        return redirect(url_for("incoming_requests"))
    if req["donor_id"] != session["user_id"] and session.get("role") != "admin":
        db.close()
        flash("Access denied.", "danger")
        return redirect(url_for("incoming_requests"))

    db.execute("UPDATE requests SET status=? WHERE id=?", (new_status, req_id))
    if new_status == "fulfilled":
        db.execute("UPDATE medicines SET status='donated' WHERE id=?", (req["medicine_id"],))
    elif new_status == "rejected":
        db.execute("UPDATE medicines SET status='available' WHERE id=?", (req["medicine_id"],))
    db.commit()
    db.close()

    flash(f"Request marked as {new_status}.", "success")
    return redirect(url_for("incoming_requests"))


# ─── CART ─────────────────────────────────────────────────────────────────────

@app.route("/cart")
@login_required
@role_required("receiver")
def cart():
    db = get_db()
    items = db.execute("""
        SELECT c.id as cart_id, m.*, u.name as donor_name, u.phone as donor_phone
        FROM cart c
        JOIN medicines m ON c.medicine_id = m.id
        JOIN users u ON m.donor_id = u.id
        WHERE c.user_id=?
    """, (session["user_id"],)).fetchall()
    db.close()
    return render_template("cart.html", items=items, is_expiring_soon=is_expiring_soon)


@app.route("/cart/add/<int:med_id>", methods=["POST"])
@login_required
@role_required("receiver")
def add_to_cart(med_id):
    db = get_db()
    existing = db.execute(
        "SELECT id FROM cart WHERE user_id=? AND medicine_id=?",
        (session["user_id"], med_id)
    ).fetchone()
    if existing:
        db.close()
        flash("Medicine already in cart.", "info")
        return redirect(url_for("search"))
    db.execute("INSERT INTO cart (user_id, medicine_id) VALUES (?,?)", (session["user_id"], med_id))
    db.commit()
    db.close()
    flash("Added to cart!", "success")
    return redirect(url_for("search"))


@app.route("/cart/remove/<int:cart_id>", methods=["POST"])
@login_required
def remove_from_cart(cart_id):
    db = get_db()
    db.execute("DELETE FROM cart WHERE id=? AND user_id=?", (cart_id, session["user_id"]))
    db.commit()
    db.close()
    flash("Removed from cart.", "info")
    return redirect(url_for("cart"))


@app.route("/cart/checkout", methods=["POST"])
@login_required
@role_required("receiver")
def checkout():
    db = get_db()
    items = db.execute("""
        SELECT c.id as cart_id, m.*
        FROM cart c JOIN medicines m ON c.medicine_id = m.id
        WHERE c.user_id=? AND m.status='available'
    """, (session["user_id"],)).fetchall()

    count = 0
    for item in items:
        db.execute(
            "INSERT INTO requests (medicine_id, receiver_id, donor_id) VALUES (?,?,?)",
            (item["id"], session["user_id"], item["donor_id"])
        )
        db.execute("UPDATE medicines SET status='reserved' WHERE id=?", (item["id"],))
        count += 1

    db.execute("DELETE FROM cart WHERE user_id=?", (session["user_id"],))
    db.commit()
    db.close()

    flash(f"Checkout complete! {count} request(s) sent to donors.", "success")
    return redirect(url_for("my_requests"))


# ─── DASHBOARD ────────────────────────────────────────────────────────────────

@app.route("/dashboard")
def dashboard():
    db = get_db()
    stats = {
        "total_donors": db.execute("SELECT COUNT(*) FROM users WHERE role='donor'").fetchone()[0],
        "total_receivers": db.execute("SELECT COUNT(*) FROM users WHERE role='receiver'").fetchone()[0],
        "total_medicines": db.execute("SELECT COUNT(*) FROM medicines").fetchone()[0],
        "total_donated": db.execute("SELECT COUNT(*) FROM medicines WHERE status='donated'").fetchone()[0],
        "total_requests": db.execute("SELECT COUNT(*) FROM requests").fetchone()[0],
        "total_fulfilled": db.execute("SELECT COUNT(*) FROM requests WHERE status='fulfilled'").fetchone()[0],
    }

    top_donated = db.execute("""
        SELECT name, COUNT(*) as cnt FROM medicines
        GROUP BY name ORDER BY cnt DESC LIMIT 6
    """).fetchall()

    top_requested = db.execute("""
        SELECT m.name, COUNT(*) as cnt FROM requests r
        JOIN medicines m ON r.medicine_id = m.id
        GROUP BY m.name ORDER BY cnt DESC LIMIT 6
    """).fetchall()

    cities = db.execute("""
        SELECT city, COUNT(*) as cnt FROM medicines
        GROUP BY city ORDER BY cnt DESC LIMIT 5
    """).fetchall()

    db.close()

    top_donated_json = json.dumps([{"name": r["name"], "count": r["cnt"]} for r in top_donated])
    top_requested_json = json.dumps([{"name": r["name"], "count": r["cnt"]} for r in top_requested])
    cities_json = json.dumps([{"city": r["city"], "count": r["cnt"]} for r in cities])

    return render_template("dashboard.html", stats=stats,
                           top_donated_json=top_donated_json,
                           top_requested_json=top_requested_json,
                           cities_json=cities_json)


# ─── ADMIN ────────────────────────────────────────────────────────────────────

@app.route("/admin/users")
@login_required
@role_required("admin")
def admin_users():
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    db.close()
    return render_template("admin_users.html", users=users)


@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
@login_required
@role_required("admin")
def admin_delete_user(user_id):
    if user_id == session["user_id"]:
        flash("Cannot delete your own account.", "danger")
        return redirect(url_for("admin_users"))
    db = get_db()
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    db.close()
    flash("User deleted.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/medicines")
@login_required
@role_required("admin")
def admin_medicines():
    db = get_db()
    medicines = db.execute("""
        SELECT m.*, u.name as donor_name FROM medicines m
        JOIN users u ON m.donor_id = u.id
        ORDER BY m.created_at DESC
    """).fetchall()
    db.close()
    return render_template("admin_medicines.html", medicines=medicines, is_expiring_soon=is_expiring_soon)


@app.errorhandler(404)
def not_found(_):
    return render_template("404.html"), 404


@app.errorhandler(413)
def file_too_large(_):
    flash("Uploaded file is too large. Maximum allowed size is 5 MB.", "danger")
    return redirect(request.referrer or url_for("home"))


@app.errorhandler(500)
def internal_error(_):
    return render_template("500.html"), 500


# Ensure DB/schema exists for Gunicorn/Render startup too.
init_db()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_ENV") != "production")