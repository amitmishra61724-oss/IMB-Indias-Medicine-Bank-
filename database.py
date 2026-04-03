import sqlite3
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), "imb.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'receiver',
            phone TEXT,
            city TEXT NOT NULL,
            address TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS medicines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            generic_name TEXT,
            quantity INTEGER NOT NULL,
            unit TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            condition TEXT NOT NULL DEFAULT 'sealed',
            description TEXT,
            image_filename TEXT,
            pickup_location TEXT NOT NULL,
            city TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'available',
            donor_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            medicine_id INTEGER NOT NULL REFERENCES medicines(id) ON DELETE CASCADE,
            receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            donor_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            status TEXT NOT NULL DEFAULT 'pending',
            is_emergency INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            ack_message TEXT,
            receiver_acknowledged INTEGER NOT NULL DEFAULT 0,
            acknowledged_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS cart (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            medicine_id INTEGER NOT NULL REFERENCES medicines(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            purpose TEXT NOT NULL,
            otp_code TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            is_used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
    """)

    # Lightweight schema migration for existing databases
    medicine_columns = {row[1] for row in cur.execute("PRAGMA table_info(medicines)").fetchall()}
    if "image_filename" not in medicine_columns:
        cur.execute("ALTER TABLE medicines ADD COLUMN image_filename TEXT")

    request_columns = {row[1] for row in cur.execute("PRAGMA table_info(requests)").fetchall()}
    if "ack_message" not in request_columns:
        cur.execute("ALTER TABLE requests ADD COLUMN ack_message TEXT")
    if "receiver_acknowledged" not in request_columns:
        cur.execute("ALTER TABLE requests ADD COLUMN receiver_acknowledged INTEGER NOT NULL DEFAULT 0")
    if "acknowledged_at" not in request_columns:
        cur.execute("ALTER TABLE requests ADD COLUMN acknowledged_at TEXT")

    # Seed admin and sample data if empty
    existing = cur.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if existing == 0:
        admin_hash = generate_password_hash("admin123")
        donor1_hash = generate_password_hash("password123")
        donor2_hash = generate_password_hash("password123")
        receiver1_hash = generate_password_hash("password123")

        cur.executescript(f"""
            INSERT INTO users (name, email, password_hash, role, phone, city, address) VALUES
            ('Admin User', 'admin@imb.org', '{admin_hash}', 'admin', '9999999999', 'Mumbai', 'IMB Headquarters'),
            ('Rajesh Kumar', 'rajesh@example.com', '{donor1_hash}', 'donor', '9876543210', 'Mumbai', 'Andheri West'),
            ('Priya Sharma', 'priya@example.com', '{donor2_hash}', 'donor', '9876543211', 'Delhi', 'Connaught Place'),
            ('Anita Patel', 'anita@example.com', '{receiver1_hash}', 'receiver', '9876543212', 'Pune', 'Kothrud');

            INSERT INTO medicines (name, generic_name, quantity, unit, expiry_date, condition, description, pickup_location, city, donor_id) VALUES
            ('Paracetamol 500mg', 'Acetaminophen', 20, 'tablets', '2027-06-30', 'sealed', 'Unopened strip, fever & pain relief', 'Near Andheri Station, Exit Gate 2', 'Mumbai', 2),
            ('Amoxicillin 250mg', 'Amoxicillin', 10, 'capsules', '2026-09-15', 'sealed', 'Antibiotic, unused from prescription', 'Connaught Place Market', 'Delhi', 3),
            ('Metformin 500mg', 'Metformin HCl', 30, 'tablets', '2027-01-20', 'sealed', 'Diabetes medicine, sealed pack', 'Indiranagar, 100 Feet Road', 'Delhi', 3),
            ('Cough Syrup', 'Dextromethorphan', 2, 'bottles', '2026-12-10', 'sealed', 'Children cough syrup, sealed', 'Andheri West, Versova Road', 'Mumbai', 2),
            ('Cetirizine 10mg', 'Cetirizine HCl', 15, 'tablets', '2027-03-15', 'sealed', 'Antihistamine for allergies', 'Andheri East, MIDC', 'Mumbai', 2),
            ('Insulin Glargine', 'Insulin', 3, 'vials', '2026-08-01', 'sealed', 'Insulin for diabetes - keep refrigerated', 'Connaught Place', 'Delhi', 3),
            ('Omeprazole 20mg', 'Omeprazole', 14, 'capsules', '2026-11-30', 'sealed', 'Acid reflux medicine', 'Andheri East, MIDC', 'Mumbai', 2);
        """)

    conn.commit()
    conn.close()


def is_expiring_soon(expiry_date_str):
    try:
        expiry = datetime.strptime(expiry_date_str, "%Y-%m-%d")
        return expiry <= datetime.now() + timedelta(days=30)
    except Exception:
        return False


def is_expired(expiry_date_str):
    try:
        expiry = datetime.strptime(expiry_date_str, "%Y-%m-%d")
        return expiry < datetime.now()
    except Exception:
        return False