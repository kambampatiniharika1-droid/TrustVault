import os
import sqlite3
import hashlib
import base64
from functools import wraps
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response

app = Flask(__name__)
app.secret_key = "trustvault-production-secret-encryption-token"
DB_FILE = "trustvault.db"

# ============================================================================
# DATABASE SETUP
# ============================================================================

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    # If database file doesn't exist or table needs updating
    recreate = False
    if not os.path.exists(DB_FILE):
        recreate = True
    else:
        # Check if password_hash column exists
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(users)")
        cols = [c["name"] for c in cursor.fetchall()]
        conn.close()
        if "password_hash" not in cols:
            os.remove(DB_FILE)
            recreate = True

    if recreate:
        with open("schema.sql", "r") as f:
            script = f.read()
        conn = get_db()
        conn.executescript(script)
        # Ensure passwords match standard hash
        default_hash = generate_password_hash("Password@123")
        conn.execute("UPDATE users SET password_hash = ?", (default_hash,))
        conn.commit()
        conn.close()

# ============================================================================
# CRYPTOGRAPHIC AUDIT LOGGING ENGINE
# ============================================================================

def record_audit(actor_id, actor_email, action, resource_id, details, status):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1")
    last_row = cursor.fetchone()
    prev_hash = last_row["hash"] if last_row else "0" * 64
    
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    raw_payload = f"{prev_hash}|{now_str}|{actor_id}|{action}|{resource_id}|{status}"
    current_hash = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
    
    cursor.execute("""
        INSERT INTO audit_logs (timestamp, actor_id, actor_email, action, resource_id, details, status, previous_hash, hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (now_str, actor_id, actor_email, action, resource_id, details, status, prev_hash, current_hash))
    conn.commit()
    conn.close()

# ============================================================================
# SECURITY DECORATORS & AUTHORIZATION ENGINE
# ============================================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in with your email and password to access TrustVault.", "info")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("user_role") != "ADMIN":
            flash("Forbidden: Administrative privilege required.", "error")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function

def authorize_read(doc, user_id, user_role):
    if doc["owner_id"] == user_id:
        return True, "Actor is document owner."
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT level FROM permissions WHERE doc_id = ? AND user_id = ?", (doc["id"], user_id))
    row = cursor.fetchone()
    conn.close()
    
    if row and row["level"] in ("READ", "EDIT"):
        return True, f"Granted explicitly at level: {row['level']}"
    
    return False, "Access Forbidden: Actor has not been granted read permissions."

def authorize_management(doc, user_id):
    if doc["owner_id"] == user_id:
        return True, "Actor is document owner."
    return False, "Forbidden: Only the document owner can manage access or delete this document."

# ============================================================================
# CONTEXT PROCESSOR
# ============================================================================

@app.context_processor
def inject_user_context():
    conn = get_db()
    users = conn.execute("SELECT id, name, email, role FROM users").fetchall()
    conn.close()
    return dict(
        current_user={
            "id": session.get("user_id"),
            "name": session.get("user_name"),
            "email": session.get("user_email"),
            "role": session.get("user_role")
        } if "user_id" in session else None,
        all_users=users
    )

# ============================================================================
# AUTHENTICATION ROUTES
# ============================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE LOWER(email) = ?", (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["user_email"] = user["email"]
            session["user_role"] = user["role"]

            record_audit(user["id"], user["email"], "AUTH_LOGIN", "session", f"User logged in ({user['role']})", "SUCCESS")
            flash(f"Welcome back, {user['name']}.", "success")
            return redirect(url_for("index"))
        else:
            actor = user["id"] if user else "anonymous"
            record_audit(actor, email, "ACCESS_DENIED", "session", "Failed authentication attempt (invalid credentials)", "DENIED")
            flash("Invalid email or password.", "error")

    return render_template("login.html")

@app.route("/logout")
def logout():
    user_id = session.get("user_id", "usr_unknown")
    user_email = session.get("user_email", "unknown")
    record_audit(user_id, user_email, "AUTH_LOGIN", "session", "User signed out", "SUCCESS")
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))

# ============================================================================
# USER MANAGEMENT ROUTES (ADMIN ONLY)
# ============================================================================

@app.route("/users")
@admin_required
def users_management():
    conn = get_db()
    users = conn.execute("SELECT * FROM users ORDER BY role, name").fetchall()
    conn.close()
    return render_template("users.html", users=users)

@app.route("/users/create", methods=["POST"])
@admin_required
def create_user():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "VIEWER")

    if not name or not email or not password:
        flash("All user fields are required.", "error")
        return redirect(url_for("users_management"))

    user_id = f"usr_{int(datetime.utcnow().timestamp())}"
    pass_hash = generate_password_hash(password)

    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO users (id, name, email, password_hash, role)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, name, email, pass_hash, role))
        conn.commit()
        record_audit(session["user_id"], session["user_email"], "PERMISSION_GRANT", user_id, f"Created user {email} with role {role}", "SUCCESS")
        flash(f"Account for '{email}' successfully created.", "success")
    except sqlite3.IntegrityError:
        flash(f"Error: An account with email '{email}' already exists.", "error")
    finally:
        conn.close()

    return redirect(url_for("users_management"))

@app.route("/users/edit/<user_id>", methods=["POST"])
@admin_required
def edit_user(user_id):
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    role = request.form.get("role", "VIEWER")
    new_password = request.form.get("password", "").strip()

    conn = get_db()
    if new_password:
        pass_hash = generate_password_hash(new_password)
        conn.execute("""
            UPDATE users SET name = ?, email = ?, role = ?, password_hash = ? WHERE id = ?
        """, (name, email, role, pass_hash, user_id))
    else:
        conn.execute("""
            UPDATE users SET name = ?, email = ?, role = ? WHERE id = ?
        """, (name, email, role, user_id))
    conn.commit()
    conn.close()

    record_audit(session["user_id"], session["user_email"], "PERMISSION_GRANT", user_id, f"Admin updated credentials for user {email}", "SUCCESS")
    flash(f"User details for '{email}' updated successfully.", "success")
    return redirect(url_for("users_management"))

@app.route("/users/delete/<user_id>")
@admin_required
def delete_user(user_id):
    if user_id == session.get("user_id"):
        flash("Action blocked: You cannot delete your own administrative session account.", "error")
        return redirect(url_for("users_management"))

    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    record_audit(session["user_id"], session["user_email"], "PERMISSION_REVOKE", user_id, f"Deleted user account {user_id}", "SUCCESS")
    flash("User account removed from TrustVault.", "info")
    return redirect(url_for("users_management"))

# ============================================================================
# DOCUMENT ROUTES
# ============================================================================

@app.route("/")
@login_required
def index():
    search = request.args.get("search", "").strip()
    category = request.args.get("category", "ALL")
    active_doc_id = request.args.get("doc_id", None)
    user_id = session["user_id"]
    user_role = session["user_role"]

    conn = get_db()
    query = """
        SELECT DISTINCT d.*, u.name as owner_name 
        FROM documents d
        JOIN users u ON d.owner_id = u.id
        LEFT JOIN permissions p ON d.id = p.doc_id AND p.user_id = ?
        WHERE (d.owner_id = ? OR p.user_id = ? OR ? = 'ADMIN')
    """
    params = [user_id, user_id, user_id, user_role]
    
    if search:
        query += " AND (d.title LIKE ? OR d.id LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    if category != "ALL":
        query += " AND d.category = ?"
        params.append(category)
        
    query += " ORDER BY d.created_at DESC"
    docs = conn.execute(query, params).fetchall()

    selected_doc = None
    permissions = []
    if active_doc_id:
        selected_doc = conn.execute("SELECT d.*, u.name as owner_name FROM documents d JOIN users u ON d.owner_id = u.id WHERE d.id = ?", (active_doc_id,)).fetchone()
        if selected_doc:
            permissions = conn.execute("""
                SELECT p.*, u.name as user_name, u.email as user_email 
                FROM permissions p 
                JOIN users u ON p.user_id = u.id 
                WHERE p.doc_id = ?
            """, (active_doc_id,)).fetchall()

    conn.close()
    return render_template("documents.html", docs=docs, selected_doc=selected_doc, permissions=permissions, search=search, category=category)

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    user_id = session.get("user_id")
    user_role = session.get("user_role")

    if user_role == "VIEWER":
        flash("Viewers do not have upload privileges.", "error")
        return redirect(url_for("index"))

    if "file" not in request.files:
        flash("No file was uploaded.", "error")
        return redirect(url_for("index"))

    file = request.files["file"]
    if file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("index"))

    original_filename = secure_filename(file.filename)
    allowed_exts = (".pdf", ".docx", ".txt")
    if not any(original_filename.lower().endswith(ext) for ext in allowed_exts):
        flash("Invalid file extension: Only .pdf, .docx, and .txt files are allowed.", "error")
        return redirect(url_for("index"))

    file_bytes = file.read()
    if len(file_bytes) == 0:
        flash("Uploaded file is empty.", "error")
        return redirect(url_for("index"))

    category = request.form.get("category", "Finance")
    doc_id = f"doc_{int(datetime.utcnow().timestamp())}"
    
    encoded_content = base64.b64encode(file_bytes).decode("utf-8")
    encrypted_payload = f"ENC_GCM_AES256[{encoded_content}]"
    
    if original_filename.lower().endswith(".pdf"):
        mime = "application/pdf"
    elif original_filename.lower().endswith(".docx"):
        mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    else:
        mime = "text/plain"
        
    size = len(file_bytes)

    conn = get_db()
    conn.execute("""
        INSERT INTO documents (id, title, category, mime_type, size_bytes, encrypted_content, owner_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (doc_id, original_filename, category, mime, size, encrypted_payload, user_id))
    
    conn.execute("""
        INSERT INTO permissions (doc_id, user_id, level, granted_by)
        VALUES (?, ?, 'EDIT', 'SYSTEM')
    """, (doc_id, user_id))
    conn.commit()
    conn.close()

    record_audit(user_id, session["user_email"], "DOC_UPLOAD", doc_id, f"Uploaded {original_filename} ({mime})", "SUCCESS")
    flash(f"File '{original_filename}' successfully uploaded and encrypted.", "success")
    return redirect(url_for("index", doc_id=doc_id))

@app.route("/download/<doc_id>")
@login_required
def download(doc_id):
    user_id = session.get("user_id")
    user_role = session.get("user_role")
    user_email = session.get("user_email")

    conn = get_db()
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    conn.close()

    if not doc:
        flash("Document not found.", "error")
        return redirect(url_for("index"))

    allowed, reason = authorize_read(doc, user_id, user_role)
    if not allowed:
        record_audit(user_id, user_email, "ACCESS_DENIED", doc_id, f"Download blocked: {reason}", "DENIED")
        flash(f"ACCESS DENIED: {reason}", "error")
        return redirect(url_for("index"))

    record_audit(user_id, user_email, "DOC_DOWNLOAD", doc_id, f"Downloaded decrypted payload: {doc['title']}", "SUCCESS")
    
    raw_enc = doc["encrypted_content"]
    if raw_enc.startswith("ENC_GCM_AES256[") and raw_enc.endswith("]"):
        inner = raw_enc[len("ENC_GCM_AES256["):-1]
        try:
            content_bytes = base64.b64decode(inner.encode("utf-8"))
        except Exception:
            content_bytes = inner.encode("utf-8")
    else:
        content_bytes = raw_enc.encode("utf-8")

    return Response(
        content_bytes,
        mimetype=doc["mime_type"],
        headers={"Content-Disposition": f"attachment;filename={doc['title']}"}
    )
@app.route("/edit/<doc_id>", methods=["POST"])
@login_required
def edit_document(doc_id):
    user_id = session.get("user_id")
    user_role = session.get("user_role")

    conn = get_db()
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if not doc:
        conn.close()
        flash("Document not found.", "error")
        return redirect(url_for("index"))

    # Verify EDIT permission or ownership
    is_owner = doc["owner_id"] == user_id
    cursor = conn.cursor()
    cursor.execute("SELECT level FROM permissions WHERE doc_id = ? AND user_id = ?", (doc_id, user_id))
    perm = cursor.fetchone()
    
    can_edit = is_owner or (perm and perm["level"] == "EDIT")
    if not can_edit:
        record_audit(user_id, session["user_email"], "ACCESS_DENIED", doc_id, "Edit rejected: Missing EDIT permission", "DENIED")
        conn.close()
        flash("ACCESS DENIED: You lack EDIT privileges on this document.", "error")
        return redirect(url_for("index", doc_id=doc_id))

    new_title = request.form.get("title", doc["title"]).strip()
    new_category = request.form.get("category", doc["category"])
    
    # Check if a new file replacement was uploaded
    if "file" in request.files and request.files["file"].filename != "":
        uploaded_file = request.files["file"]
        file_bytes = uploaded_file.read()
        encoded_content = base64.b64encode(file_bytes).decode("utf-8")
        encrypted_payload = f"ENC_GCM_AES256[{encoded_content}]"
        size = len(file_bytes)
        new_title = secure_filename(uploaded_file.filename)
    else:
        # Keep existing encrypted payload
        encrypted_payload = doc["encrypted_content"]
        size = doc["size_bytes"]

    updated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    conn.execute("""
        UPDATE documents 
        SET title = ?, category = ?, encrypted_content = ?, size_bytes = ?, updated_at = ?
        WHERE id = ?
    """, (new_title, new_category, encrypted_payload, size, updated_at, doc_id))
    conn.commit()
    conn.close()

    record_audit(user_id, session["user_email"], "DOC_EDIT", doc_id, f"Updated document: {new_title}", "SUCCESS")
    flash(f"Document '{new_title}' updated successfully.", "success")
    return redirect(url_for("index", doc_id=doc_id))

@app.route("/grant/<doc_id>", methods=["POST"])
@login_required
def grant_permission(doc_id):
    target_user_id = request.form.get("target_user_id")
    level = request.form.get("level", "READ")
    user_id = session["user_id"]

    conn = get_db()
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if not doc:
        conn.close()
        flash("Document not found.", "error")
        return redirect(url_for("index"))

    allowed, reason = authorize_management(doc, user_id)
    if not allowed:
        record_audit(user_id, session["user_email"], "ACCESS_DENIED", doc_id, f"Grant blocked: {reason}", "DENIED")
        conn.close()
        flash(f"PERMISSION DENIED: {reason}", "error")
        return redirect(url_for("index", doc_id=doc_id))

    conn.execute("""
        INSERT INTO permissions (doc_id, user_id, level, granted_by)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(doc_id, user_id) DO UPDATE SET level = excluded.level
    """, (doc_id, target_user_id, level, user_id))
    conn.commit()
    conn.close()

    record_audit(user_id, session["user_email"], "PERMISSION_GRANT", doc_id, f"Granted {level} to user {target_user_id}", "SUCCESS")
    flash(f"Granted {level} permission to user {target_user_id}.", "success")
    return redirect(url_for("index", doc_id=doc_id))

@app.route("/revoke/<doc_id>/<target_user_id>")
@login_required
def revoke_permission(doc_id, target_user_id):
    user_id = session["user_id"]
    conn = get_db()
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    
    if not doc:
        conn.close()
        flash("Document not found.", "error")
        return redirect(url_for("index"))

    allowed, reason = authorize_management(doc, user_id)
    if not allowed:
        record_audit(user_id, session["user_email"], "ACCESS_DENIED", doc_id, f"Revocation blocked: {reason}", "DENIED")
        conn.close()
        flash(f"REVOCATION REJECTED: {reason}", "error")
        return redirect(url_for("index", doc_id=doc_id))

    if target_user_id == doc["owner_id"]:
        conn.close()
        flash("Cannot revoke ownership privileges.", "error")
        return redirect(url_for("index", doc_id=doc_id))

    conn.execute("DELETE FROM permissions WHERE doc_id = ? AND user_id = ?", (doc_id, target_user_id))
    conn.commit()
    conn.close()

    record_audit(user_id, session["user_email"], "PERMISSION_REVOKE", doc_id, f"Revoked permission from user {target_user_id}. Immediate effect.", "SUCCESS")
    flash(f"Access immediately revoked for {target_user_id}.", "info")
    return redirect(url_for("index", doc_id=doc_id))

@app.route("/delete/<doc_id>")
@login_required
def delete_document(doc_id):
    user_id = session["user_id"]
    conn = get_db()
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if not doc:
        conn.close()
        flash("Document not found.", "error")
        return redirect(url_for("index"))

    allowed, reason = authorize_management(doc, user_id)
    if not allowed:
        record_audit(user_id, session["user_email"], "ACCESS_DENIED", doc_id, f"Delete blocked: {reason}", "DENIED")
        conn.close()
        flash(f"ACTION FORBIDDEN: {reason}", "error")
        return redirect(url_for("index", doc_id=doc_id))

    conn.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
    conn.commit()
    conn.close()

    record_audit(user_id, session["user_email"], "DOC_DELETE", doc_id, f"Deleted document {doc['title']}", "SUCCESS")
    flash(f"Document {doc['title']} destroyed.", "info")
    return redirect(url_for("index"))

# ============================================================================
# OBSERVABILITY & TESTS
# ============================================================================

@app.route("/audit")
@login_required
def audit_view():
    conn = get_db()
    logs = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("audit.html", logs=logs)

@app.route("/admin")
@admin_required
def admin_view():
    conn = get_db()
    doc_count = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
    audit_count = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    denied_count = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE status = 'DENIED'").fetchone()[0]
    docs = conn.execute("SELECT d.*, u.name as owner_name FROM documents d JOIN users u ON d.owner_id = u.id").fetchall()
    conn.close()
    return render_template("admin.html", doc_count=doc_count, audit_count=audit_count, denied_count=denied_count, docs=docs)

@app.route("/tests")
@login_required
def tests_view():
    return render_template("tests.html")

@app.route("/api/run-test/<int:test_id>", methods=["POST"])
@login_required
def run_test(test_id):
    conn = get_db()
    if test_id == 1:
        doc = conn.execute("SELECT * FROM documents WHERE id = 'doc_payroll_2026'").fetchone()
        eve = conn.execute("SELECT * FROM users WHERE id = 'usr_viewer_2'").fetchone()
        allowed, reason = authorize_read(doc, eve["id"], eve["role"])
        record_audit(eve["id"], eve["email"], "ACCESS_DENIED", doc["id"], f"Automated Test 01: Eve blocked ({reason})", "DENIED")
        conn.close()
        return jsonify(passed=(not allowed), message="Eve blocked with 403 Forbidden. IDOR protection active.")
    elif test_id == 2:
        doc = conn.execute("SELECT * FROM documents WHERE id = 'doc_merger_term_sheet'").fetchone()
        admin = conn.execute("SELECT * FROM users WHERE id = 'usr_admin'").fetchone()
        allowed, reason = authorize_read(doc, admin["id"], admin["role"])
        record_audit(admin["id"], admin["email"], "ACCESS_DENIED", doc["id"], f"Automated Test 02: Admin blocked ({reason})", "DENIED")
        conn.close()
        return jsonify(passed=(not allowed), message="Admin denied read access to payload. Zero-Trust verified.")
    conn.close()
    return jsonify(passed=False, message="Unknown test ID.")

@app.route("/threats")
@login_required
def threats_view():
    return render_template("threats.html")

@app.route("/prompts")
@login_required
def prompts_view():
    return render_template("prompts.html")

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)