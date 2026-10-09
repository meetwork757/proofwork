import os
import json
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, flash, g, redirect, render_template, request,
    send_from_directory, session, url_for, jsonify, abort, send_file,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import qrcode
from io import BytesIO

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "proofwork.db")
UPLOAD_DIR = os.path.join(BASE, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

COMPLETE_AT = 8
ALLOWED = {"png", "jpg", "jpeg", "webp", "gif"}

app = Flask(__name__)
app.secret_key = os.environ.get("PROOFWORK_SECRET", "proofwork-dev-secret-change-me")
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            phone TEXT DEFAULT '',
            city TEXT DEFAULT '',
            slug TEXT UNIQUE,
            suspended INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS workshops (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            master_id INTEGER UNIQUE NOT NULL,
            name TEXT NOT NULL,
            trade TEXT NOT NULL,
            area TEXT NOT NULL,
            city TEXT NOT NULL,
            invite_code TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (master_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS memberships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workshop_id INTEGER NOT NULL,
            apprentice_id INTEGER UNIQUE NOT NULL,
            joined_at TEXT NOT NULL,
            FOREIGN KEY (workshop_id) REFERENCES workshops(id),
            FOREIGN KEY (apprentice_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            apprentice_id INTEGER NOT NULL,
            workshop_id INTEGER NOT NULL,
            note TEXT NOT NULL,
            photo TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            review_note TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            reviewed_at TEXT,
            FOREIGN KEY (apprentice_id) REFERENCES users(id),
            FOREIGN KEY (workshop_id) REFERENCES workshops(id)
        );
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """
    )
    conn.commit()
    conn.close()


def slugify(name, user_id):
    base = "".join(ch.lower() if ch.isalnum() else "-" for ch in name).strip("-")
    base = "-".join(p for p in base.split("-") if p) or "apprentice"
    return f"{base}-{user_id}"


def invite_code():
    return secrets.token_hex(3).upper()


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def login_required(role=None):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for("login"))
            if user["suspended"]:
                session.clear()
                flash("This account is suspended.")
                return redirect(url_for("login"))
            if role and user["role"] != role:
                flash("That page is for a different account type.")
                return redirect(url_for("home"))
            return fn(*args, **kwargs)
        return wrapper
    return deco


def workshop_for_master(master_id):
    return db().execute("SELECT * FROM workshops WHERE master_id = ?", (master_id,)).fetchone()


def membership_for(apprentice_id):
    return db().execute(
        """
        SELECT m.*, w.name AS workshop_name, w.trade, w.area, w.city, w.invite_code,
               u.name AS master_name, u.id AS master_id
        FROM memberships m
        JOIN workshops w ON w.id = m.workshop_id
        JOIN users u ON u.id = w.master_id
        WHERE m.apprentice_id = ?
        """,
        (apprentice_id,),
    ).fetchone()


def approved_count(apprentice_id):
    row = db().execute(
        "SELECT COUNT(*) AS c FROM tasks WHERE apprentice_id = ? AND status = 'approved'",
        (apprentice_id,),
    ).fetchone()
    return row["c"]


@app.route("/")
def home():
    return render_template("mobile.html")


@app.route("/app")
def mobile_app():
    return render_template("mobile.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "")
        phone = request.form.get("phone", "").strip()
        city = request.form.get("city", "").strip()
        if role not in {"master", "apprentice"}:
            flash("Choose master or apprentice.")
            return redirect(url_for("register"))
        if len(name) < 3 or len(password) < 6 or "@" not in email:
            flash("Use a real name, a valid email, and a password of at least 6 characters.")
            return redirect(url_for("register"))
        try:
            cur = db().execute(
                "INSERT INTO users (email, password_hash, name, role, phone, city, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (email, generate_password_hash(password), name, role, phone, city, now()),
            )
            db().commit()
        except sqlite3.IntegrityError:
            flash("That email is already registered.")
            return redirect(url_for("register"))
        uid = cur.lastrowid
        if role == "apprentice":
            slug = slugify(name, uid)
            db().execute("UPDATE users SET slug = ? WHERE id = ?", (slug, uid))
            db().commit()
        session["uid"] = uid
        return redirect(url_for("master_dash" if role == "master" else "apprentice_dash"))
    return render_template("register.html", user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Email or password is wrong.")
            return redirect(url_for("login"))
        if user["suspended"]:
            flash("This account is suspended.")
            return redirect(url_for("login"))
        session["uid"] = user["id"]
        if user["role"] == "admin":
            return redirect(url_for("admin"))
        if user["role"] == "master":
            return redirect(url_for("master_dash"))
        return redirect(url_for("apprentice_dash"))
    return render_template("login.html", user=current_user())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/master", methods=["GET", "POST"])
@login_required("master")
def master_dash():
    user = current_user()
    shop = workshop_for_master(user["id"])
    if request.method == "POST":
        action = request.form.get("action")
        if action == "create_workshop" and not shop:
            name = request.form.get("name", "").strip()
            trade = request.form.get("trade", "").strip()
            area = request.form.get("area", "").strip()
            city = request.form.get("city", "").strip()
            if len(name) < 3 or len(trade) < 2 or len(area) < 2 or len(city) < 2:
                flash("Fill in the workshop name, trade, area, and city.")
            else:
                code = invite_code()
                db().execute(
                    "INSERT INTO workshops (master_id, name, trade, area, city, invite_code, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (user["id"], name, trade, area, city, code, now()),
                )
                db().commit()
                flash("Workshop opened. Share the invite code with apprentices only.")
        elif action == "new_code" and shop:
            code = invite_code()
            db().execute("UPDATE workshops SET invite_code = ? WHERE id = ?", (code, shop["id"]))
            db().commit()
            flash("Invite code changed. Old code no longer works.")
        elif action == "review" and shop:
            task_id = request.form.get("task_id")
            decision = request.form.get("decision")
            review_note = request.form.get("review_note", "").strip()[:240]
            if decision in {"approved", "rejected"}:
                db().execute(
                    """
                    UPDATE tasks SET status = ?, review_note = ?, reviewed_at = ?
                    WHERE id = ? AND workshop_id = ? AND status = 'pending'
                    """,
                    (decision, review_note, now(), task_id, shop["id"]),
                )
                db().commit()
        return redirect(url_for("master_dash"))
    apprentices = []
    pending = []
    if shop:
        apprentices = db().execute(
            """
            SELECT u.*, 
              (SELECT COUNT(*) FROM tasks t WHERE t.apprentice_id = u.id AND t.status = 'approved') AS approved,
              (SELECT COUNT(*) FROM tasks t WHERE t.apprentice_id = u.id AND t.status = 'pending') AS pending
            FROM memberships m
            JOIN users u ON u.id = m.apprentice_id
            WHERE m.workshop_id = ?
            ORDER BY u.name
            """,
            (shop["id"],),
        ).fetchall()
        pending = db().execute(
            """
            SELECT t.*, u.name AS apprentice_name, u.slug
            FROM tasks t JOIN users u ON u.id = t.apprentice_id
            WHERE t.workshop_id = ? AND t.status = 'pending'
            ORDER BY t.created_at
            """,
            (shop["id"],),
        ).fetchall()
    return render_template(
        "master.html", user=user, shop=shop, apprentices=apprentices,
        pending=pending, complete_at=COMPLETE_AT,
    )


@app.route("/apprentice", methods=["GET", "POST"])
@login_required("apprentice")
def apprentice_dash():
    user = current_user()
    member = membership_for(user["id"])
    if request.method == "POST":
        action = request.form.get("action")
        if action == "join" and not member:
            code = request.form.get("code", "").strip().upper()
            shop = db().execute("SELECT * FROM workshops WHERE invite_code = ?", (code,)).fetchone()
            if not shop:
                flash("That invite code was not found.")
            else:
                db().execute(
                    "INSERT INTO memberships (workshop_id, apprentice_id, joined_at) VALUES (?, ?, ?)",
                    (shop["id"], user["id"], now()),
                )
                db().commit()
                flash("You joined the workshop. Submit real tasks your master can check.")
        elif action == "task" and member:
            note = request.form.get("note", "").strip()
            photo = request.files.get("photo")
            if len(note) < 4:
                flash("Describe the task in a short note.")
            elif not photo or not photo.filename:
                flash("Add a photo of the finished work.")
            else:
                ext = photo.filename.rsplit(".", 1)[-1].lower() if "." in photo.filename else ""
                if ext not in ALLOWED:
                    flash("Use a PNG, JPG, or WEBP photo.")
                else:
                    fname = f"{user['id']}-{secrets.token_hex(6)}.{ext}"
                    photo.save(os.path.join(UPLOAD_DIR, fname))
                    db().execute(
                        "INSERT INTO tasks (apprentice_id, workshop_id, note, photo, status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)",
                        (user["id"], member["workshop_id"], note[:240], fname, now()),
                    )
                    db().commit()
                    flash("Task sent to your master.")
        return redirect(url_for("apprentice_dash"))
    tasks = []
    approved = 0
    if member:
        tasks = db().execute(
            "SELECT * FROM tasks WHERE apprentice_id = ? ORDER BY created_at DESC",
            (user["id"],),
        ).fetchall()
        approved = approved_count(user["id"])
    return render_template(
        "apprentice.html", user=user, member=member, tasks=tasks,
        approved=approved, complete_at=COMPLETE_AT,
    )


@app.route("/r/<slug>")
def public_record(slug):
    person = db().execute(
        "SELECT * FROM users WHERE slug = ? AND role = 'apprentice'", (slug,)
    ).fetchone()
    if not person or person["suspended"]:
        abort(404)
    member = membership_for(person["id"])
    approved = approved_count(person["id"])
    tasks = db().execute(
        "SELECT * FROM tasks WHERE apprentice_id = ? AND status = 'approved' ORDER BY reviewed_at",
        (person["id"],),
    ).fetchall()
    return render_template(
        "public.html", person=person, member=member, tasks=tasks,
        approved=approved, complete_at=COMPLETE_AT, user=current_user(),
    )


@app.route("/qr/<slug>.png")
def qr_png(slug):
    person = db().execute("SELECT slug FROM users WHERE slug = ?", (slug,)).fetchone()
    if not person:
        abort(404)
    url = request.host_url.rstrip("/") + url_for("public_record", slug=slug)
    img = qrcode.make(url)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


@app.route("/media/<path:name>")
def media(name):
    safe = secure_filename(name)
    if not safe or safe != name:
        abort(404)
    return send_from_directory(UPLOAD_DIR, safe)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = db().execute("SELECT * FROM users WHERE email = ? AND role = 'admin'", (email,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Admin email or password is wrong.")
            return redirect(url_for("admin_login"))
        session["uid"] = user["id"]
        return redirect(url_for("admin"))
    return render_template("admin_login.html", user=current_user())


@app.route("/admin", methods=["GET", "POST"])
@login_required("admin")
def admin():
    if request.method == "POST":
        action = request.form.get("action")
        uid = request.form.get("user_id")
        if action == "suspend" and uid:
            db().execute("UPDATE users SET suspended = 1 WHERE id = ? AND role != 'admin'", (uid,))
            db().commit()
        elif action == "restore" and uid:
            db().execute("UPDATE users SET suspended = 0 WHERE id = ?", (uid,))
            db().commit()
        elif action == "delete_task":
            tid = request.form.get("task_id")
            db().execute("DELETE FROM tasks WHERE id = ?", (tid,))
            db().commit()
        return redirect(url_for("admin"))
    users = db().execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    shops = db().execute(
        """
        SELECT w.*, u.name AS master_name, u.email AS master_email,
          (SELECT COUNT(*) FROM memberships m WHERE m.workshop_id = w.id) AS apprentices
        FROM workshops w JOIN users u ON u.id = w.master_id
        ORDER BY w.created_at DESC
        """
    ).fetchall()
    tasks = db().execute(
        """
        SELECT t.*, u.name AS apprentice_name
        FROM tasks t JOIN users u ON u.id = t.apprentice_id
        ORDER BY t.created_at DESC LIMIT 40
        """
    ).fetchall()
    stats = {
        "users": db().execute("SELECT COUNT(*) c FROM users").fetchone()["c"],
        "masters": db().execute("SELECT COUNT(*) c FROM users WHERE role='master'").fetchone()["c"],
        "apprentices": db().execute("SELECT COUNT(*) c FROM users WHERE role='apprentice'").fetchone()["c"],
        "workshops": db().execute("SELECT COUNT(*) c FROM workshops").fetchone()["c"],
        "tasks": db().execute("SELECT COUNT(*) c FROM tasks").fetchone()["c"],
        "approved": db().execute("SELECT COUNT(*) c FROM tasks WHERE status='approved'").fetchone()["c"],
    }
    db_size = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
    upload_size = 0
    files = 0
    for fn in os.listdir(UPLOAD_DIR):
        path = os.path.join(UPLOAD_DIR, fn)
        if os.path.isfile(path):
            files += 1
            upload_size += os.path.getsize(path)
    return render_template(
        "admin.html", user=current_user(), users=users, shops=shops, tasks=tasks,
        stats=stats, db_path=DB_PATH, db_size=db_size, upload_size=upload_size,
        upload_files=files,
    )


@app.route("/admin/password", methods=["POST"])
@login_required("admin")
def admin_password():
    user = current_user()
    current = request.form.get("current", "")
    new = request.form.get("new", "")
    if not check_password_hash(user["password_hash"], current) or len(new) < 6:
        flash("Current password was wrong, or the new one is too short.")
        return redirect(url_for("admin"))
    db().execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new), user["id"]))
    db().commit()
    flash("Admin password updated. Use it on any device.")
    return redirect(url_for("admin"))


@app.route("/admin/export")
@login_required("admin")
def admin_export():
    conn = db()
    payload = {
        "exported_at": now(),
        "users": [dict(r) for r in conn.execute("SELECT id, email, name, role, phone, city, slug, suspended, created_at FROM users")],
        "workshops": [dict(r) for r in conn.execute("SELECT * FROM workshops")],
        "memberships": [dict(r) for r in conn.execute("SELECT * FROM memberships")],
        "tasks": [dict(r) for r in conn.execute("SELECT id, apprentice_id, workshop_id, note, photo, status, review_note, created_at, reviewed_at FROM tasks")],
    }
    buf = BytesIO(json.dumps(payload, indent=2).encode())
    return send_file(buf, mimetype="application/json", as_attachment=True, download_name="proofwork-cloud-export.json")


@app.route("/health")
def health():
    return jsonify({"ok": True, "store": "sqlite", "db": DB_PATH})


@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


@app.route("/api/<path:_any>", methods=["OPTIONS"])
def api_options(_any):
    return ("", 204)


def public_user(user):
    return {
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "phone": user["phone"],
        "city": user["city"],
        "slug": user["slug"],
        "suspended": user["suspended"],
    }


def issue_token(user_id):
    token = secrets.token_urlsafe(32)
    db().execute("INSERT INTO tokens (token, user_id, created_at) VALUES (?, ?, ?)", (token, user_id, now()))
    db().commit()
    return token


def bearer_user():
    header = request.headers.get("Authorization", "")
    token = header[7:] if header.startswith("Bearer ") else ""
    if not token:
        return None
    row = db().execute(
        "SELECT u.* FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.token = ?",
        (token,),
    ).fetchone()
    return row


def api_guard(role=None):
    user = bearer_user()
    if not user:
        return None, (jsonify({"error": "Sign in again."}), 401)
    if user["suspended"]:
        return None, (jsonify({"error": "This account is suspended."}), 403)
    if role and user["role"] != role:
        return None, (jsonify({"error": "Wrong account type."}), 403)
    return user, None


def media_url(name):
    if not name:
        return None
    return request.host_url.rstrip("/") + "/media/" + name


@app.route("/api/health")
def api_health():
    return jsonify({"ok": True, "app": "ProofWork", "store": "sqlite"})


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    user = db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Email or password is wrong."}), 401
    if user["suspended"]:
        return jsonify({"error": "This account is suspended."}), 403
    return jsonify({"token": issue_token(user["id"]), "user": public_user(user)})


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    role = data.get("role") or ""
    phone = (data.get("phone") or "").strip()
    city = (data.get("city") or "").strip()
    if role not in {"master", "apprentice"} or len(name) < 3 or len(password) < 6 or "@" not in email:
        return jsonify({"error": "Use a real name, email, password of 6+ characters, and master or apprentice."}), 400
    try:
        cur = db().execute(
            "INSERT INTO users (email, password_hash, name, role, phone, city, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (email, generate_password_hash(password), name, role, phone, city, now()),
        )
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "That email is already registered."}), 409
    uid = cur.lastrowid
    if role == "apprentice":
        db().execute("UPDATE users SET slug = ? WHERE id = ?", (slugify(name, uid), uid))
        db().commit()
    user = db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    return jsonify({"token": issue_token(uid), "user": public_user(user)})


@app.route("/api/me")
def api_me():
    user, err = api_guard()
    if err:
        return err
    return jsonify({"user": public_user(user)})


@app.route("/api/master")
def api_master():
    user, err = api_guard("master")
    if err:
        return err
    shop = workshop_for_master(user["id"])
    apprentices, pending = [], []
    if shop:
        apprentices = [
            {
                "id": a["id"], "name": a["name"], "slug": a["slug"],
                "approved": a["approved"], "pending": a["pending"],
            }
            for a in db().execute(
                """
                SELECT u.id, u.name, u.slug,
                  (SELECT COUNT(*) FROM tasks t WHERE t.apprentice_id = u.id AND t.status = 'approved') AS approved,
                  (SELECT COUNT(*) FROM tasks t WHERE t.apprentice_id = u.id AND t.status = 'pending') AS pending
                FROM memberships m JOIN users u ON u.id = m.apprentice_id
                WHERE m.workshop_id = ? ORDER BY u.name
                """,
                (shop["id"],),
            )
        ]
        pending = [
            {
                "id": t["id"], "note": t["note"], "photo": media_url(t["photo"]),
                "created_at": t["created_at"], "apprentice_name": t["apprentice_name"],
            }
            for t in db().execute(
                """
                SELECT t.*, u.name AS apprentice_name FROM tasks t
                JOIN users u ON u.id = t.apprentice_id
                WHERE t.workshop_id = ? AND t.status = 'pending' ORDER BY t.created_at
                """,
                (shop["id"],),
            )
        ]
    return jsonify({
        "workshop": dict(shop) if shop else None,
        "apprentices": apprentices,
        "pending": pending,
        "complete_at": COMPLETE_AT,
    })


@app.route("/api/workshop", methods=["POST"])
def api_workshop():
    user, err = api_guard("master")
    if err:
        return err
    if workshop_for_master(user["id"]):
        return jsonify({"error": "Workshop already open."}), 400
    data = request.get_json(silent=True) or {}
    name, trade = (data.get("name") or "").strip(), (data.get("trade") or "").strip()
    area, city = (data.get("area") or "").strip(), (data.get("city") or "").strip()
    if min(len(name), len(trade), len(area), len(city)) < 2:
        return jsonify({"error": "Fill in workshop name, trade, area, and city."}), 400
    db().execute(
        "INSERT INTO workshops (master_id, name, trade, area, city, invite_code, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user["id"], name, trade, area, city, invite_code(), now()),
    )
    db().commit()
    return jsonify({"ok": True})


@app.route("/api/workshop/code", methods=["POST"])
def api_new_code():
    user, err = api_guard("master")
    if err:
        return err
    shop = workshop_for_master(user["id"])
    if not shop:
        return jsonify({"error": "Open a workshop first."}), 400
    code = invite_code()
    db().execute("UPDATE workshops SET invite_code = ? WHERE id = ?", (code, shop["id"]))
    db().commit()
    return jsonify({"invite_code": code})


@app.route("/api/tasks/<int:task_id>/review", methods=["POST"])
def api_review(task_id):
    user, err = api_guard("master")
    if err:
        return err
    shop = workshop_for_master(user["id"])
    data = request.get_json(silent=True) or {}
    decision = data.get("decision")
    if decision not in {"approved", "rejected"} or not shop:
        return jsonify({"error": "Choose approve or reject."}), 400
    db().execute(
        """
        UPDATE tasks SET status = ?, review_note = ?, reviewed_at = ?
        WHERE id = ? AND workshop_id = ? AND status = 'pending'
        """,
        (decision, (data.get("review_note") or "")[:240], now(), task_id, shop["id"]),
    )
    db().commit()
    return jsonify({"ok": True})


@app.route("/api/apprentice")
def api_apprentice():
    user, err = api_guard("apprentice")
    if err:
        return err
    member = membership_for(user["id"])
    tasks = []
    approved = 0
    if member:
        approved = approved_count(user["id"])
        tasks = [
            {
                "id": t["id"], "note": t["note"], "status": t["status"],
                "photo": media_url(t["photo"]), "review_note": t["review_note"],
                "created_at": t["created_at"],
            }
            for t in db().execute(
                "SELECT * FROM tasks WHERE apprentice_id = ? ORDER BY created_at DESC",
                (user["id"],),
            )
        ]
    return jsonify({
        "member": dict(member) if member else None,
        "tasks": tasks,
        "approved": approved,
        "complete_at": COMPLETE_AT,
        "record_path": f"/r/{user['slug']}" if user["slug"] else None,
    })


@app.route("/api/join", methods=["POST"])
def api_join():
    user, err = api_guard("apprentice")
    if err:
        return err
    if membership_for(user["id"]):
        return jsonify({"error": "You already joined a workshop."}), 400
    code = ((request.get_json(silent=True) or {}).get("code") or "").strip().upper()
    shop = db().execute("SELECT * FROM workshops WHERE invite_code = ?", (code,)).fetchone()
    if not shop:
        return jsonify({"error": "That invite code was not found."}), 404
    db().execute(
        "INSERT INTO memberships (workshop_id, apprentice_id, joined_at) VALUES (?, ?, ?)",
        (shop["id"], user["id"], now()),
    )
    db().commit()
    return jsonify({"ok": True})


@app.route("/api/tasks", methods=["POST"])
def api_task():
    user, err = api_guard("apprentice")
    if err:
        return err
    member = membership_for(user["id"])
    if not member:
        return jsonify({"error": "Join a workshop first."}), 400
    note = (request.form.get("note") or "").strip()
    photo = request.files.get("photo")
    if len(note) < 4 or not photo or not photo.filename:
        return jsonify({"error": "Add a short note and a photo."}), 400
    ext = photo.filename.rsplit(".", 1)[-1].lower() if "." in photo.filename else ""
    if ext not in ALLOWED:
        return jsonify({"error": "Use a PNG, JPG, or WEBP photo."}), 400
    fname = f"{user['id']}-{secrets.token_hex(6)}.{ext}"
    photo.save(os.path.join(UPLOAD_DIR, fname))
    db().execute(
        "INSERT INTO tasks (apprentice_id, workshop_id, note, photo, status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)",
        (user["id"], member["workshop_id"], note[:240], fname, now()),
    )
    db().commit()
    return jsonify({"ok": True})


@app.route("/api/record/<slug>")
def api_record(slug):
    person = db().execute("SELECT * FROM users WHERE slug = ? AND role = 'apprentice'", (slug,)).fetchone()
    if not person or person["suspended"]:
        return jsonify({"error": "Record not found."}), 404
    member = membership_for(person["id"])
    tasks = [
        {"note": t["note"], "photo": media_url(t["photo"]), "reviewed_at": t["reviewed_at"]}
        for t in db().execute(
            "SELECT * FROM tasks WHERE apprentice_id = ? AND status = 'approved' ORDER BY reviewed_at",
            (person["id"],),
        )
    ]
    return jsonify({
        "person": {"name": person["name"], "city": person["city"], "slug": person["slug"]},
        "member": {
            "workshop_name": member["workshop_name"],
            "trade": member["trade"],
            "area": member["area"],
            "city": member["city"],
            "master_name": member["master_name"],
            "joined_at": member["joined_at"],
        } if member else None,
        "tasks": tasks,
        "approved": approved_count(person["id"]),
        "complete_at": COMPLETE_AT,
    })


@app.route("/api/admin")
def api_admin():
    user, err = api_guard("admin")
    if err:
        return err
    users = [public_user(u) for u in db().execute("SELECT * FROM users ORDER BY created_at DESC")]
    shops = [dict(s) for s in db().execute(
        """
        SELECT w.*, u.name AS master_name, u.email AS master_email,
          (SELECT COUNT(*) FROM memberships m WHERE m.workshop_id = w.id) AS apprentices
        FROM workshops w JOIN users u ON u.id = w.master_id ORDER BY w.created_at DESC
        """
    )]
    tasks = [
        {"id": t["id"], "note": t["note"], "status": t["status"], "apprentice_name": t["apprentice_name"], "photo": media_url(t["photo"])}
        for t in db().execute(
            "SELECT t.*, u.name AS apprentice_name FROM tasks t JOIN users u ON u.id = t.apprentice_id ORDER BY t.created_at DESC LIMIT 40"
        )
    ]
    return jsonify({
        "users": users,
        "shops": shops,
        "tasks": tasks,
        "stats": {
            "users": db().execute("SELECT COUNT(*) c FROM users").fetchone()["c"],
            "workshops": db().execute("SELECT COUNT(*) c FROM workshops").fetchone()["c"],
            "tasks": db().execute("SELECT COUNT(*) c FROM tasks").fetchone()["c"],
            "approved": db().execute("SELECT COUNT(*) c FROM tasks WHERE status='approved'").fetchone()["c"],
        },
    })


@app.route("/api/admin/user", methods=["POST"])
def api_admin_user():
    user, err = api_guard("admin")
    if err:
        return err
    data = request.get_json(silent=True) or {}
    uid, action = data.get("user_id"), data.get("action")
    if action == "suspend":
        db().execute("UPDATE users SET suspended = 1 WHERE id = ? AND role != 'admin'", (uid,))
    elif action == "restore":
        db().execute("UPDATE users SET suspended = 0 WHERE id = ?", (uid,))
    else:
        return jsonify({"error": "Unknown action."}), 400
    db().commit()
    return jsonify({"ok": True})


@app.route("/api/admin/task", methods=["POST"])
def api_admin_task():
    user, err = api_guard("admin")
    if err:
        return err
    tid = (request.get_json(silent=True) or {}).get("task_id")
    db().execute("DELETE FROM tasks WHERE id = ?", (tid,))
    db().commit()
    return jsonify({"ok": True})


def seed():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    existing = conn.execute("SELECT id FROM users WHERE role = 'admin'").fetchone()
    if existing:
        conn.close()
        return
    admin_email = os.environ.get("PROOFWORK_ADMIN_EMAIL", "damilolakehinde575@gmail.com").strip().lower()
    admin_pw = os.environ.get("PROOFWORK_ADMIN_PASSWORD", "Damsi@123")
    conn.execute(
        "INSERT INTO users (email, password_hash, name, role, city, created_at) VALUES (?, ?, ?, 'admin', 'Lagos', ?)",
        (admin_email, generate_password_hash(admin_pw), "Damilola Kehinde", now()),
    )
    cur = conn.execute(
        "INSERT INTO users (email, password_hash, name, role, phone, city, created_at) VALUES (?, ?, ?, 'master', ?, ?, ?)",
        ("ada@workshop.test", generate_password_hash("demo1234"), "Ada Okonkwo", "08030001111", "Enugu", now()),
    )
    master_id = cur.lastrowid
    conn.execute(
        "INSERT INTO workshops (master_id, name, trade, area, city, invite_code, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (master_id, "Ada Stitch House", "Tailoring", "Ogui Road", "Enugu", "ADA7K2", now()),
    )
    shop_id = conn.execute("SELECT id FROM workshops WHERE master_id = ?", (master_id,)).fetchone()["id"]
    cur = conn.execute(
        "INSERT INTO users (email, password_hash, name, role, phone, city, created_at) VALUES (?, ?, ?, 'apprentice', ?, ?, ?)",
        ("chidi@workshop.test", generate_password_hash("demo1234"), "Chidi Okeke", "08030002222", "Enugu", now()),
    )
    app_id = cur.lastrowid
    slug = slugify("Chidi Okeke", app_id)
    conn.execute("UPDATE users SET slug = ? WHERE id = ?", (slug, app_id))
    conn.execute(
        "INSERT INTO memberships (workshop_id, apprentice_id, joined_at) VALUES (?, ?, ?)",
        (shop_id, app_id, now()),
    )
    notes = [
        "Sewed a school uniform shirt",
        "Hemmed a pair of trousers",
        "Cut a wrapper pattern",
        "Fixed a torn sleeve",
        "Sewed a simple gown",
    ]
    for note in notes:
        conn.execute(
            "INSERT INTO tasks (apprentice_id, workshop_id, note, photo, status, review_note, created_at, reviewed_at) VALUES (?, ?, ?, NULL, 'approved', 'Good work', ?, ?)",
            (app_id, shop_id, note, now(), now()),
        )
    conn.commit()
    conn.close()


init_db()
seed()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5057")), debug=False)
