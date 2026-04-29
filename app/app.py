import os
import time
import subprocess
import json
import re
import hashlib
import base64
import binascii
import random
from functools import wraps
from urllib.parse import urlparse

import pymysql
import requests
from bson.objectid import ObjectId
from bson.errors import InvalidId
from flask import flash, Flask, jsonify, make_response, redirect, render_template, render_template_string, request, session, url_for
from lxml import etree
from pymongo import MongoClient
from pymongo.errors import OperationFailure
from pymysql.err import IntegrityError, OperationalError


def create_app():
    app = Flask(__name__)
    app.secret_key = os.getenv("FLASK_SECRET", "dev-secret")

    mysql_conf = {
        "host": os.getenv("MYSQL_HOST", "localhost"),
        "user": os.getenv("MYSQL_USER", "vulnshop"),
        "password": os.getenv("MYSQL_PASSWORD", "vulnshop"),
        "database": os.getenv("MYSQL_DB", "vulnshop"),
        "autocommit": True,
        "cursorclass": pymysql.cursors.DictCursor,
    }
    mysql_state = {"conn": None}

    mongo = MongoClient(os.getenv("MONGO_URL", "mongodb://localhost:27017"))
    reviews = mongo.vulnshop.reviews
    payment_cards = mongo.vulnshop.payment_cards

    def mysql_conn():
        conn = mysql_state.get("conn")
        if conn is not None:
            try:
                conn.ping(reconnect=True)
                return conn
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
        conn = pymysql.connect(**mysql_conf)
        mysql_state["conn"] = conn
        return conn

    def seed_demo_reviews():
        demo_authors = ["alice", "bob", "charlie", "diana", "eve", "frank"]
        demo_texts = [
            "Great quality for the price.",
            "Works exactly as expected.",
            "Packaging was excellent and shipping was fast.",
            "Good choice for everyday usage.",
            "I would buy this again.",
            "Could be better, but still decent.",
        ]
        try:
            with mysql_conn().cursor() as cur:
                cur.execute("SELECT id,name FROM products ORDER BY id LIMIT 24")
                products = cur.fetchall()
        except OperationalError:
            return False
        for product in products:
            existing = reviews.count_documents({"product_id": product["id"]})
            if existing >= 3:
                continue
            to_insert = []
            for _ in range(3 - existing):
                to_insert.append(
                    {
                        "product_id": product["id"],
                        "product": product["name"],
                        "author": random.choice(demo_authors),
                        "rating": random.randint(3, 5),
                        "text": random.choice(demo_texts),
                        "status": random.choice(["approved", "approved", "pending"]),
                        "created_at": int(time.time()) - random.randint(0, 86400 * 60),
                    }
                )
            if to_insert:
                reviews.insert_many(to_insert)
        return True

    def seed_payment_cards():
        if payment_cards.count_documents({}) > 0:
            return
        payment_cards.insert_many(
            [
                {
                    "user_id": 1,
                    "username": "admin",
                    "cardholder": "Admin River North",
                    "card_number": "4111-1111-1111-1111",
                    "exp": "12/30",
                    "cvv": "999",
                    "created_at": int(time.time()) - 3600,
                },
                {
                    "user_id": 2,
                    "username": "alice",
                    "cardholder": "Alice Hightower",
                    "card_number": "5555-4444-3333-1111",
                    "exp": "08/29",
                    "cvv": "123",
                    "created_at": int(time.time()) - 1800,
                },
            ]
        )

    startup_state = {"reviews_seeded": seed_demo_reviews()}
    seed_payment_cards()
    login_attempts_by_user = {}
    login_attempt_threshold = 25000
    login_block_seconds = 300
    otp_attempts_by_user = {}
    otp_attempt_threshold = 5
    otp_block_seconds = 60
    otp_window_state = {"window": None}

    @app.before_request
    def ensure_reviews_seeded():
        if startup_state["reviews_seeded"]:
            sync_all_twofa_codes()
            return
        startup_state["reviews_seeded"] = seed_demo_reviews()
        sync_all_twofa_codes()

    def login_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not session.get("user_id"):
                pending_uid = session.get("pre_2fa_user")
                if pending_uid and request.path == "/account/dashboard":
                    with mysql_conn().cursor() as cur:
                        cur.execute("SELECT id,username,role FROM users WHERE id=%s", (pending_uid,))
                        pending_user = cur.fetchone()
                    if pending_user:
                        session["user_id"] = pending_user["id"]
                        session["username"] = pending_user["username"]
                        session["role"] = pending_user["role"]
                        session["active"] = True
                        session.pop("pre_2fa_user", None)
                        reset_login_rate_limit(pending_user.get("username"))
                        reset_otp_rate_limit(pending_user.get("username"))
                        resp = make_response(fn(*args, **kwargs))
                        resp.set_cookie("role", encode_role_cookie(pending_user.get("role", "user")))
                        return resp
                return redirect(url_for("login"))
            return fn(*args, **kwargs)

        return wrapper

    def encode_role_cookie(role):
        return base64.b64encode((role or "user").encode()).decode()

    def role_from_cookie():
        raw = request.cookies.get("role", "")
        if not raw:
            return "user"
        try:
            decoded = base64.b64decode(raw.encode(), validate=True).decode().strip().lower()
        except (ValueError, binascii.Error, UnicodeDecodeError):
            return "user"
        return decoded if decoded in {"user", "admin"} else "user"

    def admin_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not session.get("user_id") or not session.get("active"):
                return redirect(url_for("login"))
            if role_from_cookie() != "admin":
                flash("Admin access required.", "error")
                return redirect(url_for("dashboard")), 403
            return fn(*args, **kwargs)

        return wrapper

    def admin_ip_allowed():
        admin_ip = "176.105.200.130"
        forwarded_for = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        forwarded_host = (request.headers.get("X-Forwarded-Host") or "").split(",")[0].strip()
        host_candidate = forwarded_host or (request.host or "").split(",")[0].strip()
        host_ip = host_candidate.split(":")[0]
        client_ip = forwarded_for.split(":")[0]
        return (host_ip == admin_ip) or (client_ip == admin_ip), admin_ip

    def has_empty(*values):
        return any(not (v or "").strip() for v in values)

    def reset_login_rate_limit(username):
        key = (username or "").strip().lower()
        if not key:
            return
        login_attempts_by_user[key] = {"attempts": 0, "blocked_until": 0}

    def reset_otp_rate_limit(username):
        key = (username or "").strip().lower()
        if not key:
            return
        otp_attempts_by_user[key] = {"attempts": 0, "blocked_until": 0}

    def check_login_rate_limit(username):
        key = (username or "").strip().lower()
        now = int(time.time())
        slot = login_attempts_by_user.setdefault(key, {"attempts": 0, "blocked_until": 0})
        if slot["blocked_until"] > now:
            return slot["blocked_until"] - now
        if slot["blocked_until"] and slot["blocked_until"] <= now:
            slot["attempts"] = 0
            slot["blocked_until"] = 0
        slot["attempts"] += 1
        if slot["attempts"] > login_attempt_threshold:
            slot["attempts"] = 0
            slot["blocked_until"] = now + login_block_seconds
            return login_block_seconds
        return 0

    def check_otp_rate_limit(username):
        key = (username or "").strip().lower()
        now = int(time.time())
        slot = otp_attempts_by_user.setdefault(key, {"attempts": 0, "blocked_until": 0})
        if slot["blocked_until"] > now:
            return slot["blocked_until"] - now
        if slot["blocked_until"] and slot["blocked_until"] <= now:
            slot["attempts"] = 0
            slot["blocked_until"] = 0
        slot["attempts"] += 1
        if slot["attempts"] > otp_attempt_threshold:
            slot["attempts"] = 0
            slot["blocked_until"] = now + otp_block_seconds
            return otp_block_seconds
        return 0

    def maybe_json(value):
        value = (value or "").strip()
        if value.startswith("{") and value.endswith("}"):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        return value

    def looks_like_nosqli_probe(value):
        probe = (value or "").strip()
        if not probe:
            return False
        probe_tokens = ["$foo", "\\x", ";$foo}", "\"'`{", "{\\n", "$ne", "$gt", "$regex", "$where"]
        lowered = probe.lower()
        return any(token in lowered for token in probe_tokens)

    def rolling_otp(seed, moment=None):
        now = int(moment or time.time())
        window = now // 600
        digest = hashlib.sha256(f"{seed}:{window}:{app.secret_key}".encode()).hexdigest()
        return f"{int(digest[:8], 16) % 10000:04d}"

    def refresh_user_otp_code(user):
        if not user:
            return ""
        seed = f"{user.get('username', '')}:{user.get('id', '')}"
        current_code = rolling_otp(seed)
        with mysql_conn().cursor() as cur:
            cur.execute("UPDATE users SET twofa_secret=%s WHERE id=%s", (current_code, user["id"]))
        user["twofa_secret"] = current_code
        return current_code

    def sync_all_twofa_codes():
        now_window = int(time.time()) // 600
        if otp_window_state["window"] == now_window:
            return
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT id,username FROM users ORDER BY id")
            users = cur.fetchall()
            for u in users:
                seed = f"{u.get('username', '')}:{u.get('id', '')}"
                code = rolling_otp(seed)
                cur.execute("UPDATE users SET twofa_secret=%s WHERE id=%s", (code, u["id"]))
        otp_window_state["window"] = now_window

    def hash_password(raw_password):
        return hashlib.md5((raw_password or "").encode()).hexdigest()

    def password_policy_errors(password):
        issues = []
        if len(password) < 10:
            issues.append("minimum length is 10 characters")
        if not re.search(r"[A-Z]", password):
            issues.append("at least one upper-case character")
        if not re.search(r"[a-z]", password):
            issues.append("at least one lower-case character")
        if not re.search(r"[0-9]", password):
            issues.append("at least one digit")
        return issues

    @app.route("/")
    def index():
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT id,name,description,price,category FROM products ORDER BY id DESC LIMIT 30")
            products = cur.fetchall()
            cur.execute("SELECT DISTINCT category FROM products ORDER BY category")
            categories = [row["category"] for row in cur.fetchall()]
        return render_template(
            "index.html",
            products=products,
            categories=categories,
            q="",
            selected_category="",
            user=session.get("username"),
            cart_count=len(session.get("cart", [])),
        )

    @app.route("/auth/logout")
    def logout():
        session.clear()
        resp = redirect(url_for("index"))
        resp.delete_cookie("role")
        return resp

    @app.route("/auth/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "").strip()
            if has_empty(username, email, password):
                flash("All registration fields are required.", "error")
                return render_template("register.html", cart_count=len(session.get("cart", []))), 400
            policy_issues = password_policy_errors(password)
            if policy_issues:
                flash("Password policy failed: " + ", ".join(policy_issues), "error")
                return render_template("register.html", cart_count=len(session.get("cart", []))), 400
            try:
                with mysql_conn().cursor() as cur:
                    cur.execute(
                        "INSERT INTO users (username,email,password) VALUES (%s,%s,%s)",
                        (username, email, hash_password(password)),
                    )
                flash("Registration completed.", "success")
                return redirect(url_for("login"))
            except IntegrityError:
                # Intentional enum vector: different response for existing usernames/emails.
                flash("User/email already exists.", "error")
                return render_template("register.html", cart_count=len(session.get("cart", []))), 409
        return render_template("register.html")

    @app.route("/auth/login", methods=["GET", "POST", "PUT"])
    def login():
        if request.method == "PUT":
            username = request.args.get("username")
            with mysql_conn().cursor() as cur:
                cur.execute("SELECT * FROM users WHERE username=%s", (username,))
                user = cur.fetchone()
            if user:
                session["pre_2fa_user"] = user["id"]
                return jsonify({"message": "PUT login accepted"})

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            if has_empty(username, password):
                flash("Username and password are required.", "error")
                return render_template("login.html", cart_count=len(session.get("cart", []))), 400
            retry_after = check_login_rate_limit(username)
            if retry_after > 0:
                flash(f"Too many login attempts for {username}. Try again in {retry_after} seconds.", "error")
                return render_template("login.html", cart_count=len(session.get("cart", []))), 429
            with mysql_conn().cursor() as cur:
                cur.execute("SELECT * FROM users WHERE username=%s", (username,))
                user = cur.fetchone()
            if not user:
                flash("User does not exist.", "error")
                return render_template("login.html", cart_count=len(session.get("cart", []))), 404
            if user["password"] != hash_password(password):
                flash("Wrong password.", "error")
                return render_template("login.html", cart_count=len(session.get("cart", []))), 401
            refresh_user_otp_code(user)
            session["pre_2fa_user"] = user["id"]
            return redirect(url_for("verify_2fa"))
        return render_template("login.html", cart_count=len(session.get("cart", [])))

    @app.route("/auth/2fa", methods=["GET", "POST"])
    def verify_2fa():
        uid = session.get("pre_2fa_user")
        if not uid:
            return redirect(url_for("login"))

        with mysql_conn().cursor() as cur:
            cur.execute("SELECT id,username,email,role,twofa_secret FROM users WHERE id=%s", (uid,))
            user = cur.fetchone()
        if not user:
            session.pop("pre_2fa_user", None)
            flash("2FA session expired. Please login again.", "error")
            return redirect(url_for("login"))
        otp_seed = refresh_user_otp_code(user)
        if not otp_seed:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["active"] = True
            session.pop("pre_2fa_user", None)
            reset_login_rate_limit(user.get("username"))
            reset_otp_rate_limit(user.get("username"))
            resp = redirect(url_for("dashboard"))
            resp.set_cookie("role", encode_role_cookie(user.get("role", "user")))
            return resp
        current_code = otp_seed

        if request.method == "POST":
            code = request.form.get("code", "").strip()
            retry_after = check_otp_rate_limit(user.get("username"))
            if retry_after > 0:
                return jsonify({"error": f"Too many OTP attempts. Try again in {retry_after} seconds."}), 429
            if has_empty(code):
                return jsonify({"error": "2FA code is required."}), 400
            if not re.fullmatch(r"\d{4}", code):
                return jsonify({"error": "2FA code must be exactly 4 digits."}), 400
            if code == current_code:
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                session["active"] = True
                session.pop("pre_2fa_user", None)
                reset_login_rate_limit(user.get("username"))
                reset_otp_rate_limit(user.get("username"))
                resp = redirect(url_for("dashboard"))
                resp.set_cookie("role", encode_role_cookie(user.get("role", "user")))
                return resp
            return jsonify({"error": "Invalid OTP code."}), 401

        return render_template("twofa.html", cart_count=len(session.get("cart", [])))

    @app.route("/admin.php")
    @admin_required
    def admin_php():
        allowed, admin_ip = admin_ip_allowed()
        if not allowed:
            return (
                render_template(
                    "notice.html",
                    title="Admin access blocked",
                    message=(
                        "Login detected from a non-admin IP. "
                        f"To open admin panel, use administrator IP {admin_ip}."
                    ),
                    kind="error",
                ),
                403,
            )
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT id,username,email,role FROM users ORDER BY id")
            users = cur.fetchall()
            cur.execute("SELECT id,user_id,total,created_at FROM orders ORDER BY id DESC LIMIT 20")
            orders = cur.fetchall()
            cur.execute("SELECT id,name FROM products ORDER BY id DESC LIMIT 20")
            products = cur.fetchall()
        pending_reviews = list(
            reviews.find(
                {"status": "pending"},
                {"_id": 1, "product": 1, "author": 1, "rating": 1, "text": 1, "created_at": 1},
            )
            .sort("created_at", -1)
            .limit(30)
        )
        return render_template(
            "admin.html",
            users=users,
            orders=orders,
            products=products,
            pending_reviews=pending_reviews,
            cart_count=len(session.get("cart", [])),
        )

    @app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
    @admin_required
    def admin_user_delete(user_id):
        if user_id == session.get("user_id"):
            flash("You cannot delete your own account from admin panel.", "error")
            return redirect(url_for("admin_php"))
        with mysql_conn().cursor() as cur:
            cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
        flash("User deleted.", "success")
        return redirect(url_for("admin_php"))

    @app.route("/admin/users/<int:user_id>/promote", methods=["POST"])
    @admin_required
    def admin_user_promote(user_id):
        with mysql_conn().cursor() as cur:
            cur.execute("UPDATE users SET role='admin' WHERE id=%s", (user_id,))
        flash("User role promoted to admin.", "success")
        return redirect(url_for("admin_php"))

    @app.route("/admin/users/<int:user_id>/demote", methods=["POST"])
    @admin_required
    def admin_user_demote(user_id):
        if user_id == session.get("user_id"):
            flash("You cannot demote your own account from admin panel.", "error")
            return redirect(url_for("admin_php"))
        with mysql_conn().cursor() as cur:
            cur.execute("UPDATE users SET role='user' WHERE id=%s", (user_id,))
        flash("User role demoted to user.", "success")
        return redirect(url_for("admin_php"))

    @app.route("/admin/users/<int:user_id>/password", methods=["POST"])
    @admin_required
    def admin_user_password_change(user_id):
        new_password = request.form.get("password", "").strip()
        if has_empty(new_password):
            flash("Password is required.", "error")
            return redirect(url_for("admin_php"))
        policy_issues = password_policy_errors(new_password)
        if policy_issues:
            flash("Password policy failed: " + ", ".join(policy_issues), "error")
            return redirect(url_for("admin_php"))
        with mysql_conn().cursor() as cur:
            cur.execute("UPDATE users SET password=%s WHERE id=%s", (hash_password(new_password), user_id))
        flash("User password changed.", "success")
        return redirect(url_for("admin_php"))

    @app.route("/admin/reviews/<review_id>/approve", methods=["POST"])
    @admin_required
    def admin_review_approve(review_id):
        try:
            oid = ObjectId(review_id)
        except InvalidId:
            flash("Invalid review id.", "error")
            return redirect(url_for("admin_php"))
        reviews.update_one({"_id": oid}, {"$set": {"status": "approved"}})
        flash("Review approved.", "success")
        return redirect(url_for("admin_php"))

    @app.route("/admin/reviews/<review_id>/reject", methods=["POST"])
    @admin_required
    def admin_review_reject(review_id):
        try:
            oid = ObjectId(review_id)
        except InvalidId:
            flash("Invalid review id.", "error")
            return redirect(url_for("admin_php"))
        reviews.update_one({"_id": oid}, {"$set": {"status": "rejected"}})
        flash("Review rejected.", "success")
        return redirect(url_for("admin_php"))

    @app.route("/auth/forgot", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            if has_empty(username):
                flash("Username is required.", "error")
                return render_template("forgot.html", cart_count=len(session.get("cart", []))), 400
            with mysql_conn().cursor() as cur:
                cur.execute("SELECT * FROM users WHERE username=%s", (username,))
                user = cur.fetchone()
                if not user:
                    # Intentional enum vector: explicit message if account does not exist.
                    flash("User not found.", "error")
                    return render_template("forgot.html", cart_count=len(session.get("cart", []))), 404
                token = f"{user['id']}{int(time.time())}"
                cur.execute("UPDATE users SET reset_token=%s WHERE id=%s", (token, user["id"]))
            flash("Reset link was sent to your email.", "success")
            return render_template("forgot.html", cart_count=len(session.get("cart", [])))
        return render_template("forgot.html", cart_count=len(session.get("cart", [])))

    @app.route("/auth/reset", methods=["GET", "POST"])
    def reset_password():
        token = request.args.get("token", "")
        if request.method == "POST":
            new_password = request.form.get("password", "").strip()
            if has_empty(new_password):
                flash("Password is required.", "error")
                return render_template("reset.html", token=token, cart_count=len(session.get("cart", []))), 400
            policy_issues = password_policy_errors(new_password)
            if policy_issues:
                flash("Password policy failed: " + ", ".join(policy_issues), "error")
                return render_template("reset.html", token=token, cart_count=len(session.get("cart", []))), 400
            with mysql_conn().cursor() as cur:
                cur.execute("UPDATE users SET password=%s WHERE reset_token=%s", (hash_password(new_password), token))
            return render_template("notice.html", title="Password updated", message="You can now login with your new password.", kind="success")
        return render_template("reset.html", token=token, cart_count=len(session.get("cart", [])))

    @app.route("/account/dashboard")
    @login_required
    def dashboard():
        uid = session.get("user_id")
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT id,username,email,role,bio FROM users WHERE id=%s", (uid,))
            user = cur.fetchone()
            cur.execute(
                "SELECT p.id,p.name,p.price FROM wishlists w JOIN products p ON p.id=w.product_id WHERE w.user_id=%s ORDER BY w.created_at DESC",
                (uid,),
            )
            wishlist_items = cur.fetchall()
        user["role"] = role_from_cookie()
        return render_template("dashboard.html", user=user, wishlist_items=wishlist_items, cart_count=len(session.get("cart", [])))

    @app.route("/account/orders/ids")
    @login_required
    def account_order_ids():
        uid = session.get("user_id")
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT id FROM orders WHERE user_id=%s ORDER BY id", (uid,))
            ids = [row["id"] for row in cur.fetchall()]
        return jsonify({"order_ids": ids})

    @app.route("/account/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        uid = session.get("user_id")
        if request.method == "POST":
            email = request.form.get("email", "").strip()
            bio = request.form.get("bio", "").strip()
            if has_empty(email):
                flash("Email is required.", "error")
                return render_template("profile.html", user={"email": email, "bio": bio}, cart_count=len(session.get("cart", []))), 400
            with mysql_conn().cursor() as cur:
                cur.execute("UPDATE users SET email=%s,bio=%s WHERE id=%s", (email, bio, uid))
            flash("Profile updated.", "success")
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT id,username,email,bio,role FROM users WHERE id=%s", (uid,))
            user = cur.fetchone()
        return render_template("profile.html", user=user, cart_count=len(session.get("cart", [])))

    @app.route("/shop/product/<int:pid>")
    def product_card(pid):
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT * FROM products WHERE id=%s", (pid,))
            product = cur.fetchone()
            cur.execute("SELECT * FROM products ORDER BY RAND() LIMIT 4")
            related = cur.fetchall()
        if not product:
            return "Product not found", 404
        published_reviews = list(
            reviews.find({"product_id": pid, "status": "approved"}, {"_id": 0})
            .sort("created_at", -1)
            .limit(15)
        )
        avg_rating = round(sum(r["rating"] for r in published_reviews) / len(published_reviews), 2) if published_reviews else None
        return render_template(
            "product.html",
            product=product,
            related=related,
            reviews=published_reviews,
            avg_rating=avg_rating,
            cart_count=len(session.get("cart", [])),
        )

    @app.route("/product/<int:pid>/reviews", methods=["POST"])
    @login_required
    def create_review(pid):
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT id,name FROM products WHERE id=%s", (pid,))
            product = cur.fetchone()
        if not product:
            return "Product not found", 404

        rating_raw = request.form.get("rating", "").strip()
        text = request.form.get("text", "").strip()
        if has_empty(rating_raw, text):
            flash("Rating and review text are required.", "error")
            return redirect(url_for("product_card", pid=pid))
        if not rating_raw.isdigit() or not 1 <= int(rating_raw) <= 5:
            flash("Rating must be an integer from 1 to 5.", "error")
            return redirect(url_for("product_card", pid=pid))

        reviews.insert_one(
            {
                "product_id": pid,
                "product": product["name"],
                "author": session.get("username", "guest"),
                "rating": int(rating_raw),
                "text": text,
                "status": "pending",
                "created_at": int(time.time()),
            }
        )
        flash("Review submitted and sent for moderation.", "success")
        return redirect(url_for("product_card", pid=pid))

    @app.route("/cart")
    def cart():
        ids = session.get("cart", [])
        items = []
        subtotal = 0.0
        if ids:
            placeholders = ",".join(["%s"] * len(ids))
            with mysql_conn().cursor() as cur:
                cur.execute(f"SELECT id,name,price FROM products WHERE id IN ({placeholders})", tuple(ids))
                items = cur.fetchall()
            subtotal = sum(float(item["price"]) for item in items)
        return render_template("cart.html", items=items, subtotal=subtotal, cart_count=len(ids))

    @app.route("/cart/add/<int:pid>")
    def cart_add(pid):
        cart_items = session.setdefault("cart", [])
        cart_items.append(pid)
        session["cart"] = cart_items
        return redirect(request.referrer or url_for("index"))

    @app.route("/wishlist")
    @login_required
    def wishlist():
        uid = session.get("user_id")
        with mysql_conn().cursor() as cur:
            cur.execute(
                "SELECT w.id,p.id AS product_id,p.name,p.price FROM wishlists w JOIN products p ON p.id=w.product_id WHERE w.user_id=%s ORDER BY w.created_at DESC",
                (uid,),
            )
            items = cur.fetchall()
        return render_template("wishlist.html", items=items, cart_count=len(session.get("cart", [])))

    @app.route("/wishlist/add/<int:pid>", methods=["POST"])
    @login_required
    def wishlist_add(pid):
        uid = session.get("user_id")
        with mysql_conn().cursor() as cur:
            cur.execute("INSERT INTO wishlists (user_id,product_id) VALUES (%s,%s)", (uid, pid))
        return redirect(request.referrer or url_for("wishlist"))

    @app.route("/wishlist/remove/<int:item_id>", methods=["POST"])
    @login_required
    def wishlist_remove(item_id):
        uid = session.get("user_id")
        with mysql_conn().cursor() as cur:
            cur.execute("DELETE FROM wishlists WHERE id=%s AND user_id=%s", (item_id, uid))
        return redirect(url_for("wishlist"))

    @app.route("/cart/remove/<int:pid>")
    def cart_remove(pid):
        cart_items = session.get("cart", [])
        if pid in cart_items:
            cart_items.remove(pid)
        session["cart"] = cart_items
        return redirect(url_for("cart"))

    @app.route("/cart/checkout", methods=["POST"])
    @login_required
    def checkout():
        ids = session.get("cart", [])
        if not ids:
            return redirect(url_for("cart"))
        cardholder = request.form.get("cardholder", "").strip()
        card_number = request.form.get("card_number", "").strip()
        exp = request.form.get("exp", "").strip()
        cvv = request.form.get("cvv", "").strip()
        if has_empty(cardholder, card_number, exp, cvv):
            flash("Cardholder, card number, exp and CVV are required for checkout.", "error")
            return redirect(url_for("cart"))
        placeholders = ",".join(["%s"] * len(ids))
        with mysql_conn().cursor() as cur:
            cur.execute(f"SELECT id,price FROM products WHERE id IN ({placeholders})", tuple(ids))
            products = cur.fetchall()
            total = sum(float(p["price"]) for p in products)
            for p in products:
                cur.execute(
                    "INSERT INTO orders (user_id,product_id,total,note) VALUES (%s,%s,%s,%s)",
                    (session.get("user_id"), p["id"], total, "checkout order"),
                )
        payment_cards.insert_one(
            {
                "user_id": session.get("user_id"),
                "username": session.get("username"),
                "cardholder": cardholder,
                "card_number": card_number,
                "exp": exp,
                "cvv": cvv,
                "created_at": int(time.time()),
            }
        )
        session["cart"] = []
        return redirect(url_for("dashboard"))

    @app.route("/orders/<order_id>")
    @login_required
    def order_view(order_id):
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT * FROM orders WHERE id=%s", (order_id,))
            row = cur.fetchone()
        return jsonify(row or {})

    @app.route("/support", methods=["GET", "POST"])
    @login_required
    def support():
        uid = session.get("user_id")
        if request.method == "POST":
            subject = request.form.get("subject", "").strip()
            message = request.form.get("message", "").strip()
            if has_empty(subject, message):
                flash("Subject and message are required.", "error")
                return render_template("support.html", tickets=[], cart_count=len(session.get("cart", []))), 400
            with mysql_conn().cursor() as cur:
                cur.execute(
                    "INSERT INTO support_tickets (user_id,subject,message) VALUES (%s,%s,%s)",
                    (uid, subject, message),
                )
            flash("Ticket created.", "success")
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT id,subject,status,created_at FROM support_tickets WHERE user_id=%s ORDER BY id DESC", (uid,))
            tickets = cur.fetchall()
        return render_template("support.html", tickets=tickets, cart_count=len(session.get("cart", [])))

    @app.route("/shop/brands")
    def shop_brands():
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT DISTINCT SUBSTRING_INDEX(name, ' ', 1) AS brand FROM products ORDER BY brand")
            brands = [row["brand"] for row in cur.fetchall()]
        return jsonify({"brands": brands})

    @app.route("/shop/deals")
    def shop_deals():
        category = request.args.get("category", "")
        with mysql_conn().cursor() as cur:
            if category:
                cur.execute(
                    "SELECT id,name,price,category FROM products WHERE category=%s ORDER BY price ASC LIMIT 20",
                    (category,),
                )
            else:
                cur.execute("SELECT id,name,price,category FROM products ORDER BY price ASC LIMIT 20")
            deals = cur.fetchall()
        return jsonify({"deals": deals, "category": category or "all"})

    @app.route("/account/addresses", methods=["GET", "POST"])
    @login_required
    def account_addresses():
        addresses = session.setdefault("addresses", [])
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            city = request.form.get("city", "").strip()
            street = request.form.get("street", "").strip()
            if has_empty(title, city, street):
                flash("Title, city and street are required.", "error")
                return render_template("addresses.html", addresses=addresses, cart_count=len(session.get("cart", []))), 400
            addresses.append({"title": title, "city": city, "street": street})
            session["addresses"] = addresses
            flash("Address saved.", "success")
        return render_template("addresses.html", addresses=addresses, cart_count=len(session.get("cart", [])))

    @app.route("/shipping/carrier/diagnostics", methods=["GET", "POST"])
    @login_required
    def shipping_carrier_diagnostics():
        output = None
        host = "carrier-gw.local"
        if request.method == "POST":
            host = request.form.get("host", "carrier-gw.local")
            output = subprocess.getoutput(f"ping -c 1 {host}")
        return render_template("shipping_diagnostics.html", output=output, host=host, cart_count=len(session.get("cart", [])))

    @app.route("/product/<int:pid>/reviews/moderation", methods=["GET", "POST"])
    @admin_required
    def reviews_moderation(pid):
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT id,name FROM products WHERE id=%s", (pid,))
            product = cur.fetchone()
        if not product:
            return "Product not found", 404

        allowed_nosql_ops = {"$where", "$ne", "$in", "$regex", "$options"}

        def sanitize_operator_dict(value):
            if not isinstance(value, dict):
                return value
            sanitized = {}
            for key, nested_value in value.items():
                if key.startswith("$") and key not in allowed_nosql_ops:
                    continue
                if isinstance(nested_value, dict):
                    sanitized[key] = sanitize_operator_dict(nested_value)
                else:
                    sanitized[key] = nested_value
            return sanitized

        def parse_text_filter(raw_value, *, contains=False):
            cleaned = (raw_value or "").strip()
            if not cleaned:
                return None
            parsed = maybe_json(cleaned)
            if isinstance(parsed, dict):
                return sanitize_operator_dict(parsed)
            if contains and isinstance(parsed, str):
                return {"$regex": parsed, "$options": "i"}
            return parsed

        def parse_rating_filter(raw_value):
            cleaned = (raw_value or "").strip()
            if not cleaned:
                return None
            parsed = maybe_json(cleaned)
            if isinstance(parsed, dict):
                parsed = sanitize_operator_dict(parsed)
                return parsed if parsed else None
            if isinstance(parsed, int):
                return parsed
            if isinstance(parsed, str) and parsed.isdigit():
                return int(parsed)
            return None

        def parse_card_number_filter(raw_value):
            cleaned = (raw_value or "").strip()
            if not cleaned:
                return None
            parsed = maybe_json(cleaned)
            if isinstance(parsed, dict):
                parsed = sanitize_operator_dict(parsed)
                return parsed if parsed else None
            if isinstance(parsed, str) and re.fullmatch(r"\d{4}-\d{4}-\d{4}-\d{4}", parsed):
                return parsed
            return None

        def apply_filter(query, field_name, parsed_filter):
            if parsed_filter is None:
                return
            if isinstance(parsed_filter, dict) and "$where" in parsed_filter:
                query["$where"] = parsed_filter["$where"]
                parsed_filter = {k: v for k, v in parsed_filter.items() if k != "$where"}
                if not parsed_filter:
                    return
            query[field_name] = parsed_filter

        base_review_query = {"product_id": pid}
        review_query = dict(base_review_query)
        review_results = []
        moderation_items = []

        author_input = request.values.get("author", "").strip()
        rating_input = request.values.get("rating", "").strip()
        text_input = request.values.get("text", "").strip()
        status_input = request.values.get("status", "pending").strip().lower() or "pending"
        card_number_input = request.values.get("card_number", "").strip()
        card_results = []
        filter_errors = []

        if request.method == "POST":
            action = request.form.get("action", "filter")
            if action in {"approve", "reject", "delete"}:
                review_id = request.form.get("review_id", "").strip()
                if review_id:
                    try:
                        oid = ObjectId(review_id)
                    except InvalidId:
                        flash("Invalid review id.", "error")
                        return redirect(url_for("reviews_moderation", pid=pid))
                    if action == "delete":
                        reviews.delete_one({"_id": oid, "product_id": pid})
                    else:
                        next_status = "approved" if action == "approve" else "rejected"
                        reviews.update_one({"_id": oid, "product_id": pid}, {"$set": {"status": next_status}})
                    flash("Review moderation action applied.", "success")
                return redirect(url_for("reviews_moderation", pid=pid))

        if status_input in {"pending", "approved", "rejected", "all"}:
            if status_input != "all":
                review_query["status"] = status_input
        else:
            status_input = "pending"
            review_query["status"] = status_input

        parsed_author = parse_text_filter(author_input, contains=True)
        parsed_text = parse_text_filter(text_input, contains=True)
        parsed_rating = parse_rating_filter(rating_input)

        if author_input and parsed_author is None:
            filter_errors.append("Author filter is invalid.")
        if text_input and parsed_text is None:
            filter_errors.append("Text filter is invalid.")
        if rating_input and parsed_rating is None:
            filter_errors.append("Rating must be an integer.")

        apply_filter(review_query, "author", parsed_author)
        apply_filter(review_query, "text", parsed_text)
        apply_filter(review_query, "rating", parsed_rating)

        if filter_errors:
            for msg in filter_errors:
                flash(msg, "error")
            moderation_items = list(
                reviews.find(base_review_query, {"_id": 1, "author": 1, "rating": 1, "text": 1, "status": 1, "created_at": 1})
                .sort("created_at", -1)
                .limit(40)
            )
            review_query_pretty = json.dumps(base_review_query, ensure_ascii=False, indent=2, default=str)
            search_results_pretty = json.dumps({"reviews": [], "cards": []}, ensure_ascii=False, indent=2, default=str)
            return render_template(
                "reviews_moderation.html",
                product=product,
                review_query=base_review_query,
                review_query_pretty=review_query_pretty,
                review_results=[],
                filter_author=author_input,
                filter_rating=rating_input,
                filter_text=text_input,
                filter_status=status_input,
                filter_card_number=card_number_input,
                search_results_pretty=search_results_pretty,
                moderation_items=moderation_items,
                cart_count=len(session.get("cart", [])),
            )

        review_results = list(reviews.find(review_query, {"_id": 0}).sort("created_at", -1).limit(50))
        moderation_items = list(
            reviews.find(review_query, {"_id": 1, "author": 1, "rating": 1, "text": 1, "status": 1, "created_at": 1})
            .sort("created_at", -1)
            .limit(40)
        )

        if card_number_input:
            parsed_card_number = parse_card_number_filter(card_number_input)
            if parsed_card_number is not None:
                card_query = {}
                apply_filter(card_query, "card_number", parsed_card_number)
                card_results = list(payment_cards.find(card_query, {"_id": 0}).limit(10))
            else:
                flash("Card number must be full (format: ####-####-####-####) or valid JSON filter.", "error")

        review_query_pretty = json.dumps(review_query, ensure_ascii=False, indent=2, default=str)
        search_results_pretty = json.dumps(
            {"reviews": review_results, "cards": card_results},
            ensure_ascii=False,
            indent=2,
            default=str,
        )

        return render_template(
            "reviews_moderation.html",
            product=product,
            review_query=review_query,
            review_query_pretty=review_query_pretty,
            review_results=review_results,
            filter_author=author_input,
            filter_rating=rating_input,
            filter_text=text_input,
            filter_status=status_input,
            filter_card_number=card_number_input,
            search_results_pretty=search_results_pretty,
            moderation_items=moderation_items,
            cart_count=len(session.get("cart", [])),
        )

    @app.route("/admin/pricing/rules/preview", methods=["GET", "POST"])
    @admin_required
    def pricing_rule_preview():
        expr = "(1299.99*0.92) + 49"
        result = None
        saved_rules = session.setdefault("pricing_rules", [])
        if request.method == "POST":
            expr = request.form.get("expr", expr)
            result = str(eval(expr))
            if request.form.get("action") == "save":
                title = request.form.get("title", "").strip() or f"Rule {len(saved_rules) + 1}"
                saved_rules.insert(0, {"title": title, "expr": expr, "result": result})
                session["pricing_rules"] = saved_rules[:20]
                flash("Rule saved to draft list.", "success")
        return render_template(
            "pricing_rule_preview.html",
            expr=expr,
            result=result,
            saved_rules=saved_rules,
            cart_count=len(session.get("cart", [])),
        )

    @app.route("/admin/catalog/import/xml", methods=["GET", "POST"])
    @admin_required
    def admin_catalog_import_xml():
        xml_payload = "<products><item><name>Sample</name></item></products>"
        parsed = None
        imported_items = []
        if request.method == "POST":
            xml_payload = request.form.get("xml_payload", xml_payload)
            parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
            root = etree.fromstring(xml_payload.encode(), parser=parser)
            parsed = {"root": root.tag, "text": root.text}
            for item in root.findall(".//item"):
                imported_items.append(
                    {
                        "name": (item.findtext("name") or "").strip() or "Untitled",
                        "price": (item.findtext("price") or "0").strip(),
                    }
                )
        return render_template(
            "catalog_import_xml.html",
            xml_payload=xml_payload,
            parsed=parsed,
            imported_items=imported_items,
            cart_count=len(session.get("cart", [])),
        )

    @app.route("/admin/marketing/email/preview", methods=["GET", "POST"])
    @admin_required
    def marketing_email_preview():
        tpl = "<h2>{{user}}, your gadgets are waiting</h2>"
        user = session.get("username", "guest")
        html = None
        drafts = session.setdefault("campaign_drafts", [])
        if request.method == "POST":
            tpl = request.form.get("tpl", tpl)
            user = request.form.get("user", user)
            html = render_template_string(tpl, user=user, session=session)
            if request.form.get("action") == "save":
                subject = request.form.get("subject", "").strip() or f"Campaign {len(drafts) + 1}"
                drafts.insert(0, {"subject": subject, "user": user, "tpl": tpl})
                session["campaign_drafts"] = drafts[:20]
                flash("Campaign draft saved.", "success")
        return render_template(
            "marketing_email_preview.html",
            tpl=tpl,
            user=user,
            html=html,
            drafts=drafts,
            cart_count=len(session.get("cart", [])),
        )

    @app.route("/products/search")
    def products_search():
        q = request.args.get("q", "")
        category = request.args.get("category", "")
        category_clause = category or "%"
        sql = (
            "SELECT id,name,description,price,category FROM products "
            "WHERE name LIKE %s "
            f"AND category LIKE '{category_clause}' ORDER BY id DESC"
        )
        with mysql_conn().cursor() as cur:
            cur.execute(sql, (f"%{q}%",))
            products = cur.fetchall()
            cur.execute("SELECT DISTINCT category FROM products ORDER BY category")
            categories = [row["category"] for row in cur.fetchall()]
        return render_template(
            "index.html",
            products=products,
            categories=categories,
            q=q,
            selected_category=category,
            user=session.get("username"),
            cart_count=len(session.get("cart", [])),
        )

    @app.route("/products/<pid>")
    def product_by_id(pid):
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT * FROM products WHERE id=%s", (pid,))
            product = cur.fetchone()
        return jsonify(product or {})

    @app.route("/api/stock")
    def stock_check():
        pid = request.args.get("id", "1")
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT %s AS status", ("in-stock" if str(pid).isdigit() and int(pid) > 0 else "out",))
            row = cur.fetchone()
        return jsonify({"status": row.get("status")})

    @app.route("/api/shipping")
    def shipping_quote():
        postal = request.args.get("zip", "10000")
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT 1 AS delayed")
            cur.fetchone()
        return jsonify({"quote": 14.99, "zip": postal})

    @app.route("/admin/reports")
    @admin_required
    def admin_reports():
        username_filter = request.args.get("u", "")
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT bio FROM users WHERE username=%s", (username_filter,))
            row = cur.fetchone()
            snippet = row["bio"] if row else ""
            cur.execute("SELECT * FROM orders WHERE note LIKE %s", (f"%{snippet}%",))
            rows = cur.fetchall()
        return jsonify({"orders": rows})

    @app.route("/files/upload", methods=["GET", "POST"])
    @login_required
    def upload_file():
        if request.method == "POST":
            f = request.files.get("file")
            if not f:
                return "no file", 400
            filename = f.filename
            if ".php" in filename:
                return "blocked by blacklist", 400
            if not (filename.endswith(".jpg") or filename.endswith(".png") or filename.endswith(".txt") or filename.endswith(".php5")):
                return "extension not allowed", 400
            if len(f.read()) > 1024 * 1024:
                return "too large", 400
            f.stream.seek(0)
            save_path = os.path.join("app/static/uploads", filename)
            f.save(save_path)
            suspicious = any(x in filename.lower() for x in [".php5", ".phtml", "..", ".jpg.php"])
            return f"uploaded to /static/uploads/{filename}" + (" | upload-bypass-pattern" if suspicious else "")
        return render_template("upload.html")

    @app.route("/pages")
    def include_page():
        page = request.args.get("page", "home.html")
        path = os.path.join("app/templates/pages", page)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = f.read()
                if "../" in page:
                    data += "<!-- traversal-pattern -->"
                return data
        except FileNotFoundError:
            return "not found", 404

    @app.route("/remote/include")
    def remote_include():
        url = request.args.get("url", "https://example.com")
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"]:
            return "bad scheme", 400
        content = requests.get(url, timeout=3).text
        injected = "example.com" not in parsed.netloc
        return render_template_string(content) + ("<!-- rfi-pattern -->" if injected else "")

    @app.route("/openapi.json")
    def openapi():
        spec = {
            "openapi": "3.0.3",
            "info": {"title": "VulnShop API", "version": "1.0.0"},
            "servers": [{"url": "/"}],
            "paths": {
                "/products/search": {"get": {"summary": "Search products (single SQLi demo point)", "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}, {"name": "category", "in": "query", "schema": {"type": "string"}}], "responses": {"200": {"description": "ok"}}}},
                "/auth/login": {"post": {"summary": "Login", "responses": {"200": {"description": "ok"}}}, "put": {"summary": "Verb tampering demo", "responses": {"200": {"description": "ok"}}}},
                "/auth/register": {"post": {"summary": "Register user", "responses": {"200": {"description": "ok"}}}},
                "/auth/forgot": {"post": {"summary": "Forgot password", "responses": {"200": {"description": "ok"}}}},
                "/shop/brands": {"get": {"summary": "List shop brands", "responses": {"200": {"description": "ok"}}}},
                "/shop/deals": {"get": {"summary": "Current deals", "responses": {"200": {"description": "ok"}}}},
                "/account/addresses": {"get": {"summary": "Address book", "responses": {"200": {"description": "ok"}}}, "post": {"summary": "Add address", "responses": {"200": {"description": "ok"}}}},
                "/account/orders/ids": {"get": {"summary": "Current user order ids", "responses": {"200": {"description": "ok"}}}},
                "/shipping/carrier/diagnostics": {"get": {"summary": "Carrier diagnostics page", "responses": {"200": {"description": "ok"}}}, "post": {"summary": "Run carrier diagnostics", "responses": {"200": {"description": "ok"}}}},
                "/product/{pid}/reviews": {"post": {"summary": "Create product review", "responses": {"200": {"description": "ok"}}}},
                "/product/{pid}/reviews/moderation": {"get": {"summary": "Reviews moderation dashboard", "responses": {"200": {"description": "ok"}}}, "post": {"summary": "Reviews moderation actions/filter", "responses": {"200": {"description": "ok"}}}},
                "/admin/pricing/rules/preview": {"post": {"summary": "Pricing rule preview", "responses": {"200": {"description": "ok"}}}},
                "/admin/catalog/import/xml": {"post": {"summary": "Catalog XML import", "responses": {"200": {"description": "ok"}}}},
                "/admin/marketing/email/preview": {"post": {"summary": "Marketing email preview", "responses": {"200": {"description": "ok"}}}},
                "/admin/users/{user_id}/delete": {"post": {"summary": "Delete user", "responses": {"200": {"description": "ok"}}}},
                "/admin/users/{user_id}/promote": {"post": {"summary": "Promote user to admin", "responses": {"200": {"description": "ok"}}}},
                "/admin/users/{user_id}/demote": {"post": {"summary": "Demote user to regular role", "responses": {"200": {"description": "ok"}}}},
                "/admin/users/{user_id}/password": {"post": {"summary": "Change user password", "responses": {"200": {"description": "ok"}}}},
                "/admin/reviews/{review_id}/approve": {"post": {"summary": "Approve pending review", "responses": {"200": {"description": "ok"}}}},
                "/admin/reviews/{review_id}/reject": {"post": {"summary": "Reject pending review", "responses": {"200": {"description": "ok"}}}},
                "/files/upload": {"post": {"summary": "Upload file", "responses": {"200": {"description": "ok"}}}},
                "/swagger": {"get": {"summary": "Swagger UI", "responses": {"200": {"description": "ok"}}}},
            },
        }
        return app.response_class(json.dumps(spec), mimetype="application/json")

    @app.route("/swagger")
    def swagger():
        return render_template("swagger.html", cart_count=len(session.get("cart", [])))

    return app
