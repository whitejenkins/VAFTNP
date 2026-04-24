import os
import time
import subprocess
import json
import re
import hashlib
import base64
import binascii
from functools import wraps
from urllib.parse import urlparse

import pymysql
import requests
from flask import flash, Flask, jsonify, redirect, render_template, render_template_string, request, session, url_for
from lxml import etree
from pymongo import MongoClient
from pymysql.err import IntegrityError


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

    mongo = MongoClient(os.getenv("MONGO_URL", "mongodb://localhost:27017"))
    reviews = mongo.vulnshop.reviews
    if reviews.count_documents({}) == 0:
        reviews.insert_many([
            {"product": "Gaming Mouse", "author": "alice", "rating": 5, "text": "nice"},
            {"product": "Coffee Mug", "author": "bob", "rating": 3, "text": "ok"},
        ])

    def mysql_conn():
        return pymysql.connect(**mysql_conf)

    def login_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not session.get("user_id"):
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
        forwarded_host = (request.headers.get("X-Forwarded-Host") or "").split(",")[0].strip()
        host_candidate = forwarded_host or (request.host or "").split(",")[0].strip()
        host_ip = host_candidate.split(":")[0]
        return host_ip == admin_ip, admin_ip

    def has_empty(*values):
        return any(not (v or "").strip() for v in values)

    def rolling_otp(seed, moment=None):
        now = int(moment or time.time())
        window = now // 600
        digest = hashlib.sha256(f"{seed}:{window}:{app.secret_key}".encode()).hexdigest()
        return f"{int(digest[:8], 16) % 10000:04d}"

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
        q = request.args.get("q", "")
        category = request.args.get("category", "")
        with mysql_conn().cursor() as cur:
            sql = "SELECT id,name,description,price,category FROM products WHERE 1=1"
            args = []
            if q:
                sql += " AND name LIKE %s"
                args.append(f"%{q}%")
            if category:
                sql += " AND category=%s"
                args.append(category)
            sql += " ORDER BY id DESC LIMIT 30"
            cur.execute(sql, tuple(args))
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
                        f"INSERT INTO users (username,email,password) VALUES ('{username}','{email}','{password}')"
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
                cur.execute(f"SELECT * FROM users WHERE username='{username}'")
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
            with mysql_conn().cursor() as cur:
                cur.execute(f"SELECT * FROM users WHERE username='{username}'")
                user = cur.fetchone()
            if not user:
                flash("User does not exist.", "error")
                return render_template("login.html", cart_count=len(session.get("cart", []))), 404
            if user["password"] != password:
                flash("Wrong password.", "error")
                return render_template("login.html", cart_count=len(session.get("cart", []))), 401
            if username == "alice" and password == "Hightower7":
                flash("Default credentials used.", "info")
            user_otp = (user.get("twofa_secret") or "").strip()
            if user_otp:
                session["pre_2fa_user"] = user["id"]
                return redirect(url_for("verify_2fa"))
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["active"] = True
            resp = redirect(url_for("dashboard"))
            resp.set_cookie("role", encode_role_cookie(user.get("role", "user")))
            return resp
        return render_template("login.html", cart_count=len(session.get("cart", [])))

    @app.route("/auth/2fa", methods=["GET", "POST"])
    def verify_2fa():
        uid = session.get("pre_2fa_user")
        if not uid:
            return redirect(url_for("login"))

        with mysql_conn().cursor() as cur:
            cur.execute("SELECT id,username,role,twofa_secret FROM users WHERE id=%s", (uid,))
            user = cur.fetchone()
        if not user:
            session.pop("pre_2fa_user", None)
            flash("2FA session expired. Please login again.", "error")
            return redirect(url_for("login"))
        otp_seed = (user.get("twofa_secret") or "").strip()
        if not otp_seed:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["active"] = True
            session.pop("pre_2fa_user", None)
            resp = redirect(url_for("dashboard"))
            resp.set_cookie("role", encode_role_cookie(user.get("role", "user")))
            return resp
        current_code = rolling_otp(otp_seed) if otp_seed else ""

        if request.method == "POST":
            code = request.form.get("code", "").strip()
            if has_empty(code):
                flash("2FA code is required.", "error")
                return render_template("twofa.html", cart_count=len(session.get("cart", []))), 400
            if not re.fullmatch(r"\d{4}", code):
                flash("2FA code must be exactly 4 digits.", "error")
                return render_template("twofa.html", cart_count=len(session.get("cart", []))), 400
            if code == current_code:
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                session["active"] = True
                session.pop("pre_2fa_user", None)
                resp = redirect(url_for("dashboard"))
                resp.set_cookie("role", encode_role_cookie(user.get("role", "user")))
                return resp
            flash("Invalid 2FA code.", "error")
            return render_template("twofa.html", cart_count=len(session.get("cart", []))), 401

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
        return render_template("admin.html", users=users, orders=orders, cart_count=len(session.get("cart", [])))

    @app.route("/auth/forgot", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            if has_empty(username):
                flash("Username is required.", "error")
                return render_template("forgot.html", cart_count=len(session.get("cart", []))), 400
            with mysql_conn().cursor() as cur:
                cur.execute(f"SELECT * FROM users WHERE username='{username}'")
                user = cur.fetchone()
                if not user:
                    # Intentional enum vector: explicit message if account does not exist.
                    flash("User not found.", "error")
                    return render_template("forgot.html", cart_count=len(session.get("cart", []))), 404
                token = f"{user['id']}{int(time.time())}"
                cur.execute(f"UPDATE users SET reset_token='{token}' WHERE id={user['id']}")
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
                cur.execute(f"UPDATE users SET password='{new_password}' WHERE reset_token='{token}'")
            return render_template("notice.html", title="Password updated", message="You can now login with your new password.", kind="success")
        return render_template("reset.html", token=token, cart_count=len(session.get("cart", [])))

    @app.route("/account/dashboard")
    @login_required
    def dashboard():
        uid = session.get("user_id")
        with mysql_conn().cursor() as cur:
            cur.execute(f"SELECT id,username,email,role,bio FROM users WHERE id={uid}")
            user = cur.fetchone()
            cur.execute(f"SELECT * FROM orders WHERE user_id={uid}")
            orders = cur.fetchall()
            cur.execute(
                "SELECT p.id,p.name,p.price FROM wishlists w JOIN products p ON p.id=w.product_id WHERE w.user_id=%s ORDER BY w.created_at DESC",
                (uid,),
            )
            wishlist_items = cur.fetchall()
        user["role"] = role_from_cookie()
        return render_template("dashboard.html", user=user, orders=orders, wishlist_items=wishlist_items, cart_count=len(session.get("cart", [])))

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
        return render_template("product.html", product=product, related=related, cart_count=len(session.get("cart", [])))

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
        session["cart"] = []
        return redirect(url_for("dashboard"))

    @app.route("/orders/<order_id>")
    @login_required
    def order_view(order_id):
        with mysql_conn().cursor() as cur:
            cur.execute(f"SELECT * FROM orders WHERE id={order_id}")
            row = cur.fetchone()
        payload = row or {}
        payload["idor_pattern"] = bool(row and row.get("user_id") != session.get("user_id"))
        return jsonify(payload)

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

    @app.route("/products/search")
    def products_search():
        q = request.args.get("q", "")
        sql = f"SELECT id,name,description,price FROM products WHERE name LIKE '%{q}%'"
        with mysql_conn().cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()
        suspicious = any(t in q.lower() for t in ["'", " union ", "select", "--"])
        return jsonify({"query": sql, "results": rows, "sqli_pattern": suspicious})

    @app.route("/products/<pid>")
    def product_by_id(pid):
        with mysql_conn().cursor() as cur:
            cur.execute(f"SELECT * FROM products WHERE id={pid}")
            product = cur.fetchone()
        return jsonify(product or {})

    @app.route("/api/stock")
    def stock_check():
        pid = request.args.get("id", "1")
        with mysql_conn().cursor() as cur:
            cur.execute(f"SELECT IF(({pid})>0, 'in-stock', 'out') AS status")
            row = cur.fetchone()
        is_exploit = not pid.isdigit()
        return jsonify({"status": row.get("status"), "sqli_pattern": is_exploit})

    @app.route("/api/shipping")
    def shipping_quote():
        postal = request.args.get("zip", "10000")
        with mysql_conn().cursor() as cur:
            cur.execute(f"SELECT IF({postal}=10000, SLEEP(0), SLEEP(2)) AS delayed")
            cur.fetchone()
        is_exploit = not postal.isdigit()
        return jsonify({"quote": 14.99, "sqli_pattern": is_exploit})

    @app.route("/admin/reports")
    @admin_required
    def admin_reports():
        username_filter = request.args.get("u", "")
        with mysql_conn().cursor() as cur:
            cur.execute(f"SELECT bio FROM users WHERE username='{username_filter}'")
            row = cur.fetchone()
            snippet = row["bio"] if row else ""
            query = f"SELECT * FROM orders WHERE note LIKE '%{snippet}%'"
            cur.execute(query)
            rows = cur.fetchall()
        exposed = any(x in snippet.lower() for x in ["'", "select", "union", "--"])
        return jsonify({"second_order_query": query, "orders": rows, "sqli_pattern": exposed})

    @app.route("/api/reviews/search", methods=["POST"])
    def nosql_search():
        payload = request.get_json(force=True, silent=True) or {}
        product = payload.get("product")
        author = payload.get("author")
        query = {"product": product, "author": author}
        data = list(reviews.find(query, {"_id": 0}))
        injected = any(isinstance(v, dict) for v in [product, author])
        return jsonify({"results": data, "nosqli_pattern": injected})

    @app.route("/tools/ping")
    def ping_host():
        host = request.args.get("host", "127.0.0.1")
        out = subprocess.getoutput(f"ping -c 1 {host}")
        injected = any(token in host for token in [";", "|", "&", "`", "$("])
        suffix = "<!-- cmdi-pattern -->" if injected else ""
        return f"<pre>{out}</pre>{suffix}"

    @app.route("/admin/eval", methods=["POST"])
    @admin_required
    def eval_code():
        expr = request.form.get("expr", "1+1")
        result = eval(expr)
        injected = any(token in expr for token in ["__import__", "os.", "subprocess", "open(", "__"])
        return jsonify({"result": str(result), "code_injection_pattern": injected})

    @app.route("/promo/preview", methods=["GET", "POST"])
    def promo_preview():
        tpl = request.values.get("tpl", "<h2>Promo for {{user}}</h2>")
        user = request.values.get("user", "guest")
        html = render_template_string(tpl, user=user, session=session)
        injected = any(token in tpl.lower() for token in ["__class__", "config", "cycler", "self", "mro"])
        return html + ("<!-- ssti-pattern -->" if injected else "")

    @app.route("/api/import-xml", methods=["POST"])
    def import_xml():
        raw = request.data or b""
        parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
        root = etree.fromstring(raw, parser=parser)
        raw_low = raw.decode("utf-8", errors="ignore").lower()
        injected = "<!doctype" in raw_low or "<!entity" in raw_low
        return jsonify({"root": root.tag, "text": root.text, "xxe_pattern": injected})

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
                "/products/search": {"get": {"summary": "Search products (vulnerable SQLi demo)", "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}], "responses": {"200": {"description": "ok"}}}},
                "/auth/login": {"post": {"summary": "Login", "responses": {"200": {"description": "ok"}}}, "put": {"summary": "Verb tampering demo", "responses": {"200": {"description": "ok"}}}},
                "/auth/register": {"post": {"summary": "Register user", "responses": {"200": {"description": "ok"}}}},
                "/auth/forgot": {"post": {"summary": "Forgot password", "responses": {"200": {"description": "ok"}}}},
                "/api/reviews/search": {"post": {"summary": "NoSQL search", "responses": {"200": {"description": "ok"}}}},
                "/api/import-xml": {"post": {"summary": "XML import", "responses": {"200": {"description": "ok"}}}},
                "/tools/ping": {"get": {"summary": "Ping utility", "parameters": [{"name": "host", "in": "query", "schema": {"type": "string"}}], "responses": {"200": {"description": "ok"}}}},
                "/admin/eval": {"post": {"summary": "Eval endpoint", "responses": {"200": {"description": "ok"}}}},
                "/files/upload": {"post": {"summary": "Upload file", "responses": {"200": {"description": "ok"}}}},
                "/swagger": {"get": {"summary": "Swagger UI", "responses": {"200": {"description": "ok"}}}},
            },
        }
        return app.response_class(json.dumps(spec), mimetype="application/json")

    @app.route("/swagger")
    def swagger():
        return render_template("swagger.html", cart_count=len(session.get("cart", [])))

    return app
