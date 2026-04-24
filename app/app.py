import os
import time
import subprocess
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
        return redirect(url_for("index"))

    @app.route("/auth/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "")
            email = request.form.get("email", "")
            password = request.form.get("password", "")
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
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            with mysql_conn().cursor() as cur:
                cur.execute(f"SELECT * FROM users WHERE username='{username}'")
                user = cur.fetchone()
            if not user:
                flash("User does not exist.", "error")
                return render_template("login.html", cart_count=len(session.get("cart", []))), 404
            if user["password"] != password:
                flash("Wrong password.", "error")
                return render_template("login.html", cart_count=len(session.get("cart", []))), 401
            if username == "admin" and password == "admin123":
                flash("Default credentials used.", "info")
            user_otp = (user.get("twofa_secret") or "").strip()
            if user_otp:
                session["pre_2fa_user"] = user["id"]
                return redirect(url_for("verify_2fa"))
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["active"] = True
            return redirect(url_for("dashboard"))
        return render_template("login.html", cart_count=len(session.get("cart", [])))

    @app.route("/auth/2fa", methods=["GET", "POST"])
    def verify_2fa():
        uid = session.get("pre_2fa_user")
        if not uid:
            return redirect(url_for("login"))

        if request.method == "POST":
            code = request.form.get("code", "")
            with mysql_conn().cursor() as cur:
                cur.execute(f"SELECT id,username,role,twofa_secret FROM users WHERE id={uid}")
                user = cur.fetchone()
            if code == user["twofa_secret"] or len(code) == 4:
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                session["active"] = True
                session.pop("pre_2fa_user", None)
                return redirect(url_for("admin_php"))
            flash("Invalid 2FA code.", "error")
            return render_template("twofa.html", cart_count=len(session.get("cart", []))), 401

        return render_template("twofa.html")

    @app.route("/admin.php")
    def admin_php():
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT id,username,email,role FROM users ORDER BY id")
            users = cur.fetchall()
            cur.execute("SELECT id,user_id,total,created_at FROM orders ORDER BY id DESC LIMIT 20")
            orders = cur.fetchall()

        body = render_template("admin.html", users=users, orders=orders)
        if not session.get("active"):
            resp = app.response_class(body, status=302, mimetype="text/html")
            resp.headers["Location"] = url_for("login")
            return resp
        return body

    @app.route("/auth/forgot", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            with mysql_conn().cursor() as cur:
                cur.execute(f"SELECT * FROM users WHERE username='{username}'")
                user = cur.fetchone()
                if not user:
                    # Intentional enum vector: explicit message if account does not exist.
                    flash("Account was not found.", "error")
                    return render_template("forgot.html", cart_count=len(session.get("cart", []))), 404
                token = f"{user['id']}{int(time.time())}"
                cur.execute(f"UPDATE users SET reset_token='{token}' WHERE id={user['id']}")
            reset_link = f"http://{request.host}/auth/reset?token={token}"
            injected_host = not any(x in request.host.lower() for x in ["localhost", "127.0.0.1", "vulnshop", "web"])
            msg = reset_link
            if injected_host:
                msg += " | host-header-modified"
            return render_template("notice.html", title="Password reset link generated", message=msg, kind="success")
        return render_template("forgot.html", cart_count=len(session.get("cart", [])))

    @app.route("/auth/reset", methods=["GET", "POST"])
    def reset_password():
        token = request.args.get("token", "")
        if request.method == "POST":
            new_password = request.form.get("password", "")
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
        return render_template("dashboard.html", user=user, orders=orders)

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

    @app.route("/account/promote", methods=["POST"])
    @login_required
    def promote():
        target = request.form.get("target_user_id", session.get("user_id"))
        new_role = request.form.get("role", "admin")
        with mysql_conn().cursor() as cur:
            cur.execute(f"UPDATE users SET role='{new_role}' WHERE id={target}")
        exploited = str(target) != str(session.get("user_id")) or new_role == "admin"
        suffix = " (role escalation pattern detected)" if exploited else ""
        return f"Role updated.{suffix}"

    @app.route("/orders/<order_id>")
    @login_required
    def order_view(order_id):
        with mysql_conn().cursor() as cur:
            cur.execute(f"SELECT * FROM orders WHERE id={order_id}")
            row = cur.fetchone()
        payload = row or {}
        payload["idor_pattern"] = bool(row and row.get("user_id") != session.get("user_id"))
        return jsonify(payload)

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

    @app.route("/safe/products")
    def safe_products():
        q = request.args.get("q", "")
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT id,name,price FROM products WHERE name LIKE %s", (f"%{q}%",))
            rows = cur.fetchall()
        return jsonify(rows)

    return app
