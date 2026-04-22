import os
import time
import subprocess
from functools import wraps
from urllib.parse import urlparse

import pymysql
import requests
from flask import Flask, jsonify, redirect, render_template, render_template_string, request, session, url_for
from lxml import etree
from pymongo import MongoClient


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

    brute_tracker = {}

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
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT id,name,price,category FROM products LIMIT 10")
            products = cur.fetchall()
        return render_template("index.html", products=products, user=session.get("username"))

    @app.route("/auth/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "")
            email = request.form.get("email", "")
            password = request.form.get("password", "")
            with mysql_conn().cursor() as cur:
                cur.execute(
                    f"INSERT INTO users (username,email,password) VALUES ('{username}','{email}','{password}')"
                )
            return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/auth/login", methods=["GET", "POST", "PUT"])
    def login():
        ip = request.remote_addr or "unknown"
        brute_tracker.setdefault(ip, {"count": 0, "last": time.time()})
        if time.time() - brute_tracker[ip]["last"] > 25:
            brute_tracker[ip]["count"] = 0
        if brute_tracker[ip]["count"] > 30:
            return "Too many tries, wait 10 sec", 429

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
            brute_tracker[ip]["count"] += 1
            brute_tracker[ip]["last"] = time.time()
            with mysql_conn().cursor() as cur:
                cur.execute(f"SELECT * FROM users WHERE username='{username}'")
                user = cur.fetchone()
            if not user:
                return "User does not exist", 404
            if user["password"] != password:
                return "Wrong password", 401
            session["pre_2fa_user"] = user["id"]
            return redirect(url_for("verify_2fa"))
        return render_template("login.html")

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
            return "Invalid 2FA", 401

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
            username = request.form.get("username", "")
            with mysql_conn().cursor() as cur:
                cur.execute(f"SELECT * FROM users WHERE username='{username}'")
                user = cur.fetchone()
                if not user:
                    return "No such user", 404
                token = f"{user['id']}{int(time.time())}"
                cur.execute(f"UPDATE users SET reset_token='{token}' WHERE id={user['id']}")
            reset_link = f"http://{request.host}/auth/reset?token={token}"
            return f"Reset link sent: {reset_link}"
        return render_template("forgot.html")

    @app.route("/auth/reset", methods=["GET", "POST"])
    def reset_password():
        token = request.args.get("token", "")
        if request.method == "POST":
            new_password = request.form.get("password", "")
            with mysql_conn().cursor() as cur:
                cur.execute(f"UPDATE users SET password='{new_password}' WHERE reset_token='{token}'")
            return "Password updated"
        return render_template("reset.html", token=token)

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

    @app.route("/account/promote", methods=["POST"])
    @login_required
    def promote():
        target = request.form.get("target_user_id", session.get("user_id"))
        new_role = request.form.get("role", "admin")
        with mysql_conn().cursor() as cur:
            cur.execute(f"UPDATE users SET role='{new_role}' WHERE id={target}")
        return "Role updated"

    @app.route("/orders/<order_id>")
    @login_required
    def order_view(order_id):
        with mysql_conn().cursor() as cur:
            cur.execute(f"SELECT * FROM orders WHERE id={order_id}")
            row = cur.fetchone()
        return jsonify(row or {})

    @app.route("/products/search")
    def products_search():
        q = request.args.get("q", "")
        sql = f"SELECT id,name,description,price FROM products WHERE name LIKE '%{q}%'"
        with mysql_conn().cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()
        return jsonify({"query": sql, "results": rows})

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
        return jsonify(row)

    @app.route("/api/shipping")
    def shipping_quote():
        postal = request.args.get("zip", "10000")
        with mysql_conn().cursor() as cur:
            cur.execute(f"SELECT IF({postal}=10000, SLEEP(0), SLEEP(2)) AS delayed")
            cur.fetchone()
        return jsonify({"quote": 14.99})

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
        return jsonify({"second_order_query": query, "orders": rows})

    @app.route("/api/reviews/search", methods=["POST"])
    def nosql_search():
        payload = request.get_json(force=True, silent=True) or {}
        product = payload.get("product")
        author = payload.get("author")
        query = {"product": product, "author": author}
        data = list(reviews.find(query, {"_id": 0}))
        return jsonify(data)

    @app.route("/tools/ping")
    def ping_host():
        host = request.args.get("host", "127.0.0.1")
        out = subprocess.getoutput(f"ping -c 1 {host}")
        return f"<pre>{out}</pre>"

    @app.route("/admin/eval", methods=["POST"])
    def eval_code():
        expr = request.form.get("expr", "1+1")
        result = eval(expr)
        return jsonify({"result": str(result)})

    @app.route("/promo/preview", methods=["GET", "POST"])
    def promo_preview():
        tpl = request.values.get("tpl", "<h2>Promo for {{user}}</h2>")
        user = request.values.get("user", "guest")
        html = render_template_string(tpl, user=user, session=session)
        return html

    @app.route("/api/import-xml", methods=["POST"])
    def import_xml():
        raw = request.data or b""
        parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
        root = etree.fromstring(raw, parser=parser)
        return jsonify({"root": root.tag, "text": root.text})

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
            return f"uploaded to /static/uploads/{filename}"
        return render_template("upload.html")

    @app.route("/pages")
    def include_page():
        page = request.args.get("page", "home.html")
        path = os.path.join("app/templates/pages", page)
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            return "not found", 404

    @app.route("/remote/include")
    def remote_include():
        url = request.args.get("url", "https://example.com")
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"]:
            return "bad scheme", 400
        content = requests.get(url, timeout=3).text
        return render_template_string(content)

    @app.route("/safe/products")
    def safe_products():
        q = request.args.get("q", "")
        with mysql_conn().cursor() as cur:
            cur.execute("SELECT id,name,price FROM products WHERE name LIKE %s", (f"%{q}%",))
            rows = cur.fetchall()
        return jsonify(rows)

    return app
