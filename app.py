from flask import (
    Flask, render_template, redirect, url_for,
    request, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import os

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
load_dotenv()
from flask_wtf.csrf import CSRFProtect, generate_csrf


import random
import smtplib
import time
from email.message import EmailMessage
import qrcode
from io import BytesIO
from base64 import b64encode



# --- read envs (already have load_dotenv earlier) ---
EMAIL_HOST = os.environ.get("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", 587))
EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASS = os.environ.get("EMAIL_PASS")

UPI_ID = os.environ.get("UPI_ID", "yourupi@bank")
UPI_NAME = os.environ.get("UPI_NAME", "Bhavna Herbal Care")

# --- OTP helpers ---
OTP_TTL_SECONDS = 5 * 60  # 5 minutes

def gen_otp():
    """Return 6-digit string OTP."""
    return f"{random.randint(0, 999999):06d}"

def send_email_otp(to_email, otp):
    """Send OTP to user's gmail via SMTP."""
    if not EMAIL_USER or not EMAIL_PASS:
        raise RuntimeError("EMAIL_USER / EMAIL_PASS not configured")

    msg = EmailMessage()
    msg["Subject"] = "Your Herbalytix Care login OTP"
    msg["From"] = EMAIL_USER
    msg["To"] = to_email
    msg.set_content(f"Your OTP for Herbalytix Care is: {otp}\nIt is valid for {OTP_TTL_SECONDS//60} minutes.\nIf you did not request this, ignore this email.")

    # send via TLS
    with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)

def make_upi_qr_data_uri(upi_id, payee_name, amount=None):
    """
    Build UPI URI and generate QR code PNG and return data URI (base64).
    If amount provided, include it in UPI URI.
    """
    # UPI intent format
    u = f"upi://pay?pa={upi_id}&pn={payee_name}&cu=INR"
    if amount:
        # amount must be float/string with two decimals
        u += f"&am={amount}"
    # build QR
    img = qrcode.make(u)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    b64 = b64encode(buffered.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{b64}", u

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

db = SQLAlchemy()

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret"

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)





\
# app = Flask(__name__)
# app.config["SECRET_KEY"] = "dev-secret-key-change-later"



# ------------ CONFIG ------------
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL is None:
    raise RuntimeError("DATABASE_URL is not set")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgres://",
        "postgresql://",
        1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
import os

DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")


app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL




# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     email = db.Column(db.String(120), unique=True)

# class Product(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(100))

# ---------------- SECURITY CONFIG ---------------- #

# CSRF Protection
csrf = CSRFProtect(app)
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

# Secure Session Cookies
if os.environ.get("FLASK_ENV") == "production":
    app.config['SESSION_COOKIE_SECURE'] = True
else:
    app.config['SESSION_COOKIE_SECURE'] = False
        # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True        # JS cannot read cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'       # Prevent CSRF attacks

# Rate Limiter (prevents brute force attacks)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Force HTTPS (for production platforms like Render)
@app.before_request
def force_https():
    if request.headers.get("X-Forwarded-Proto") == "http":
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)



from datetime import datetime

# ----------------- Gmail-only OTP login flow -----------------

@app.route("/login_email", methods=["GET", "POST"])
def login_email():
    """
    Step 1: user enters Gmail address; we validate domain and send OTP.
    """
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        if not email.lower().endswith("@gmail.com"):
            flash("Please use a Gmail address (example@gmail.com).")
            return redirect(url_for("login_email"))

        # generate OTP and store in session (server-side)
        otp = gen_otp()
        session["otp_email"] = email
        session["otp_code"] = otp
        session["otp_expires"] = int(time.time()) + OTP_TTL_SECONDS
        session["otp_attempts"] = 0

        try:
            send_email_otp(email, otp)
        except Exception as e:
            # don't leak raw error in production — log it instead
            app.logger.exception("Failed to send OTP email")
            flash("Failed to send OTP. Check email configuration.")
            return redirect(url_for("login_email"))

        flash("OTP sent to your Gmail address. Check your inbox (and spam).")
        return redirect(url_for("verify_otp"))

    return render_template("login_email.html")


@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    # 🔒 session protection
    email = session.get("otp_email")
    otp_code = session.get("otp_code")

    if not email or not otp_code:
        flash("Session expired. Please login again.")
        return redirect(url_for("login_email"))

    if request.method == "POST":
        user_otp = request.form.get("otp")

        if user_otp == otp_code:
            user = User.query.filter_by(email=email).first()
            if not user:
                user = User(username=email.split("@")[0], email=email)
                db.session.add(user)
                db.session.commit()

            # clean session safely
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username

            return redirect(url_for("home"))

        flash("Invalid OTP. Try again.")

    return render_template("verify_otp.html", email=email)



# ------------ MODELS ------------
DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL is None:
    raise RuntimeError("DATABASE_URL is not set")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgres://",
        "postgresql://",
        1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

password_hash = db.Column(db.String(256), nullable=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    price = db.Column(db.Integer, nullable=False)      # INR
    ml = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(200), nullable=True)   # path under /static
    stock = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    customer_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.Text, nullable=False)
    city = db.Column(db.String(80), nullable=False)
    pincode = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending/packed/shipped
    total_amount = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    items = db.relationship("OrderItem", backref="order", lazy=True)


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Integer, nullable=False)

    product = db.relationship("Product")
class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.String(120))
    payment_id = db.Column(db.String(120))
    amount = db.Column(db.Float)
    method = db.Column(db.String(50))
    status = db.Column(db.String(50))


# ------------ ADMIN CONFIG ------------

# Admin credentials MUST come from environment variables in production.
# Provide defaults for local dev ONLY if you really want them.
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", None)

# If running in production and ADMIN_PASSWORD is not set, fail loudly
if os.environ.get("FLASK_ENV") == "production" and not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD environment variable is required in production")
@app.route("/admin/payments")
def admin_payments():
    payments = Payment.query.all()
    return render_template("admin_payments.html", payments=payments)


# ------------ HELPERS ------------

def get_cart():
    """Return cart dict from session: {product_id: quantity}"""
    cart = session.get("cart")
    if cart is None:
        cart = {}
        session["cart"] = cart
    return cart


def save_cart(cart):
    session["cart"] = cart
    session.modified = True


def cart_items_and_total():
    """Return list of (product, quantity, subtotal) and total amount."""
    cart = get_cart()
    items = []
    total = 0
    if not cart:
        return items, total

    product_ids = [int(pid) for pid in cart.keys()]
    products = Product.query.filter(Product.id.in_(product_ids)).all()
    products_by_id = {p.id: p for p in products}

    for pid_str, qty in cart.items():
        pid = int(pid_str)
        product = products_by_id.get(pid)
        if product:
            subtotal = product.price * qty
            items.append((product, qty, subtotal))
            total += subtotal

    return items, total


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Please login as admin.")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapper

    


# ------------ USER AUTH ------------

@app.route("/register", methods=["GET", "POST"])
def user_register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("Please fill all fields.")
            return redirect(url_for("user_register"))

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already exists.")
            return redirect(url_for("user_register"))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please login.")
        return redirect(url_for("user_login"))

    return render_template("user_register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def user_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            session["user_name"] = user.username
            flash("Logged in successfully.")
            return redirect(url_for("home"))

        flash("Invalid username or password.")
        return redirect(url_for("user_login"))

    return render_template("user_login.html")



@app.route("/logout")
def user_logout():
    session.pop("user_id", None)
    session.pop("user_name", None)
    flash("Logged out.")
    return redirect(url_for("home"))


# ------------ ADMIN AUTH ------------

@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["is_admin"] = True
            flash("Admin login successful.")
            return redirect(url_for("admin_products"))

        flash("Invalid admin credentials.")
        return redirect(url_for("admin_login"))

    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    flash("Admin logged out.")
    return redirect(url_for("admin_login"))


# ------------ SHOP PAGES ------------


@app.route("/")
def home():
    if not session.get("user_id"):
        return redirect(url_for("login_email"))
    products = Product.query.filter_by(is_active=True).order_by(Product.id.desc()).all()
    return render_template("home.html", products=products)


@app.route("/product/<int:product_id>")
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template("product_detail.html", product=product)


@app.route("/add-to-cart/<int:product_id>", methods=["POST"])
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    if product.stock <= 0:
        flash("This product is out of stock.")
        return redirect(url_for("product_detail", product_id=product.id))

    try:
        qty = int(request.form.get("quantity", 1))
        if qty < 1:
            qty = 1
    except ValueError:
        qty = 1

    cart = get_cart()
    current_qty = cart.get(str(product_id), 0)
    if current_qty + qty > product.stock:
        flash(f"Only {product.stock} item(s) available in stock.")
        return redirect(url_for("product_detail", product_id=product.id))

    cart[str(product_id)] = current_qty + qty
    save_cart(cart)
    flash("Added to cart.")
    return redirect(url_for("cart"))


@app.route("/cart", methods=["GET", "POST"])
def cart():
    # Update quantities / remove items via POST
    if request.method == "POST":
        cart = get_cart()
        action = request.form.get("action")
        pid = request.form.get("product_id")

        if action == "remove" and pid in cart:
            cart.pop(pid, None)
            save_cart(cart)
            flash("Item removed from cart.")
        elif action == "update" and pid in cart:
            try:
                qty = int(request.form.get("quantity", 1))
                if qty < 1:
                    cart.pop(pid, None)
                else:
                    cart[pid] = qty
                save_cart(cart)
                flash("Cart updated.")
            except ValueError:
                pass

    items, total = cart_items_and_total()
    return render_template("cart.html", items=items, total=total)

@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    items, total = cart_items_and_total()
    if not items:
        flash("Your cart is empty.")
        return redirect(url_for("home"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        city = request.form.get("city", "").strip()
        pincode = request.form.get("pincode", "").strip()

        if not all([name, phone, address, city, pincode]):
            flash("Please fill all required fields.")
            return redirect(url_for("checkout"))

        # Check stock again before creating order
        for product, qty, _ in items:
            if qty > product.stock:
                flash(f"Not enough stock for {product.name}.")
                return redirect(url_for("cart"))

        # Create order
        order = Order(
            user_id=session.get("user_id"),
            customer_name=name,
            email=email,
            phone=phone,
            address=address,
            city=city,
            pincode=pincode,
            total_amount=total,
            status="pending",
        )
        db.session.add(order)
        db.session.flush()  # get order.id without full commit yet

        # Create order items & reduce stock
        for product, qty, _ in items:
            item = OrderItem(
                order_id=order.id,
                product_id=product.id,
                quantity=qty,
                unit_price=product.price,
            )
            db.session.add(item)
            product.stock -= qty

        db.session.commit()

        # Clear cart
        session["cart"] = {}
        flash("Order placed successfully.")
        return render_template("success.html", order=order)

    return render_template("checkout.html", items=items, total=total)

@app.route("/pay_upi", methods=["GET"])
def pay_upi():
    # calculate total from cart
    items, total = cart_items_and_total()
    # generate QR data URI and upi uri
    qr_data_uri, upi_uri = make_upi_qr_data_uri(UPI_ID, UPI_NAME, amount=f"{total:.2f}" if total else None)
    return render_template("pay_upi.html", items=items, total=total, upi_id=UPI_ID, upi_uri=upi_uri, qr_data_uri=qr_data_uri)




# @app.route("/UPIcheckout", methods=["GET", "POST"])
# def UIPcheckout():
#     total_amount = session.get("cart_total", 199)

#     upi_link = (
#         f"upi://pay?pa={UPI_ID}"
#         f"&pn={MERCHANT_NAME}"
#         f"&am={total_amount}"
#         f"&cu=INR"
#     )

#     return render_template(
#         "checkout.html",
#         total=total_amount,
#         upi_id=UPI_ID,
#         upi_link=upi_link
#     )

# @app.route("/pay_upi", methods=["GET"])
# def pay_upi():
#     # calculate total from cart
#     items, total = cart_items_and_total()
#     # generate QR data URI and upi uri
#     qr_data_uri, upi_uri = make_upi_qr_data_uri(UPI_ID, UPI_NAME, amount=f"{total:.2f}" if total else None)
#     return render_template("pay_upi.html", items=items, total=total, upi_id=UPI_ID, upi_uri=upi_uri, qr_data_uri=qr_data_uri)
# UPI_ID = os.environ.get("UPI_ID")
# MERCHANT_NAME = os.environ.get("MERCHANT_NAME")

import razorpay
import os

RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")

razorpay_client = razorpay.Client(
    auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET)
)

@app.route("/create_payment")
def create_payment():
    items, total = cart_items_and_total()

    order = razorpay_client.order.create({
        "amount": int(total * 100),   # in paise
        "currency": "INR",
        "payment_capture": 1
    })

    return render_template(
        "razorpay_checkout.html",
        order_id=order["id"],
        amount=total,
        razorpay_key=RAZORPAY_KEY_ID
    )


# @app.route("/confirm_upi_payment", methods=["POST"])
# def confirm_upi_payment():
#     txn = request.form.get("txn", "").strip()
#     # In real app you'd verify txn via payment provider. For demo:
#     if not txn:
#         flash("Please enter transaction id.")
#         return redirect(url_for("pay_upi"))
#     # Create order like normal checkout but set status='paid' and store txn id
#     items, total = cart_items_and_total()
#     # ... create Order and OrderItems as in checkout route ...
#     # For brevity, you can call the existing checkout logic instead and add txn
#     flash("Payment confirmed (demo). We will verify and ship soon.")
#     # Clear cart
#     session["cart"] = {}
#     return redirect(url_for("home"))
@app.route("/confirm_upi_payment", methods=["GET", "POST"])
def confirm_upi_payment():
    if request.method == "POST":
        txn_id = request.form["txn_id"]
        total = session.get("cart_total")

        payment = Payment(
            amount=total,
            method="UPI",
            txn_id=txn_id,
            status="paid"
        )

        db.session.add(payment)
        db.session.commit()

        return "Payment saved successfully!"

    return render_template("confirm_payment.html", total=session.get("cart_total"))

# ------------ ADMIN: PRODUCTS ------------

@app.route("/admin/products")
@admin_required
def admin_products():
    products = Product.query.order_by(Product.id.desc()).all()
    return render_template("admin_products.html", products=products)


@app.route("/admin/products/new", methods=["GET", "POST"])
@admin_required
def admin_product_new():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        price = int(request.form.get("price", "0") or 0)
        ml = int(request.form.get("ml", "0") or 0)
        stock = int(request.form.get("stock", "0") or 0)
        description = request.form.get("description", "").strip()
        image = request.form.get("image", "").strip()   # e.g. /static/shampoo1.png
        is_active = bool(request.form.get("is_active"))

        if not name or price <= 0 or ml <= 0:
            flash("Name, price and ml are required.")
            return redirect(url_for("admin_product_new"))

        product = Product(
            name=name,
            price=price,
            ml=ml,
            stock=stock,
            description=description,
            image=image or "/static/shampoo.jpg",
            is_active=is_active,
        )
        db.session.add(product)
        db.session.commit()
        flash("Product created.")
        return redirect(url_for("admin_products"))

    return render_template("admin_product_form.html", product=None)


@app.route("/admin/products/<int:product_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_product_edit(product_id):
    product = Product.query.get_or_404(product_id)

    if request.method == "POST":
        product.name = request.form.get("name", "").strip()
        product.price = int(request.form.get("price", "0") or 0)
        product.ml = int(request.form.get("ml", "0") or 0)
        product.stock = int(request.form.get("stock", "0") or 0)
        product.description = request.form.get("description", "").strip()
        image = request.form.get("image", "").strip()
        product.image = image or product.image
        product.is_active = bool(request.form.get("is_active"))

        db.session.commit()
        flash("Product updated.")
        return redirect(url_for("admin_products"))

    return render_template("admin_product_form.html", product=product)


@app.route("/admin/products/<int:product_id>/delete", methods=["POST"])
@admin_required
def admin_product_delete(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash("Product deleted.")
    return redirect(url_for("admin_products"))


# ------------ ADMIN: ORDERS ------------

@app.route("/admin/orders")
@admin_required
def admin_orders():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template("admin_orders.html", orders=orders)


@app.route("/admin/orders/<int:order_id>")
@admin_required
def admin_order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    return render_template("admin_order_detail.html", order=order)


@app.route("/admin/orders/<int:order_id>/status", methods=["POST"])
@admin_required
def admin_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    status = request.form.get("status", "pending")
    order.status = status
    db.session.commit()
    flash("Order status updated.")
    return redirect(url_for("admin_order_detail", order_id=order.id))


# ------------ INIT DB & SEED ------------

def seed_products():
    """Create one demo product if no products exist."""
    if Product.query.count() == 0:
        demo = Product(
            name="HERBALYTRIX Shampoo – Strength & Shine",
            price=249,
            ml=200,
            stock=20,
            description=(
                "Gentle sulphate-free herbal shampoo with amla, bhringraj "
                "and aloe vera. Supports stronger roots, reduced hair fall "
                "and natural shine with regular use."
            ),
            image="shempoo.jpg",
            is_active=True,
        )
        db.session.add(demo)
        db.session.commit()
        print("Seeded demo product.")
@app.route("/payment_success")
def payment_success():
    payment_id = request.args.get("payment_id")
    items, total = cart_items_and_total()

    payment = Payment(
        amount=total,
        method="UPI",
        txn_id=payment_id,
        status="paid"
    )

    db.session.add(payment)
    db.session.commit()

    return render_template("success.html", payment_id=payment_id)

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

limiter.init_app(app)



if __name__ == "__main__":
    app.run(debug=True)
