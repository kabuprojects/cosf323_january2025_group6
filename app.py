import base64
import random
import smtplib
from email.mime.text import MIMEText
import string
import logging
import os

import cv2
import face_recognition
import numpy as np
import requests
import datetime
import json

from requests.auth import HTTPBasicAuth

import mail
import bcrypt
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_pymongo import PyMongo
from flask_mail import Mail, Message
from werkzeug import Response

from config import Config
from database.db_setup import users_collection, verification_codes

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)
app.config.from_object(Config)
app.secret_key = "your_secret_key"

# Initialize MongoDB
mongo = PyMongo(app)

# Initialize Flask-Mail
mail = Mail(app)

MPESA_SHORTCODE = "174379"
MPESA_PASSKEY = "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919"
MPESA_CONSUMER_KEY = "uuIMpEhEkFxwVQYXcZoHnzAbQOBJqWcK9unijtbLYg6X8czG"
MPESA_CONSUMER_SECRET = "HghELMMLUMgJWNjn3JWcbeR1SJthYE3mKAlGwuizNLOz9Z0fAcWhnBnj2blGXZTP"
MPESA_STK_PUSH_URL = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
MPESA_ACCESS_TOKEN_URL = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"



def get_access_token():
    response = requests.get(
        MPESA_ACCESS_TOKEN_URL,
        auth=(MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET)
    )
    access_token = response.json().get("access_token")
    return access_token

# Function to initiate STK Push
def initiate_mpesa_payment(phone_number, amount):
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    password = base64.b64encode(f"{MPESA_SHORTCODE}{MPESA_PASSKEY}{timestamp}".encode()).decode()

    def initiate_mpesa_payment(phone_number, amount):
        """
        Mock function for M-Pesa payment initiation.
        Replace with actual API request and response handling.
        """
        try:
            if not phone_number or amount <= 0:
                return {"ResponseCode": "1", "errorMessage": "Invalid phone number or amount"}

            # Simulated API response
            response = {
                "ResponseCode": "0",  # Success
                "ResponseDescription": "Success",
            }
            return response
        except Exception as e:
            print(f"Error in M-Pesa Payment: {e}")
            return {"ResponseCode": "1", "errorMessage": str(e)}  # Return error

    headers = {"Authorization": f"Bearer {get_access_token()}"}
    payload = {
    "BusinessShortCode": 174379,
    "Password": "MTc0Mzc5YmZiMjc5ZjlhYTliZGJjZjE1OGU5N2RkNzFhNDY3Y2QyZTBjODkzMDU5YjEwZjc4ZTZiNzJhZGExZWQyYzkxOTIwMjUwMzE2MTMzMjAy",
    "Timestamp": "20250316133202",
    "TransactionType": "CustomerPayBillOnline",
    "Amount": amount,
    "PartyA": 254708374149,
    "PartyB": 174379,
    "PhoneNumber": phone_number,
    "CallBackURL": "https://mydomain.com/path",
    "AccountReference": "CompanyXLTD",
    "TransactionDesc": "Payment of X"
  }
    response = requests.post(MPESA_STK_PUSH_URL, json=payload, headers=headers)
    return response.json()

def calculate_fraud_score(user):
    """
    Calculates a fraud score based on multiple risk factors.
    The score determines the level of verification required.
    """
    fraud_score = 0

    # 1️⃣ Failed login attempts increase risk
    failed_attempts = user.get("failed_attempts", 0)
    if failed_attempts >= 3:
        fraud_score += 72  # Previously 72
    if failed_attempts >= 5:
        fraud_score += 108 # Previously 108

    # 2️⃣ Previous fraud history significantly increases risk
    if user.get("blocked", False):
        fraud_score += 180  # Previously 180, Very high risk

    # 3️⃣ Check if the user has recent failed payments
    recent_fraud_attempts = mongo.db.mpesa_attempts.count_documents(
        {"email": user["email"], "status": "failed"}
    )
    if recent_fraud_attempts >= 2:
        fraud_score += 90  # Previously 90, High-risk behavior

    # 4️⃣ Check if the user's device or location has changed drastically
    if user.get("last_known_ip") != user.get("current_ip"):
        fraud_score += 54  # Previously 54, Moderate risk

    # 5️⃣ Assign a small random risk factor for unpredictability
    fraud_score += random.randint(0, 72)  # Previously 0-36

    # Ensure the fraud score is within 0-100%
    return min(fraud_score, 100)


def verify_fraud_risk(user):
    """
    Checks fraud score and determines the required security actions.
    """
    fraud_score = calculate_fraud_score(user)

    if fraud_score < 30:
        return "low", "✅ Low Risk - Only email verification required."
    elif fraud_score < 75:
        return "moderate", "⚠️ Moderate Risk - Email and Face verification required."
    else:
        # High fraud risk, transaction should be blocked
        log_fraud_attempts(user, "blocked")
        return "high", "🚨 High Risk - Transaction blocked due to suspicious activity."


def log_fraud_attempts(user, status="suspicious"):
    """
    Logs fraud-related attempts and blocks users if needed.
    """
    fraud_log = {
        "email": user["email"],
        "timestamp": datetime.datetime.utcnow(),
        "status": status
    }
    mongo.db.fraud_logs.insert_one(fraud_log)

    # If too many failed fraud attempts, block the user
    failed_attempts = mongo.db.fraud_logs.count_documents({"email": user["email"], "status": "suspicious"})
    if failed_attempts >= 5:
        mongo.db.users.update_one({"email": user["email"]}, {"$set": {"blocked": True}})
        print(f"User {user['email']} has been blocked due to multiple fraud attempts.")
@app.route("/")
def home():
    return redirect(url_for("register"))

def is_disposable_email(email):
    """Check if the given email is from a disposable email provider."""
    disposable_domains = {
        "tempmail.com", "mailinator.com", "guerrillamail.com", "10minutemail.com",
        "throwawaymail.com", "yopmail.com", "getnada.com", "fakeinbox.com",
        "dispostable.com", "mytemp.email"
    }
    domain = email.split("@")[-1]  # Extract domain from email
    return domain in disposable_domains


def generate_verification_code(length=5):
    """Generate a case-sensitive verification code with letters & numbers."""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def send_verification_email(email, code):
    """Send email with verification code (dummy function)."""
    print(f"Sending verification code {code} to {email}")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        fraud_policy_accepted = request.form.get("fraud_policy")

        image_file = request.files.get("image")  # Get image from form

        if not all([username, email, password, confirm_password, image_file]):
            flash("All fields including image are required!", "error")
            return render_template("register.html")

        if not fraud_policy_accepted:
            flash("You must accept the fraud policy to continue!", "error")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return render_template("register.html")

        if is_disposable_email(email):
            flash("Disposable email addresses are not allowed!", "error")
            return render_template("register.html")

        existing_user = users_collection.find_one({"email": email})
        if existing_user:
            flash("Email already registered!", "error")
            return render_template("register.html")

        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        verification_code = generate_verification_code()

        # Save image temporarily
        image_path = f"temp_{username}.jpg"
        image_file.save(image_path)

        # Encode face
        img = face_recognition.load_image_file(image_path)
        encodings = face_recognition.face_encodings(img)

        if not encodings:
            os.remove(image_path)
            flash("No face detected in the image!", "error")
            return render_template("register.html")

        face_encoding = encodings[0].tolist()  # Convert encoding to list

        # Store user data in MongoDB
        user_data = {
            "username": username,
            "email": email,
            "password": hashed_password,
            "verified": False,
            "fraud_policy_accepted": True,
            "face_encoding": face_encoding  # Store face encoding
        }
        users_collection.insert_one(user_data)
        verification_codes.insert_one({"email": email, "code": verification_code})

        send_verification_email(email, verification_code)

        os.remove(image_path)  # Cleanup temp file

        session["email"] = email
        flash("Verification code sent to your email!", "success")
        return redirect(url_for("email_verification"))

    return render_template("register.html")

def send_verification_email(email, verification_code):
    sender = "noreply@app.com"
    subject = "Email Verification"

    msg = Message(subject=subject, sender=sender, recipients=[email])
    msg.body = f"Your verification code is: {verification_code}"

    mail.send(msg)  # Use the global 'mail' object
    print(f"Verification email sent to {email}")

@app.route("/fraud-policy")
def fraud_policy():
    return render_template("fraud-policy.html")

@app.route("/email_verification", methods=["GET", "POST"])
def email_verification():
    if request.method == "POST":
        email = request.form.get("email")
        entered_code = request.form.get("code")

        if not email or not entered_code:
            flash("Please enter your email and verification code.", "error")
            return render_template("email_verification.html")

        stored_code_data = mongo.db.verification_codes.find_one({"email": email})

        if not stored_code_data:
            flash("Email not found. Please register first.", "error")
            return redirect(url_for("register"))

        if entered_code == stored_code_data["code"]:  # ✅ Strict case-sensitive check
            mongo.db.users.update_one({"email": email}, {"$set": {"verified": True}})
            mongo.db.verification_codes.delete_one({"email": email})
            flash("Email verified successfully! You can now log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("Incorrect code. Please try again.", "error")

    return render_template("email_verification.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = mongo.db.users.find_one({"email": email})

        if not user:
            flash("Email not found. Please register first.", "error")
            return redirect(url_for("register"))

        # Check if user is blocked
        if user.get("blocked", False):
            flash("Your account is blocked. Please verify your email to unblock.", "error")
            return redirect(url_for("verify_email"))

        # Initialize or update failed attempts
        failed_attempts = user.get("failed_attempts", 0)

        if not bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
            failed_attempts += 1
            mongo.db.users.update_one({"email": email}, {"$set": {"failed_attempts": failed_attempts}})

            if failed_attempts >= 5:
                mongo.db.users.update_one({"email": email}, {"$set": {"blocked": True}})
                flash("Too many failed attempts. Your account is blocked. Please verify your email.", "error")
                return redirect(url_for("verify_email"))
            elif failed_attempts >= 3:
                flash(f"Warning: {failed_attempts} failed attempts. Your account will be blocked after 5 attempts.", "warning")

            flash("Incorrect password. Please try again.", "error")
            return redirect(url_for("login"))

        # Reset failed attempts on successful login
        mongo.db.users.update_one({"email": email}, {"$set": {"failed_attempts": 0}})

        session["user"] = email
        flash("Login successful!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/verify_email", methods=["GET", "POST"])
def verify_email():
    if request.method == "POST":
        email = request.form["email"]
        user = mongo.db.users.find_one({"email": email})

        if not user:
            flash("Email not found. Please register first.", "error")
            return redirect(url_for("register"))

        # Generate and store verification code with expiration time
        verification_code = str(random.randint(10000, 99999))
        expiration_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=1)        # Code expires in 5 minutes
        mongo.db.users.update_one({"email": email}, {"$set": {
            "verification_code": verification_code,
            "code_expiry": expiration_time
        }})
        send_verification_email(email, verification_code)

        flash("Verification code sent to your email. Enter the code to verify.", "info")
        return redirect(url_for("enter_verification_code", email=email))

    return render_template("verify_email.html")

def send_verification_email(email, verification_code):
    sender = "noreply@app.com"
    subject = "Email Verification"

    msg = Message(subject=subject, sender=sender, recipients=[email])
    msg.body = f"Your verification code is: {verification_code}"

    mail.send(msg)  # Use the global 'mail' object
    print(f"Verification email sent to {email}")



@app.route("/enter_verification_code", methods=["GET", "POST"])
def enter_verification_code():
    email = request.args.get("email")

    if request.method == "POST":
        code = request.form["code"]
        user = mongo.db.users.find_one({"email": email})

        if user:
            stored_code = user.get("verification_code")
            code_expiry = user.get("code_expiry")

            if not stored_code or not code_expiry:
                flash("No verification code found. Please request a new one.", "error")
                return redirect(url_for("verify_email"))

            # Check if the code is expired
            if datetime.datetime.utcnow() > code_expiry:
                flash("Verification code has expired. Please request a new one.", "error")
                return redirect(url_for("verify_email"))

            # Check if the entered code matches
            if code == stored_code:
                mongo.db.users.update_one({"email": email}, {"$set": {
                    "blocked": False,
                    "failed_attempts": 0,
                    "verification_code": None,
                    "code_expiry": None
                }})
                flash("Email verified successfully! You can now login.", "success")
                return redirect(url_for("login"))

            flash("Invalid verification code. Please try again.", "error")

    return render_template("enter_verification_code.html", email=email)
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))
    return render_template("dashboard.html")


# ─── SHOPPING CART FUNCTIONALITY ─────────────────────────────────────────
@app.route("/shop")
def shop():
    return render_template("shop.html")


@app.route("/cart")
def cart():
    cart_items = session.get("cart", [])
    total_price = sum(item["price"] for item in cart_items)
    return render_template("cart.html", cart=cart_items, total=total_price)


@app.route("/add_to_cart", methods=["POST"])
def add_to_cart():
    item_name = request.form["name"]
    item_price = float(request.form["price"])

    if "cart" not in session:
        session["cart"] = []

    session["cart"].append({"name": item_name, "price": item_price})
    session.modified = True

    flash("Item added to cart!", "success")
    return redirect(url_for("shop"))


@app.route("/remove_from_cart", methods=["GET" , "POST"])
def remove_from_cart():
    item_name = request.form["name"]

    if "cart" in session:
        session["cart"] = [item for item in session["cart"] if item["name"] != item_name]
        session.modified = True

    flash("Item removed from cart!", "info")
    return redirect(url_for("cart"))





# ─── PAYMENT SYSTEM (M-PESA & BANK) ─────────────────────────────────
@app.route("/payment", methods=["GET", "POST"])
def payment():
    if "user" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    email = session["user"]
    user = users_collection.find_one({"email": email})

    if not user:
        flash("User not found. Please register.", "error")
        return redirect(url_for("register"))

    # Calculate fraud score
    fraud_score = calculate_fraud_score(user)

    if request.method == "POST":
        payment_method = request.form.get("payment_method")

        if payment_method == "mpesa":
            phone = request.form.get("phone")
            if not phone:
                flash("Phone number is required for M-Pesa payments!", "error")
                return redirect(url_for("payment"))

            session["phone"] = phone
            otp = str(random.randint(10000, 99999))
            mongo.db.email_otp.update_one({"email": email}, {"$set": {"otp": otp}}, upsert=True)
            send_email(email, otp)

            # Fraud score determines verification method
            if fraud_score < 30:
                flash(f"Fraud Risk: {fraud_score}% - Only email verification required.", "info")
                return redirect(url_for("mpesa_verification"))
            else:
                flash(f"Fraud Risk: {fraud_score}% - Both email and face verification required.", "warning")
                return redirect(url_for("verify_face"))

        elif payment_method == "bank":
            flash("Bank payment selected. Proceeding to bank payment details.", "info")
            return redirect(url_for("bank_payment"))

    return render_template("payment.html", fraud_score=fraud_score)

def generate_frames():
    cap = cv2.VideoCapture(0)
    while True:
        success, frame = cap.read()
        if not success:
            break
        else:
            ret, buffer = cv2.imencode('.jpg', frame)
            frame = buffer.tobytes()
            yield (b'--frame\r\n' b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
    cap.release()

@app.route("/verify_face", methods=["GET", "POST"])
def verify_face():
    if "user" not in session:
        flash("Please log in first!", "error")
        return redirect(url_for("login"))

    email = session["user"]
    user = users_collection.find_one({"email": email})
    if not user:
        flash("User not found!", "error")
        return redirect(url_for("login"))

    stored_encoding = user.get("face_encoding")
    if not stored_encoding:
        flash("No face data found for this user!", "error")
        return redirect(url_for("payment"))  # Redirect back to payment instead of login

    if request.method == "POST":
        cap = cv2.VideoCapture(0)
        ret, frame = cap.read()
        cap.release()

        if not ret:
            flash("No face detected on the live screen!", "error")
            return render_template("verify_face.html", video_feed=url_for("video_feed"))

        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        encodings = face_recognition.face_encodings(rgb_frame)

        if not encodings:
            flash("No face detected in the live video!", "error")
            return render_template("verify_face.html", video_feed=url_for("video_feed"))

        live_encoding = encodings[0]
        match = face_recognition.compare_faces([stored_encoding], live_encoding, tolerance=0.2)[0]

        if match:
            flash("Face verified successfully!", "success")
            return redirect(url_for("mpesa_verification"))
        else:
            session["attempts"] = session.get("attempts", 0) + 1
            remaining_attempts = 3 - session["attempts"]

            if remaining_attempts > 0:
                flash(f"Faces do not match! Attempts left: {remaining_attempts}", "error")
                return redirect(url_for("verify_face"))  # Allow retry
            else:
                session.pop("attempts", None)  # Reset attempts
                flash("Too many failed attempts. Returning to payment.", "error")
                return redirect(url_for("payment"))  # Redirect to payment instead of login

    return render_template("verify_face.html", video_feed=url_for("video_feed"))

@app.route("/video_feed")
def video_feed():
    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')


def send_email(email, otp):
    sender = "noreply@app.com"
    subject = "Email Verification"

    msg = Message(subject=subject, sender=sender, recipients=[email])
    msg.body = f"Your verification code is: {otp}"

    mail.send(msg)  # Use the global 'mail' object
    print(f"Verification email sent to {email}")


@app.route("/mpesa_verification", methods=["GET", "POST"])
def mpesa_verification():
    if request.method == "POST":
        email = session.get("email")
        entered_code = request.form.get("verification_code")
        action = request.form.get("action")

        if not email:
            flash("Session expired. Please log in again.", "error")
            return redirect(url_for("login"))

        # Fetch OTP from MongoDB
        stored_otp = mongo.db.email_otp.find_one({"email": email})
        if not stored_otp or entered_code != stored_otp.get("otp"):
            flash("Invalid OTP. Try again.", "error")
            return render_template("mpesa_verification.html")

        if action == "pay":
            cart_items = session.get("cart", [])
            total_amount = sum(item.get("price", 0) for item in cart_items)
            phone_number = session.get("phone")

            # Validate phone number
            if not phone_number:
                flash("No phone number found in session. Try again.", "error")
                return redirect(url_for("mpesa_verification"))

            # Convert phone number to international format (if necessary)
            if phone_number.startswith("0"):
                phone_number = "254" + phone_number[1:]

            # Debugging: Print values
            logging.debug(f"Phone: {phone_number}, Amount: {total_amount}")

            # ✅ Store the timestamp correctly before initiating payment
            verification_attempt = {
                "email": email,
                "timestamp": datetime.datetime.utcnow(),  # ✅ Fixes datetime issue
                "status": "attempting_payment"
            }
            mongo.db.mpesa_attempts.insert_one(verification_attempt)

            # Initiate M-Pesa Payment
            response = initiate_mpesa_payment(phone_number, total_amount)
            logging.debug(f"M-Pesa API Response: {response}")

            if response.get("ResponseCode") == "0":
                return redirect(url_for("dashboard"))
            else:
                error_message = response.get("errorMessage", "Unknown error")
                flash(f"Payment failed: {error_message}", "error")
                return redirect(url_for("mpesa_verification"))

        else:
            flash("OTP Verified. Click Pay to proceed.", "success")

    return render_template("mpesa_verification.html")

@app.route("/logout")
def logout():
    session.pop("user", None)  # Remove the user session
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("login"))  # Redirect to login page after logout

if __name__ == "__main__":
    app.run(debug=True)
New content
