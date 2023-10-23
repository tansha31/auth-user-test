import os
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, redirect, request, session, flash

load_dotenv()

db = SQLAlchemy()
DB_NAME = os.getenv("DB_NAME")
SECRET_KEY = os.getenv("SECRET_KEY")

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_NAME}"
app.config["SECRET_KEY"] = SECRET_KEY

db.init_app(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), nullable=False)


with app.app_context():
    db.create_all()


@app.route("/")
def home():
    if "user" in session:
        return render_template("home.html", is_authenticated=True)

    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()

        if user:
            if check_password_hash(user.password, password):
                session["user"] = email
                flash("Logged in successfully.", category="success")

                return redirect("/")

            else:
                flash("Incorrect password.", category="error")

        else:
            flash("No account associated with this email.", category="error")

    return render_template("login.html", is_authenticated=False)


@app.route("/sign-up", methods=["GET", "POST"])
def sign_up():
    if request.method == "POST":
        email = request.form.get("email")
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()

        if user:
            flash("User with this email already exits.", category="error")

        elif len(password) < 8:
            flash("Password must be at least 8 characters.", category="error")

        else:
            new_user = User(
                email=email,
                first_name=first_name,
                last_name=last_name,
                password=generate_password_hash(password=password),
            )
            db.session.add(new_user)
            db.session.commit()

            flash("Account created successfully, please log in.", category="success")

            return redirect("/login")

    return render_template("sign_up.html", is_authenticated=False)


@app.route("/logout")
def logout():
    if "user" in session:
        session.pop("user", None)
        flash("Logged out successfully.", category="success")

    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True, port=8000)
