from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
# from forms import CreatePostForm, CreateRegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from flask import abort
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = "abcd"
ckeditor = CKEditor(app)
Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL",  "sqlite:///cafes.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)
##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    comments = relationship("Comment", back_populates="comment_author")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    # ***************Child Relationship*************#
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafe.id"))
    parent_cafe = relationship("Cafe", back_populates="comments")
    text = db.Column(db.Text, nullable=False)
    vote = db.Column(db.Integer, nullable=False)

class Cafe(db.Model):
    __tablename__ = "cafe"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    map_url = db.Column(db.String(500), nullable=False)
    img_url = db.Column(db.String(500), nullable=False)
    location = db.Column(db.String(250), nullable=False)
    seats = db.Column(db.String(250), nullable=False)
    has_toilet = db.Column(db.Boolean, nullable=False)
    has_wifi = db.Column(db.Boolean, nullable=False)
    has_sockets = db.Column(db.Boolean, nullable=False)
    can_take_calls = db.Column(db.Boolean, nullable=False)
    coffee_price = db.Column(db.String(250), nullable=True)
    comments = relationship("Comment", back_populates="parent_cafe")


db.create_all()

@app.route('/')
def get_all_cafes():
    cafes = Cafe.query.all()
    return render_template("index.html", all_Cafes=cafes , logged_in=current_user.is_authenticated)

@app.route('/register', methods=[ 'GET', 'POST'] )
def register():
    if request.method == "POST":
        if User.query.filter_by(email=request.form["email"]).first():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('sigin'))
        if request.form["password"] != request.form["cpassword"]:
            flash("Password and confirm password field should match!")
            return redirect(url_for('sigin'))
        hash_and_salted_password = generate_password_hash(
            request.form["password"],
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=request.form["email"],
            password=hash_and_salted_password,
            name=request.form["fname"],

        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)

        return redirect(url_for("get_all_cafes"))




    return render_template("register.html", logged_in=current_user.is_authenticated)

@app.route('/sigin', methods=[ 'GET', 'POST'] )
def sigin():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        # Find user by email entered.
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email incorrect! Please try again later.')
            return redirect(url_for('sigin'))
        else:

            # Check stored password hash against entered password hashed.
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('get_all_cafes'))
            else:
                flash('Password incorrect! Please try again later.')
                return redirect(url_for('sigin'))

    return render_template("login.html", logged_in=current_user.is_authenticated)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_cafes'))

@app.route("/cafe/<int:cafe_id>", methods=[ 'GET'])
def show_cafe(cafe_id):
    requested_cafe = Cafe.query.get(cafe_id)
    lst = []
    for comment in requested_cafe.comments:
        lst.append(comment.vote)

    if len(lst) == 0:
        avg_vote = 100
    else:
        avg_vote = int(sum(lst) / len(lst))

    return render_template("cafe.html", cafe= requested_cafe, logged_in=current_user.is_authenticated, vote=avg_vote)

@app.route("/edit/<int:cafe_id>", methods=[ 'GET', 'POST'])
def edit_cafe(cafe_id):
    requested_cafe = Cafe.query.get(cafe_id)
    if request.method == "POST":
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("sigin"))
        requested_cafe.has_wifi = int(request.form["has_wifi"])
        requested_cafe.has_sockets = int(request.form["has_sockets"])
        requested_cafe.has_toilet = int(request.form["has_toilet"])
        requested_cafe.can_take_calls = int(request.form["can_take_calls"])
        requested_cafe.seats = request.form["seats"]
        requested_cafe.coffee_price = request.form["coffee_price"]
        requested_cafe.location = request.form["location"]
        requested_cafe.map_url = request.form["map_url"]
        db.session.commit()
    return render_template("edit_cafe.html", cafe= requested_cafe, logged_in=current_user.is_authenticated)

@app.route("/review/<int:cafe_id>", methods=[ 'GET', 'POST'])
def review(cafe_id):
    requested_cafe = Cafe.query.get(cafe_id)
    if request.method == "POST":
        if not current_user.is_authenticated:
            flash("You need to login or register to give feedback.")
            return redirect(url_for("sigin"))
        new_comment = Comment(
            vote=int(request.form["like"]),
            text=request.form["comment"],
            comment_author=current_user,
            parent_cafe=requested_cafe

        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_cafe", cafe_id= cafe_id))

    return render_template("review.html", cafe=requested_cafe, logged_in=current_user.is_authenticated)



if __name__ == "__main__":
    app.run(debug=True)

