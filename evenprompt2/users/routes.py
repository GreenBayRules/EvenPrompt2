from flask import render_template, url_for, flash, redirect, request, Blueprint, abort
from flask_login import login_user, current_user, logout_user, login_required
from evenprompt2 import db, bcrypt
from evenprompt2.models import User
from evenprompt2.users.forms import RegistrationForm, LoginForm, RequestResetForm, ResetPasswordForm
from evenprompt2.users.utils import save_picture, send_reset_email, get_joined_string
from sqlalchemy import func
from datetime import datetime
import json
import time


users = Blueprint('users', __name__)

@users.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.tutorial'))
    form = RegistrationForm()

    # if form validated properly
    if form.validate_on_submit():
        # hash pass for security
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        print(form.is_bank.data)
        string_bool = str(form.is_bank.data).lower()
        print(string_bool)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, is_bank=string_bool)

        # add to database
        db.session.add(user)
        db.session.commit()

        flash("Your account has been created! You are now able to log in", 'success')
        return redirect(url_for('users.login'))
    return render_template("register.html", title="Register", subtitle="Create a new account", form=form)

@users.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.tutorial'))
    form = LoginForm()
    
    # on submit
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.home'))
        else:
            flash("Login unsuccesful. Please check your email and password.", "danger")
    
    return render_template("login.html", title="Login", subtitle="Access your account", form=form)

@users.route("/logout", methods=['GET', 'POST'])
def logout():
    logout_user()
    flash("Logged out!", "info")
    return redirect(url_for('users.login'))


@users.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password', "info")
        redirect(url_for('users.login'))
    return render_template('reset_request.html', title="Reset Your Password", subtitle="Get a link to reset your password", form=form)


@users.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('users.reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        # hash pass for security
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()

        flash("Your password has been updated! You are now able to log in", 'success')
        return redirect(url_for('users.login'))
    return render_template('reset_token.html', title="Reset Password", subtitle="The final step", form=form)

@users.route("/portal")
def portal():
    if not current_user.is_authenticated:
        return redirect(url_for('users.login'))
    if current_user.is_bank == "false":
        return render_template("user_portal.html", title="User Portal", subtitle="View your credit score here")
    else:
        return render_template("bank_portal.html", title="Bank Portal", subtitle="View your credit score here")
