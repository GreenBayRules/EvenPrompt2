from flask import render_template, request, Blueprint, redirect, url_for
from flask_login import current_user

main = Blueprint('main', __name__)

@main.route("/")
@main.route("/home")
def home():
    if current_user.is_authenticated:
        return redirect(url_for('users.portal'))
    return render_template("home.html", title="Welcome", subtitle="fintech")
