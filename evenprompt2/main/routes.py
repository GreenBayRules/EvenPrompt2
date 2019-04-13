from flask import render_template, request, Blueprint

main = Blueprint('main', __name__)

@main.route("/")
@main.route("/home")
def home():
    return render_template("home.html", title="Welcome", subtitle="fintech")

@main.route("/portal")
def portal():
    return render_template("portal.html", title="Portal", subtitle="View your credit score here")
