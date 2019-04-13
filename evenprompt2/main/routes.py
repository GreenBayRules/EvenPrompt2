from flask import render_template, request, Blueprint

main = Blueprint('main', __name__)

@main.route("/")
@main.route("/home")
def home():
    page = request.args.get('page', 1, type=int)
    return render_template("home.html", title="Welcome", subtitle="to the home of Math Attackerz")
