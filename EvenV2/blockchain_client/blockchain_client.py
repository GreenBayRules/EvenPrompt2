'''
title           : blockchain_client.py
description     : A blockchain client implemenation, with the following features
                  - Wallets generation using Public/Private key encryption (based on RSA algorithm)
                  - Generation of transactions with RSA encryption
author          : Adil Moujahid
date_created    : 20180212
date_modified   : 20180309
version         : 0.3
usage           : python blockchain_client.py
                  python blockchain_client.py -p 8080
                  python blockchain_client.py --port 8080
python_version  : 3.6.1
Comments        : Wallet generation and transaction signature is based on [1]
References      : [1] https://github.com/julienr/ipynb_playground/blob/master/bitcoin/dumbcoin/dumbcoin.ipynb
'''

from collections import OrderedDict

import binascii
from flask_bcrypt import Bcrypt
import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from flask_login import login_user, current_user, logout_user, login_required, UserMixin, LoginManager
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.widgets import TextArea
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import current_user

import requests
from flask import Flask, jsonify, request, render_template, redirect, url_for, abort
from flask_sqlalchemy import SQLAlchemy

class RegistrationForm(FlaskForm):
    """
    registration form for program
    """
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=2, max=20)
    ])

    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6)
    ])

    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password'),
        Length(min=6)
    ])

    is_bank = BooleanField('Are you a bank? Leave un-checked if you are a client.')

    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        if not username.data.isalnum():
            raise ValidationError('Username must only be alphabets and numbers (alphanumeric).')
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('That username is taken. Please choose a different one.')



class LoginForm(FlaskForm):
    """
    login form for the program
    """
    username = StringField('Username', validators=[
        DataRequired()
    ])

    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6)
    ])

    remember = BooleanField('Remember Me')

    submit = SubmitField('Login')

class Transaction:

    def __init__(self, sender_address, sender_private_key, recipient_address, value):
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.recipient_address = recipient_address
        self.value = value

    def __getattr__(self, attr):
        return self.data[attr]

    def to_dict(self):
        return OrderedDict({'sender_address': self.sender_address,
                            'recipient_address': self.recipient_address,
                            'value': self.value})

    def sign_transaction(self):
        """
        Sign transaction with private key
        """
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')



app = Flask(__name__)
bcrypt = Bcrypt()
app.config["SECRET_KEY"] = '6ea2e1c3b62394266c99f7ad6aab816c'
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///site.db'
app.config["TESTING"] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter(User.id == int(user_id)).first()

@app.route('/wheel')
@login_required
def index():
	return render_template('./index.html')

@app.route('/make/transaction')
@login_required
def make_transaction():
    if current_user.type != "bank":
        abort(403)
    return render_template('./make_transaction.html')

@app.route('/view/transactions')
@login_required
def view_transaction():
    return render_template('./view_transactions.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('./profile.html')

def get_public_and_private_keys():
    random_gen = Crypto.Random.new().read
    print("test")
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    return binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'), binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')

@app.route('/wallet/new', methods=['GET'])
def new_wallet():
	private_key, public_key  = get_public_and_private_keys()
	response = {
		'private_key': private_key,
		'public_key': public_key
	}

	return jsonify(response), 200

@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
	print(request.form)
	sender_address = request.form['sender_address']
	sender_private_key = request.form['sender_private_key']
	recipient_address = request.form['Person Id']
	value = request.form['amount']

	transaction = Transaction(sender_address, sender_private_key, recipient_address, value)

	response = {'transaction': transaction.to_dict(), 'signature': transaction.sign_transaction()}

	return jsonify(response), 200


@app.route('/info')
@login_required
def info():
    return render_template('./info.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    # if form validated properly
    if form.validate_on_submit():
        # hash pass for security
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)

        user.public_key, user.private_key = user.default_public_key, user.default_private_key
        user.type = "client"
        if form.is_bank.data:
            user.type = "bank"

        # add to database
        db.session.add(user)
        db.session.commit()

        return redirect(url_for('info'))
    return render_template("register.html", current_user=current_user, title="Register", subtitle="Create a new account", form=form)


@app.route('/')
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('info'))
    form = LoginForm()
    
    # on submit
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            print(user.is_authenticated, current_user, user, current_user.is_authenticated)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('info'))
        else:
            flash("Login unsuccesful. Please check your email and password.", "danger")
    
    return render_template("login.html", title="Login", subtitle="Access your account", form=form)

@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    type = db.Column(db.String(20), unique=False, nullable=False)
    default_private_key, default_public_key  = get_public_and_private_keys()
    public_key = db.Column(db.String(1000), nullable=False)
    private_key = db.Column(db.String(5000), nullable=False)
    password = db.Column(db.String(60), nullable=False)


    def __repr__(self):
        return "Username: {}, Public key: {}, Type: {}".format(self.username, self.public_key, self.type)


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port
    

    app.run(host='127.0.0.1', port=port, debug=True)
