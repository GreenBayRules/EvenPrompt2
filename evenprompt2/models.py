from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from datetime import datetime
from evenprompt2 import db, login_manager
from flask_login import UserMixin
from flask import current_app
import json

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    """
    user class for database
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(13), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.png')
    password = db.Column(db.String(60), nullable=False)
    join_date = db.Column(db.DateTime, primary_key=False, default=datetime.utcnow)
    is_bank = db.Column(db.String(20), primary_key=False, nullable=False, default='false')


    def get_reset_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')
    
    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)
