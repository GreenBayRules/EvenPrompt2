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
    default_score_information = {
        "multiplication": {
            "easy": 0,
            "medium": 0,
            "hard": 0,
            "expert": 0,
            "points": 0
        },
        "addition": {
            "easy": 0,
            "medium": 0,
            "hard": 0,
            "expert": 0,
            "points": 0
        },
        "subtraction": {
            "easy": 0,
            "medium": 0,
            "hard": 0,
            "expert": 0,
            "points": 0
        },
        "division": {
            "easy": 0,
            "medium": 0,
            "hard": 0,
            "expert": 0,
            "points": 0
        }
    }
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(13), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.png')
    password = db.Column(db.String(60), nullable=False)
    score_information = db.Column(db.String(1000), default=json.dumps(default_score_information))
    points = db.Column(db.Integer, primary_key=False, default=0)
    join_date = db.Column(db.DateTime, primary_key=False, default=datetime.utcnow)
    bio = db.Column(db.String(500), unique=False, default="This user has not set a bio yet.")
    followers = db.Column(db.String(), unique=False, default="[]")
    following = db.Column(db.String(), unique=False, default="[]")
    comments = db.Column(db.String(), unique=False, default="[]")


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

class Comment(db.Model, UserMixin):
    """
    comment class for database
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(13), unique=False, nullable=False)
    text = db.Column(db.String(250), unique=False, nullable=False)
    image_url = db.Column(db.String(20), nullable=False)
    replies = db.Column(db.String(), unique=False, default="[]", nullable=False)
    parent = db.Column(db.Integer, primary_key=False, unique=False, default=0, nullable=False)
    time = db.Column(db.String(), primary_key=False, default=datetime.utcnow().strftime('%B %d %Y'), nullable=False)
    
    def __repr__(self):
        return json.dumps({
            "id":str(self.id),
            "username":self.username,
            "text":self.text, 
            "image_url":self.image_url, 
            "replies":self.replies, 
            "parent": self.parent,
            "time":self.time,
        })

    @staticmethod
    def get_proper_comment(comment_id):
        comment = Comment.query.get(comment_id)
        comments_2 = json.loads(str(comment))
        comments_2 = {key.encode('ascii','ignore'): str(value).encode('ascii','ignore') for (key, value) in comments_2.items()}
        comments_2['replies'] = json.loads(comments_2['replies'])
        new_replies = list()
        for reply_id in comments_2['replies']:
            new_replies.append(Comment.get_proper_comment(reply_id))
        comments_2['replies'] = new_replies
        comments_2['id'] = int(comments_2['id'])
        comments_2['parent'] = int(comments_2['parent'])
        return comments_2
