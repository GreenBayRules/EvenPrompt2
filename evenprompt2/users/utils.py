import os
from PIL import Image
from flask import url_for, current_app
from flask_mail import Message
from evenprompt2 import mail

def save_picture(form_picture):
    random_hex = os.urandom(8).encode('hex')
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(current_app.root_path, 'static/profile_pics', picture_fn)
    
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset', sender="noreply@demo.com", recipients=[user.email])

    msg.body = """To reset your password click the following link: {}
    
    If you didn't request this, then just ignore this email.""".format(url_for('users.reset_token', token=token, _external=True))

    mail.send(msg)


def get_joined_string(days, seconds):
    if days == 0:
        minutes, seconds = divmod(seconds, 60)
        if minutes == 0:
            date_string = "{} seconds".format(seconds)
        else:
            hours, minutes = divmod(minutes, 60)
            if hours == 0:
                date_string = "{} minutes".format(minutes)
            else:
                date_string = "{} hours".format(hours)
    else:
        months, days = divmod(days, 30)
        if months == 0:
            date_string = "{} days".format(days)
        else:
            years, months = divmod(months, 12)
            if years == 0:
                date_string = "{} months".format(months)
            else:
                date_string = "{} years ".format(years)
    
    if date_string[:2] == "1 ":
        date_string = date_string[:-1]
    
    return date_string