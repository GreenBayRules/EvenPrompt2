from flask import render_template, url_for, flash, redirect, request, Blueprint, abort
from flask_login import login_user, current_user, logout_user, login_required
from evenprompt2 import db, bcrypt
from evenprompt2.models import User, Comment 
from evenprompt2.users.forms import (RegistrationForm, LoginForm, UpdateAccountForm,
                                   RequestResetForm, ResetPasswordForm, UpdateBioForm,  PostCommentForm)
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
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)

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

@users.route("/settings", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account details have been updated!', 'success')
        return redirect(url_for('users.account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename="profile_pics/" + current_user.image_file)
    return render_template("account.html", title="Settings", subtitle="Update your information", image_file=image_file, form=form)

@users.route("/users/<username>", methods=['GET', 'POST'])
@login_required
def user_profile(username):
    form = PostCommentForm()
    user = User.query.filter(func.lower(User.username) == func.lower(username)).first()
    if user is None:
        abort(404)
    time_diff = datetime.utcnow() - user.join_date
    days = time_diff.days
    seconds = time_diff.seconds
    date_string = get_joined_string(days, seconds)

    score_information = json.loads(user.score_information)
    # top_score = 0
    # top_skill = "None"
    # for skill, score in score_information.items():
    #     if score > top_score:
    #         top_skill = skill
    #         top_score = score
    
    # top_skill = top_skill.upper()
    leader_board = User.query.order_by(User.points.desc()).limit(100).all()
    followers = json.loads(user.followers)
    following = json.loads(user.following)
    comments = json.loads(user.comments)


    # if form validated properly
    if form.validate_on_submit():
        
        if len(form.comment.data) > 250 or len(form.comment.data) < 1:
            flash("Your comment could not be posted! Comments must be 1-250 characters long", "danger")
        elif "badword" in form.comment.data:
            flash("Your comment could not be posted! Remember to be nice and don't use bad words", "danger")
        else:
            reply = form.reply.data
            if reply == "f":
                comment = Comment(text=form.comment.data, username=current_user.username, image_url=current_user.image_file)
                db.session.add(comment)
                db.session.commit()
                comments.insert(0, comment.id)
                user.comments = json.dumps(comments)
                db.session.commit()
            else:
                comment = Comment(text=form.comment.data, username=current_user.username, image_url=current_user.image_file, parent=reply)
                db.session.add(comment)
                db.session.commit()
                parent = Comment.query.get(reply)
                replies = json.loads(parent.replies)
                replies.append(comment.id)
                parent.replies = json.dumps(replies)
                db.session.commit()
            flash("Your comment was successfully posted!", "success")
            return redirect(url_for('users.user_profile', username=username))

    comments = [Comment.get_proper_comment(comment_id) for comment_id in comments]
    print(comments)
    if user in leader_board:
        rank_index = str(leader_board.index(user) + 1)
        if rank_index[-1] == '1':
            rank_index += "st"
        elif rank_index[-1] == '2':
            rank_index += "nd"
        elif rank_index[-1] == '3':
            rank_index += "rd"
        else:
            rank_index += "th"
        followers = [User.query.get(i) for i in followers]
        following = [User.query.get(i) for i in following]
        return render_template("profile.html", form=form, title=user.username, rank_index=rank_index, subtitle="Joined {} ago".format(date_string), user=user, date_string=date_string, logo=user.image_file, followers=followers, following=following, comments=comments)
    else:
        return render_template("profile.html", form=form, title=user.username, subtitle="Joined {} ago".format(date_string), user=user, date_string=date_string, logo=user.image_file, followers=followers, following=following, comments=comments)


@users.route("/un_follow_user/<user_id>", methods=['POST'])
@login_required
def un_follow_user(user_id):
    current_user_id = current_user.id
    user_id = int(user_id)
    user = User.query.get(user_id)
    followers = json.loads(user.followers)
    print(followers)
    print(user_id)
    following = json.loads(current_user.following)
    if current_user_id in followers:
        followers.remove(current_user.id)
        following.remove(user_id)
        user.followers = json.dumps(followers)
        current_user.following = json.dumps(following)
        db.session.commit()
        flash('You have successfully unfollowed this user.', 'success')
        return redirect(url_for('users.user_profile', username=user.username))
    else:
        flash('Error: You cannot unfollow a user who you are not following', 'danger')
        return redirect(url_for('users.user_profile', username=user.username))

@users.route("/follow_user/<user_id>", methods=['POST'])
@login_required
def follow_user(user_id):
    current_user_id = current_user.id
    user = User.query.get(user_id)
    followers = json.loads(user.followers)
    following = json.loads(current_user.following)
    if int(current_user_id) not in followers:
        followers.append(current_user.id)
        following.append(int(user_id))
        user.followers = json.dumps(followers)
        current_user.following = json.dumps(following)
        db.session.commit()
        flash('You have successfully followed this user.', 'success')
        return redirect(url_for('users.user_profile', username=user.username))
    else:
        flash('You are already following this user', 'danger')
        return redirect(url_for('users.user_profile', username=user.username))


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


@users.route("/update_bio", methods=['GET', 'POST'])
@login_required
def update_bio():
    form = UpdateBioForm()
    if form.validate_on_submit():
        new_bio = form.bio.data

        current_user.bio = new_bio
        db.session.commit()

        flash('Updated your bio!', "info")
        return redirect(url_for('users.user_profile', username=current_user.username))
    return render_template('update_bio.html', title="Update your profile bio", subtitle="Change your bio that is displayed on your profile.", form=form)

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