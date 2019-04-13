from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.widgets import TextArea
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import current_user
from evenprompt2.models import User

class RegistrationForm(FlaskForm):
    """
    registration form for program
    """
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=2, max=20)
    ])

    email = StringField('Email', validators=[
        DataRequired(),
        Email()
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

    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        if not username.data.isalnum():
            raise ValidationError('Username must only be alphabets and numbers (alphanumeric).')
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('That email is taken. Please choose a different one.')



class LoginForm(FlaskForm):
    """
    login form for the program
    """
    email = StringField('Email', validators=[
        DataRequired(),
        Email()
    ])

    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6)
    ])

    remember = BooleanField('Remember Me')

    submit = SubmitField('Login')

class RequestResetForm(FlaskForm):
    email = StringField('Email', 
                        validators=[DataRequired(),Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account associated with that email. Please register first.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', 
            validators=[DataRequired(), Length(min=6)])

    confirm_password = PasswordField('Confirm Password', 
            validators=[DataRequired(), EqualTo('password'), Length(min=6)])

    submit = SubmitField('Reset Password')