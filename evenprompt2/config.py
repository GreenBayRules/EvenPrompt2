import os

class Config:
    
    SECRET_KEY = '6ea2e1c3b62394266c99f7ad6aab816c'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site1.db'
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    # put real mail information later
    MAIL_USERNAME = 'later@gmail.com'
    MAIL_PASSWORD = 'later'
    