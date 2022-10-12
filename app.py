from flask import Flask, flash,  render_template, redirect, url_for, session, current_app, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, TextAreaField, HiddenField, SelectField
from flask_wtf.file import FileField, FileAllowed
import os
from base64 import b64encode
import base64
from io import BytesIO #Converts data from Database into bytes
from flask_migrate import Migrate
# Built-in Imports
import os
from datetime import datetime
from base64 import b64encode
import base64
from io import BytesIO #Converts data from Database into bytes
from flask_bootstrap import Bootstrap
from flask_login import UserMixin
import random

from random import randint
from flask_mail import Mail , Message
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_required, logout_user, current_user, login_user, AnonymousUserMixin
import functools

# Flask
from flask import Flask, render_template, request, flash, redirect, url_for, send_file # Converst bytes into a file for downloads

# FLask SQLAlchemy, Database
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField,  TextAreaField, SelectField, FileField, FloatField
from flask_wtf.file import FileField, FileAllowed, FileRequired, DataRequired
from sqlalchemy import create_engine
#from flask_mysqldb import MySQL
#import mysql.connector





#import smtplib
#import unittest
from flask_bootstrap import Bootstrap
import os
from flask import Flask, request, url_for, render_template, flash, redirect, Blueprint, make_response
from flask_mail import Mail, Message
#from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, SignatureExpired
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField,  TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo, Optional
from wtforms import ValidationError
from flask import current_app, abort, jsonify
import bleach
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
#from threading import Thread
from flask import current_app, render_template
from flask_mail import Message
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_required, logout_user, current_user, login_user, AnonymousUserMixin
#from dotenv import load_dotenv
from flask_moment import Moment
from datetime import datetime
import functools
import hashlib

from flask_login import UserMixin, AnonymousUserMixin,  LoginManager,  login_user, logout_user, login_required, current_user
from sqlalchemy.dialects.postgresql import ARRAY
from flask import Flask, Blueprint, render_template, redirect, url_for, flash, request, Markup, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_fontawesome import FontAwesome
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
import os
import random
from random import shuffle
#from sqlalchemy.sql import text
from sqlalchemy import create_engine
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
#from flask_wtf.html5 import NumberInput
from wtforms import TextAreaField, PasswordField, SubmitField, StringField, IntegerField, SelectField
#from wtforms.fields.html5 import EmailField
from wtforms.validators import  Length, EqualTo, ValidationError, DataRequired, Email
from flask_bootstrap import Bootstrap
from flask_mail import Mail
from flask_fontawesome import FontAwesome
import smtplib
import unittest
from flask_bootstrap import Bootstrap
import os
from flask import Flask, request, url_for, render_template, flash, redirect, Blueprint
from flask_mail import Mail, Message
#from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, SignatureExpired
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
#from threading import Thread
from flask import current_app, render_template
from flask_mail import Message
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_required, logout_user, current_user, login_user, AnonymousUserMixin





app = Flask(__name__)



#basedir = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'triple-s-systems.sqlite')

#SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
   #username="TheCalf",
   #password="BeReal12!",
   #hostname="TheCalf.mysql.pythonanywhere-services.com",
   #databasename="TheCalf$TripleSsystems",
#)


otp=randint(000000,999999)


#app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:CoreSocial94!@localhost:5433/peerfund-dev-08'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['DEBUG'] = True
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'info.starturn@gmail.com'
app.config['MAIL_PASSWORD'] = 'CoreSocial94!'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = 'SECRET_KEY'
app.config['FLASKY_ADMIN'] = 'theofuremomoh@outlook.com,momohofure@gmail.com, ogani@gmail.com'
app.config['PRODUCTS_PER_PAGE'] = 4
app.config['CARTS_PER_PAGE'] = 7
app.config['ORDERS_PER_PAGE'] = 5



db = SQLAlchemy(app)
migrate = Migrate(app, db)

mail = Mail(app)
bootstrap = Bootstrap(app)

fa = FontAwesome(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

#configure_uploads(app, photos)






def render_picture(data):
    render_pic = base64.b64encode(data).decode('ascii')
    return render_pic

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    return user


def permission_required(permission):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    return permission_required(Permission.ADMIN)(f)

class User( UserMixin, db.Model):
 
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    is_admin = db.Column(db.Boolean, default=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    group_in = db.Column(db.Integer, default = 0)
    group = db.relationship('Group', backref='user', lazy='dynamic')
    member = db.relationship('Member', backref='user', lazy='dynamic')
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email in app.config['FLASKY_ADMIN']:
            #if self.email == 'momohofure@gmail.com':
                self.role = Role.query.filter_by(name='Administrator').first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()

    

    def change_email(self, token):

        self.email = new_email
        db.session.add(self)
        return True

    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)

    def is_administrator(self):
        return self.can(Permission.ADMIN)
       
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    
    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id}).decode('utf-8')

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
      
        return True


    def __repr__(self):
        return f"['{self.username}']"

class Permission:
    ORDER = 1
    ADMIN = 2

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    user = db.relationship('User', backref='role', lazy='dynamic')

    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm

    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm

    def reset_permissions(self):
        self.permissions = 0

    def has_permission(self, perm):
        return self.permissions & perm == perm

    @staticmethod
    def insert_roles():
        roles = {
            'User': [Permission.ORDER],
            'Administrator': [Permission.ORDER,
                              Permission.ADMIN],
        }
        default_role = 'User'
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permissions()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default = (role.name == default_role)
            db.session.add(role)
        db.session.commit()


class Member(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    member_target = db.Column(db.Integer)
    monthly_target = db.Column(db.Integer)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    period = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)



    def __init__(self, member_target, monthly_target, group_id, user_id, period):
        self.member_target = member_target
        self.monthly_target = monthly_target
        self.group_id = group_id
        self.user_id = user_id
        self.period = period

        def __repr__(self):
            return f"['{self.id}']"





class Group(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    group_name = db.Column(db.String(80))
    group_admin = db.Column(db.Integer)
    group_members = db.Column(db.Integer)
    member_limit = db.Column(db.Integer)
    group_target = db.Column(db.Integer)
    member_target = db.Column(db.Float)
    monthly_target = db.Column(db.Float)
    current_contribution = db.Column(db.Integer)
    members = db.relationship('Member', backref='group', lazy=True)
    paylist = db.relationship('Paylist', backref='group', lazy=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __init__(self, group_name, group_admin, group_members, member_limit,monthly_target, member_target, group_target, current_contribution, user_id):
        self.group_name = group_name
        self.group_admin = group_admin
        self.group_members = group_members
        self.member_limit = member_limit
        self.monthly_target = monthly_target
        self.member_target = member_target
        self.group_target = group_target
        self.current_contribution = current_contribution
        self.user_id = user_id

    def __repr__(self):
        return f"['{self.group_name}']"

class Paylist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    payee_list = db.Column(ARRAY(db.Integer), default=None)
    start_tenure = db.Column(db.Boolean, default=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))

    def __init__(self, group_id):
        self.group_id = group_id

    def __repr__(self):
        return f"[{self.payee_list}]"

class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False


class Account(db.Model):

    __tablename__ = 'accounts'

    id = db.Column(db.Integer,primary_key = True)
    name = db.Column(db.String(80),unique=True)
    balance = db.Column(db.Float)
    active = db.Column(db.Boolean,default=True)

    def deposit_withdraw(self,type,amount):
        if type == 'withdraw':
            amount *= -1
        if self.balance + amount < 0:
            return False #Unsuccessful
        else:
            self.balance += amount
            return True #Successful

    def __init__(self,name, balance=0):
        self.name = name
        self.balance = balance

    def __repr__(self):
        return f"Account name is {self.name} with account number {self.id}"



class Transaction(db.Model):

    __tablename__ = 'transactions'
    id = db.Column(db.Integer,primary_key = True)
    transaction_type = db.Column(db.Text)
    description = db.Column(db.Text)
    amount = db.Column(db.Float)
    date = db.Column(db.DateTime,nullable=False,default=datetime.utcnow)
    account_id = db.Column(db.Integer,db.ForeignKey('accounts.id'),nullable=False)
    account = db.relationship('Account',backref=db.backref('transactions', lazy=True))


    def __init__(self,transaction_type, description, account_id, amount=0):
        self.transaction_type = transaction_type
        self.description = description
        self.account_id = account_id
        self.amount = amount

    def __repr__(self):
        return f"Transaction {self.id}: {self.transaction_type} on {self.date}"


login_manager.anonymous_user = AnonymousUser


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Usernames must have only letters, numbers, dots or ''underscores')])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

################## Main Forms ##########################

class NameForm(FlaskForm):
    name = StringField('What is your name?', validators=[DataRequired()])
    submit = SubmitField('Submit')


class EditProfileForm(FlaskForm):
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')

class EditProfileAdminForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64),
                                             Email()])
    username = StringField('Username', validators=[
        DataRequired(), Length(1, 64),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
               'Usernames must have only letters, numbers, dots or '
               'underscores')])
    confirmed = BooleanField('Confirmed')
    role = SelectField('Role', coerce=int)
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
                             for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and \
                User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if field.data != self.user.username and \
                User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


class AdminForm(FlaskForm):

    '''admin signup'''
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('password',  validators=[DataRequired(message='password required')])
    submit_button = SubmitField('Ugrade')

class GroupForm(FlaskForm):

    '''group signup'''

    group_name = StringField('group name', validators=[DataRequired()])
    #group_target = IntegerField(validators=[DataRequired()])

    group_target= IntegerField(validators=[DataRequired()])
    member_limit = IntegerField(validators=[DataRequired()])
    submit_button = SubmitField('Create')


class JoinForm(FlaskForm):

    '''group signup'''

    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('password',  validators=[DataRequired(message='password required')])
    period = IntegerField(validators=[DataRequired()])
    join = SubmitField('join')


class ChangeAdminForm(FlaskForm):
    members_id = IntegerField( validators=[DataRequired()])
    change = SubmitField('Change')


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_email(to, subject, template, **kwargs):
    app = current_app._get_current_object()
    msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + ' ' + subject,
                  sender=app.config['MAIL_USERNAME'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    thr = Thread(target=send_async_email, args=[app, msg])
    thr.start()
    return thr

# Context.Processors ####################################################################################################
@app.context_processor
def inject_permissions():
    return dict(Permission=Permission)

@app.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('index'))
    return render_template('unconfirmed.html')


#@login_manager.user_loader
#def load_user(user_id):
    #return User.query.get(int(user_id))


#s = Serializer('Secret-Key')

#token = User.generate_confirmation_token()

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data.lower(),
                    username=form.username.data,
                    password=form.password.data,
                    confirmed = False
                    
                    )
        db.session.add(user)
        db.session.commit()
        #token = user.generate_confirmation_token()
        #send_email(user.email, 'Confirm Your Account',
                   #'mail/confirm', user=user, token=token)
        #flash('A confirmation email has been sent to you by email.')
        return redirect(url_for('login')) ##...This should be for Login instead###
    return render_template('signup.html', form=form)
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('index')
            return redirect(next)
        flash('Invalid email or password.') 
    return render_template('login.html', form=form)

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
 
    return render_template('index.html')

#@app.route('/login?next=/confirm/<token>')
#def login_confirm(token):
    #form = LoginForm()
    #if form.validate_on_submit():
        #user = User.query.filter_by(email=form.email.data.lower()).first()
        #if user is not None\
                #and user.verify_password(form.password.data)\
                #and current_user.confirm(token):
            #db.session.commit()
            #login_user(user, form.remember_me.data)
            #next = request.args.get('next')
            #if next is None or not next.startswith('/'):
                #next = url_for('index')
            #return redirect(next)
        #flash('Invalid email or password.')
        #return redirect(url_for('index'))
    #return render_template('login.html', form=form)

@app.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('index'))

    if current_user.confirm(token):
        db.session.commit()
        #congrats_email(user.email, 'Confirm Your Account', 'mail/confirm', user=user, token=token)
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))


@app.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
               'mail/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('index'))


        

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/images', picture_fn)
    form_picture.save(picture_path)

    return picture_fn

#@app.route('/upd_acct_info', methods=['GET','POST'])
#@login_required
#def upd_acct_info():

 #   form = UpdateAccountInfoForm()

 #   if form.validate_on_submit():
#        if form.picture.data:
#            picture_file = save_picture(form.picture.data)
 #           current_user.profil_pix = picture_file
 #       current_user.username =  form.username.data
  #      current_user.email = form.email.data
  #      db.session.commit()

   #     flash('account details updated')
   #     return redirect(url_for('account_profile'))

  #  elif request.method == 'GET':
       # form.username.data = current_user.username
       # form.email.data = current_user.email
    #profile_pix = url_for('static', filename=f'images/{current_user.profil_pix}')
    #return render_template('account_home.html', form=form, current_user=current_user, profile_pix=profile_pix)


@app.route('/create_admin', methods=['GET', 'POST'])
@login_required
def create_admin():

    form = AdminForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user is not None and user.verify_password(form.password.data):
            user.is_admin=True
            db.session.commit()
            flash('Your account have been upgraded to an administrative account')
            return redirect(url_for('group_creation'))

        #user = User.query.filter_by(email=email).first()

     

        #if current_user.email != email or not check_password_hash(current_user.password, password):
            #return redirect(url_for('admin_signup'))
        else:
            return redirect(url_for('admin_signup'))
            #if current_user.is_admin == False:
            #user.is_admin=True
            #db.session.commit()
            #flash('Your account have been upgraded to an administrative account')
            #return redirect(url_for('group_creation'))
            #elif user.is_admin == True:
                #return redirect(url_for('group_creation'))
    return render_template('admin-signup.html', form=form)

'''create group logic'''

@app.route('/create_group', methods=['GET', 'POST'])
@login_required
@admin_required
def create_group():

    form = GroupForm()

    if form.validate_on_submit():
        group_name = str(form.group_name.data)
        member_limit = int(form.member_limit.data)
        group_target = int(form.group_target.data)
        monthly_target = (group_target/12)
        target = (group_target/member_limit)

        group = Group(group_name=group_name, group_admin=current_user.id, group_members=0, member_limit=member_limit, member_target = target, group_target=group_target, current_contribution=0, monthly_target=monthly_target, user_id=current_user.id)
        db.session.add(group)
        db.session.commit()

        group = Group.query.filter_by(group_name=group_name).first()

        paylist = Paylist(group_id=group.id)
        db.session.add(paylist)
        db.session.commit()

        #monthly_target = group_target/member_limit
        #member = Member(member_target=target, monthly_target=monthly_target, group_id=group.id, user_id=current_user.id, period=period)
        #db.session.add(member)
        #db.session.commit()

        #current_user.group_in += 1
        #db.session.commit()

        flash(f'{group.group_name} have been successfully created')
        return redirect(url_for('group_creation'))
    return render_template('create-group-page.html', form=form)
    
#thheee have been successfully created
#join group
@app.route('/all_groups', methods=['GET', 'POST'])
@login_required
def all_groups():

    form = JoinForm()

    group = Group.query.all()

    if form.validate_on_submit():
        email = form.email.data
        #member_target = form.amount.data
        password = form.password.data
        period = form.period.data
        user = User.query.filter_by(email=form.email.data.lower()).first()

        if user is not None and user.verify_password(form.password.data):
           
            group = Group.query.filter_by(group_target=member_target).first()
            group_id = group.id
            member_limit=group.member_limit
            monthly_target = member_target/member_limit

            ## The Period the user has chosen, how does it reflect here 

            new_member = Member(member_target=member_target, monthly_target=monthly_target,user_id=current_user.id, group_id=group.id, period=period)
            db.session.add(new_member)
            db.session.commit()

            current_user.group_in += 1
            db.session.commit()

            group.group_members += 1
            db.session.commit()

            res = make_response(jsonify({'message': f'you\'ve been added to {group.group_name}.'}), 200)
            return res
    return render_template('join-group-page.html', group=group, form=form)

@app.route('/leave_group')
@login_required
def remove_user():
    group_id = request.args.get('group_id')
    member = Member.query.filter_by(group_id=group_id).filter_by(user_id=current_user.id).first()
    group = Group.query.get(group_id)

    if member:
        db.session.delete(member)
        db.session.commit()

        current_user.group_in -= 1
        db.session.commit()

        group = Group.query.get(group_id)
        group.group_members -= 1
        db.session.commit()

        res = {
            'error' : '0',
            'message' : f'{current_user.username} you have been successfully removed from this group                                    '
        }
        return res
    else:

        res = {
            'error' : '0',
            'message' : f'You are not a member to this {group.group_name}'
        }
        return res


@app.route('/start_tenure/<int:id>')
@login_required
def start_tenure(id):
    group_id =id
    #member = Member.query.filter_by(group_id=group_id).all()
    n = Member.query.filter_by(group_id=group_id).order_by(Member.period).all()
    member = Member.query.filter_by(group_id=group_id).all()
    payee_list = Paylist.query.filter_by(group_id=group_id).first()  #querying the roles in Paylist model that have that group.ID
    users = User.query.all()
    paylist = list()
## OFURE this is where you will assign them to where they are to be 
    #shuffle(member)
    print(member)

    i = 0

    #for y in n:
    for y in member:
        for user in users:
            if y.user_id == user.id:
                i += 1
            
                #paylist.append(f'{i}.{user.username}')
                #paylist.append(user.id)
                paylist.insert(y.period, user.id)
                if len(member) == i:
                    ##payee_listToStr = ' '.join([str(elem) for elem in payee_list])
                    payee_list.payee_list = paylist
                    payee_list.start_tenure = True
                    db.session.commit()

                    #print(paylist)

    flash('tenure has started go to the go to payee list to see who takes the money first')
    return render_template('account_home.html', group_id=group_id, member=member , payee_list=payee_list, users=users, paylist=paylist)

'''   

@app.route('/start_tenure')
@login_required
def start_tenure():
    group_id = request.args.get('group_id')
    #member = Member.query.filter_by(group_id=group_id).all()
    #n = Member.query.filter_by(group_id=group_id).order_by(Member.period).all()
    member = Member.query.filter_by(group_id=group_id).all()
    payee_list = Paylist.query.filter_by(group_id=group_id).first()  #querying the roles in Paylist model that have that group.ID
    users = User.query.all()
    paylist = list()
## OFURE this is where you will assign them to where they are to be 
    #shuffle(member)

    i = 0

    #for y in n:
    for y in member:
        for user in users:
            if y.user_id == user.id:
                i += 1
            
                #paylist.append(f'{i}.{user.username}')
                #paylist.append(user.id)
                paylist.insert(y.period, user.id)
                if len(member) == i:
                    ##payee_listToStr = ' '.join([str(elem) for elem in payee_list])
                    payee_list.payee_list = paylist
                    payee_list.start_tenure = True
                    db.session.commit()

                    print(paylist)

    flash('tenure has started go to the go to payee list to see who takes the money first')
    return render_template('account_home.html', group_id=group_id, member=member , payee_list=payee_list, users=users, paylist=paylist)
'''

@app.route('/transactions/<int:group_id>/<int:period>')
@login_required
def view(group_id, period):



    group = Group.query.filter_by(id=group_id).first()
    #member = Member.query.filter_by(group_id=group_id).filter_by(period=period).first()
    monthly_target = group.monthly_target
    member_target = group.group_target
    print(period)
    print(monthly_target)
    print(member_target)

    
    p = period

    #savings side
    pv = monthly_target
    i = 0.14
    #n = 1
    n = p/12
    m = 12
    nm = n*m
    im = i/m

    step_1 = (1+im)**nm
    step_2 = step_1 -1 
    step_3 = step_2/im
    step_4 = step_3 * pv
    earnings = step_4 - (monthly_target * p) 
    print(step_4)
    print(earnings)

  
   # print(earnings)
    ##### EROI
    A = member_target - (monthly_target * p)
    print(A)
    r = 0.16
    n = 12
    #t = 1
    t = (12-p)/n
   

    nt = n * t


    e = 1+(r/n)
   

    er = e**nt
    print(er)
    ero = er - 1
    print(ero)
    eroi = ero*A
    print(eroi)

    payments = list()
    receipts = list()

    for earnings in range(p):
        receipts.append(monthly_target)
    
    for bills in range(12-p):
        payments.append(monthly_target + eroi/nt)

    transactions = receipts + payments
    print(transactions)
    

    return "successful"

@app.route('/transactions/<int:group_id>/<int:period>')
@login_required
def transactions(group_id, period):



    group = Group.query.filter_by(id=group_id).first()
    member = Member.query.filter_by(group_id=group_id).filter_by(period=period).first()
    period = member.period
    monthly_target = member.monthly_target
    member_target = member.member_target
    print(period)
    print(monthly_target)
    print(member_target)

    
    p = period

    #savings side
    pv = monthly_target
    i = 0.14
    #n = 1
    n = p/12
    m = 12
    nm = n*m
    im = i/m

    step_1 = (1+im)**nm
    step_2 = step_1 -1 
    step_3 = step_2/im
    step_4 = step_3 * pv
    earnings = step_4 - (monthly_target * p) 
    print(step_4)
    print(earnings)

  
   # print(earnings)



    ##### EROI
    A = member_target - (monthly_target * p)
    r = 0.16
    n = 12
    #t = 1
    t = (12-p)/n
   

    nt = n * t


    e = 1+(r/n)
   

    er = e**nt
    print(er)
    ero = er - 1
    print(ero)
    eroi = ero*A
    print(eroi)

    payments = list()
    receipts = list()

    for earnings in range(p):
        receipts.append(monthly_target)
    
    for bills in range(12-p):
        payments.append(monthly_target + eroi/nt)

    transactions = receipts + payments
    print(transactions)
    

    return "successful"




@app.route('/payee_list/<int:id>')
@login_required
def payee_list(id):
    #group_id = request.args.get('group_id')
    group = Group.query.get_or_404(id)
    #group = Group.query.get(group_id)
    member = Member.query.filter_by(group_id=id).all()
    paylist = Paylist.query.filter_by(group_id=id).first()

    if current_user.is_authenticated : # and current_user.is_admin
        return render_template('payee-list.html', group_id=id, group=group, member=member, paylist=paylist)
    else:
        return abort(404)


@app.route('/account_home')
@login_required
def account_home():
    groups = Group.query.all()

    return render_template('home.html', groups=groups)


@app.route('/account_profile')
@login_required
def account_profile():

    form = UpdateAccountInfoForm()
    form.username.data = current_user.username
    form.email.data = current_user.email
    profile_pix = url_for('static', filename=f'images/{current_user.profil_pix}')
    return render_template('account_home.html', form=form, current_user=current_user, profile_pix=profile_pix)

@app.route('/admin_signup')
@login_required
def admin_signup():

    form = AdminForm()
    return render_template('admin-signup.html', form=form,)

@app.route('/group_creation')
@login_required
def group_creation():

    form = GroupForm()

    return render_template('create-group-page.html', form=form)

@app.route('/group')
@login_required
def group():

    return render_template('group.html', current_user=current_user)


@app.route('/group_details/<int:id>', methods=['GET', 'POST'])
@login_required
def group_details(id):

    group = Group.query.get(id)
    member = Member.query.filter_by(group_id=id).filter_by(user_id=current_user.id).first()
    member_target = group.member_target
    member_limit=group.member_limit
    monthly_target = member_target/member_limit

    period = request.form.get('period')

    form = JoinForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        period = form.period.data
        user = User.query.filter_by(email=form.email.data.lower()).first()

        if user is not None and user.verify_password(form.password.data):

            ## The Period the user has chosen, how does it reflect here 

            new_member = Member(member_target=member_target, monthly_target=monthly_target,user_id=current_user.id, group_id=group.id, period=period)
            db.session.add(new_member)
            db.session.commit()

            current_user.group_in += 1
            db.session.commit()

            group.group_members += 1
            db.session.commit()

            res = make_response(jsonify({'message': f'you\'ve been added to {group.group_name}.'}), 200)
            return res
    
    return render_template('group-details.html', group=group, current_user=current_user, group_id=id, member=member, form=form)


@app.route('/member')
@login_required
def member():

    group_id  = request.args.get('group_id')

    group = Group.query.get(group_id)
    members_in_group = Member.query.filter_by(group_id=group_id).all()

    if current_user.is_authenticated and current_user.is_admin:
        return render_template('member-detail.html', members_in_group=members_in_group, group=group, group_id=group_id)
    else:
        return abort(404)

@app.route('/busery')
@login_required
def busery():
    group_id  = request.args.get('group_id')
    group = Group.query.get(group_id)
    members_in_group = Member.query.filter_by(group_id=group_id).all()

    if current_user.is_authenticated and current_user.is_admin:
        return render_template('busery.html', group=group, members_in_group=members_in_group, group_id=group_id)
    else:
        return abort(404)
    
@app.route('/admin_pannel')
@login_required
def admin_pannel():
    form = ChangeAdminForm()
    group_id  = request.args.get('group_id')
    group = Group.query.get(group_id)
    paylist = Paylist.query.filter_by(group_id=group_id).first()

    if current_user.is_authenticated and current_user.is_admin:
        return render_template('admin-pannel.html', group=group, group_id=group_id, form=form, paylist=paylist)
    else:
        return abort(404)

@app.route('/create_account', methods=['GET', 'POST'])
def create_account():
    form = CreateForm()

    if form.validate_on_submit():
        name = form.name.data
        if form.balance.data > 0:
            balance = form.balance.data
        else:
            balance = 0

        # Add new bank account to database
        new_account = Account(name=name,balance=balance)
        db.session.add(new_account)
        db.session.commit()
        new_transaction = Transaction('deposit','account opening',new_account.id,balance)
        db.session.add(new_transaction)
        db.session.commit()
        session['username'] = new_account.name

        return redirect(url_for('login'))

    return render_template('create_account.html',form=form)

@app.route('/my_account', methods=['GET', 'POST'])
def my_account():
    recharge_form = RechargeForm()
    deposit_form = DepositForm()
    transfer_form = TransferForm()
    if session['username'] is None:
        return render_template('my_account.html')
    user = session['username']
    account = Account.query.filter_by(name=user).first()
    transactions = Transaction.query.filter_by(account_id=account.id).order_by(Transaction.date.desc())

    if deposit_form.deposit.data and deposit_form.validate():
        id = account.id
        amount = deposit_form.amount.data
        account = Account.query.get(id)
        if account.deposit_withdraw('deposit',amount):
            new_transaction = Transaction('deposit','self deposit',account.id,amount)
            db.session.add(new_transaction)
            db.session.commit()
            return redirect(url_for('my_account'))
        else:
            #flash = you do not have sufficient funds to perform this operation
            return redirect(url_for('my_account'))

    elif recharge_form.withdraw.data and recharge_form.validate():
        id = account.id
        amount = recharge_form.amount.data
        account = User.query.get(id)
        if account.deposit_withdraw('withdraw',amount):
            new_transaction = Transaction('withdraw','self withdraw',account.id,(amount*(-1)))
            db.session.add(new_transaction)
            db.session.commit()
            return redirect(url_for('my_account'))
        else:
            #flash = you do not have sufficient funds to perform this operation
            return redirect(url_for('my_account'))
            
    elif transfer_form.transfer.data and transfer_form.validate():
        id = account.id
        amount = transfer_form.amount.data
        account_id = transfer_form.account_id.data
        password = transfer_form.password.data #To be HASHED      ### Account they are transfering to 
        account = Account.query.get(id)
        if check_password_hash(account.password,password):
            if account.deposit_withdraw('withdraw',amount):
                new_transaction = Transaction('transfer out',f'transfer to account {account_id}',account.id,(amount*(-1)))
                db.session.add(new_transaction)
                recipient = Account.query.get(account_id)
                if recipient.deposit_withdraw('deposit',amount):
                    new_transaction2 = Transaction('transfer in',f'transfer from account {account.id}',account_id,amount)
                    db.session.add(new_transaction2)
                    db.session.commit()
                    return redirect(url_for('my_account'))
                else:
                    #flash = you do not have sufficient funds to perform this operation
                    return redirect(url_for('my_account'))
            else:
                #flash = you do not have sufficient funds to perform this operation
                return redirect(url_for('my_account'))
        else:
            return '<h1>Invalid Account Password</h1>'

    return render_template('my_account.html',user=user,account=account,transactions=transactions,deposit_form=deposit_form,transfer_form=transfer_form, recharge_form=recharge_form)

@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    form = DeleteForm()

    if form.validate_on_submit():
        id = form.id.data
        password = form.password.data #To be HASHED
        account = Account.query.get(id)
        if check_password_hash(account.password,password):
            #db.session.delete(account)
            account.active = False
            db.session.commit()
            return redirect(url_for('list_accounts'))
        else:
            return redirect(url_for('list_accounts')) #'<h1>Invalid Account ID & Password combination</h1>'

    return render_template('delete_account.html',form=form)

@app.route('/list_accounts')
def list_accounts():
    # Grab a list of accounts from database.
    accounts = Account.query.filter_by(active=True)
    return render_template('list_accounts.html', accounts=accounts)
class WithdrawForm(FlaskForm):

    amount = FloatField('Withdraw Amount: ', [DataRequired()])
    withdraw = SubmitField('Withdraw Amount')

class DepositForm(FlaskForm):

    amount = FloatField('Deposit Amount: ', [DataRequired()])
    deposit = SubmitField('Deposit Amount')

class TransferForm(FlaskForm):

    account_id = IntegerField("Recipient's Account ID: ", [DataRequired()])
    amount = FloatField('Transfer Amount: ', [DataRequired()])
    password = PasswordField('Account password: ', [DataRequired()])
    transfer = SubmitField('Transfer Amount')

class DeleteForm(FlaskForm):

    id = IntegerField('Account ID to Delete: ', [DataRequired()])
    password = PasswordField('Account password: ', [DataRequired(), EqualTo('pwd_confirm', message='Passwords must match')])
    pwd_confirm = PasswordField('Confirm account password: ')
    submit = SubmitField('Delete Account')


class CreateForm(FlaskForm):

    name = StringField('Name of Account: ', [DataRequired()])
    balance = FloatField('Opening balance (optional)')
    submit = SubmitField('Create Account')


class RechargeForm(FlaskForm):

    amount = FloatField('Amount: ', [DataRequired()])
    phone_number = FloatField('Phone Number: ', [DataRequired()])
    withdraw = SubmitField('Buy Airtime')





if __name__ == '__main__':
    app.run()