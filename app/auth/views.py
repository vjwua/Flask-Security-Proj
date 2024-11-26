import email_validator
from itsdangerous import URLSafeTimedSerializer
import datetime
import logging
import pyotp, qrcode
from io import BytesIO
import base64

from flask import flash, render_template, redirect, url_for, request, session
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
from app import app, captcha, mail
from config import Config
app.config.from_object(Config)

from . import auth_blueprint

from .forms import LoginForm, RegisterForm, TwoFactorForm
from .models import db, User

MAX_LOGIN_ATTEMPTS = 5

@auth_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('account_bp.account'))
    
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        confirm_password = form.confirm_password.data
        image_file = form.image_file.data

        if password == confirm_password:
            new_user = User(username=username, email=email, password=password, image_file=image_file)
            db.session.add(new_user)
            db.session.commit()
            token = generate_token(new_user.email)
            confirm_url = url_for('account_bp.confirm_email', token=token, _external=True)
            html = render_template("confirm_email.html", confirm_url=confirm_url)
            subject = "Підтвердження паролю"
            send_email(new_user.email, subject, html)

            login_user(new_user)

            flash("Аккаунт зареєстровано, підтвердіть за поштою", category=("success")) #current state
            return redirect(url_for('account_bp.inactive'))
        else:
            flash("Паролі не збігаються", category=("warning"))
            return redirect(url_for('auth_bp.register'))
    
    return render_template("register.html", form=form)

@auth_blueprint.route("/resend")
@login_required
def resend_confirmation():
    if current_user.is_confirmed:
        flash("Ваш аккаунт вже був підтверджений", "success")
        return redirect(url_for('home_bp.home'))
    token = generate_token(current_user.email)
    confirm_url = url_for('account_bp.confirm_email', token=token, _external=True)
    html = render_template('confirm_email.html', confirm_url=confirm_url)
    subject = "Будь-ласка, підтвердіть пароль"
    send_email(current_user.email, subject, html)
    flash("Новий лист підтвердження був надісланий.", "success")
    return redirect(url_for('account_bp.inactive'))

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients = [to],
        html = template,
        sender = app.config["MAIL_DEFAULT_SENDER"],
    )
    mail.send(msg)

logging.basicConfig(filename='failed_logins.log', level=logging.INFO)

@auth_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('account_bp.account'))
    
    form = LoginForm()
    new_captcha = captcha.create()
    c_hash = request.form.get('captcha-hash')
    c_text = request.form.get('captcha-text')

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user:
            if user.failed_login_attempts is None:
                user.failed_login_attempts = 0
            if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS: #TBW
                flash("Ваш акаунт заблокований через занадто багато спроб входу. Спробуйте пізніше або зверніться до адміністратора.", category=("danger"))
                return redirect(url_for('auth_bp.login'))
            if user.validate_password(form.password.data):
                if form.remember.data:
                    if captcha.verify(c_hash, c_text):
                        if user.is_two_factor_enabled:
                            session['2fa_user_id'] = user.id
                            return redirect(url_for('auth_bp.two_factor_auth'))
                        user.failed_login_attempts = 0
                        db.session.commit()
                        login_user(user, remember=form.remember.data)
                        flash("Вхід виконано", category=("success"))
                        return redirect(url_for('account_bp.account'))
                    else:
                        flash("Капча введена неправильно, спробуйте ще раз", category=("warning"))
                else:
                    flash("Ви не запамʼятали себе, введіть дані ще раз", category=("warning"))
            user.failed_login_attempts += 1
            db.session.commit()
            logging.info(f'Failed login attempt for {form.email.data} at {datetime.datetime.now()}')
            flash(f"Пароль введений неправильно, ви маєте ще {6 - user.failed_login_attempts} спроб(а)", category=("warning"))
        else:
            flash("Вхід не виконано", category=("warning"))
            return redirect(url_for('auth_bp.login'))
    
    return render_template('login.html', form=form, captcha=new_captcha)

@auth_blueprint.route('/two_factor_auth', methods=['GET', 'POST'])
def two_factor_auth():
    form = TwoFactorForm()
    
    user_id = session.get('2fa_user_id')
    if not user_id:
        flash("Користувач не визначений", category=("warning"))
        return redirect(url_for('auth_bp.login'))
    
    user = User.query.get(user_id)
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.secret_token)
        
        if totp.verify(form.code.data):
            login_user(user)
            session.pop('2fa_user_id', None)
            user.failed_login_attempts = 0
            db.session.commit()
            flash("Вхід з 2FA виконано", category=("success"))
            return redirect(url_for('account_bp.account'))
        else:
            flash("Неправильний 2FA код, спробуйте ще раз", category=("danger"))
    return render_template('two_factor_auth.html', form=form)

@auth_blueprint.route('/enable_2fa', methods=['POST', 'GET'])
@login_required
def enable_2fa():
    if current_user.is_two_factor_enabled:
        flash("2FA ввімкнено", category=("success"))
        return redirect(url_for('account_bp.account'))
    
    current_user.secret_token = pyotp.random_base32()
    current_user.is_two_factor_enabled = True
    db.session.commit()
    
    totp = pyotp.TOTP(current_user.secret_token)
    provisioning_uri = totp.provisioning_uri(name=current_user.email, issuer_name="personal_flask_project")
    
    qr = qrcode.make(provisioning_uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")
    
    return render_template('enable_2fa.html', qr_code_base64=qr_code_base64)

@auth_blueprint.route('/disable_2fa', methods=['POST', 'GET'])
@login_required
def disable_2fa():
    current_user.is_two_factor_enabled = False  
    current_user.secret_token = None 
    db.session.commit()
    flash("2FA вимкнено", category=("success"))
    return redirect(url_for('account_bp.account'))

@auth_blueprint.route('/users')
@login_required
def users():
    all_users = User.query.all()
    return render_template('users.html', all_users=all_users)

@auth_blueprint.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('auth_bp.login'))

def generate_token(email):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    return serializer.dumps(email, salt=app.config["SECURITY_PASSWORD_SALT"])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    try:
        email = serializer.loads(
            token, salt=app.config["SECURITY_PASSWORD_SALT"], max_age=expiration
        )
        return email
    except Exception:
        return False