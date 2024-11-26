from flask import flash, render_template, request, redirect, url_for
from flask_login import current_user, login_required

from app import app, bcrypt
from .forms import ChangePasswordForm, UpdateAccountForm
from app.auth.models import db, User
from app.auth.views import confirm_token

from . import account_blueprint

from datetime import datetime
import os
import email_validator
import secrets
from PIL import Image

def get_user_info():
    user_os = os.name
    user_agent = request.headers.get('User-Agent')
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return user_os, user_agent, current_time

@account_blueprint.route('/base')
def index():
    user_os, user_agent, current_time = get_user_info()
    return render_template('base.html', user_os=user_os, user_agent=user_agent, current_time=current_time)

@account_blueprint.route('/info', methods=['GET'])
@login_required
def info():
    cookies = request.cookies

    return render_template('info.html', cookies=cookies)

@account_blueprint.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    cp_form = ChangePasswordForm()

    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.about_me = form.about_me.data

        if form.picture.data:
            current_user.image_file = save_picture(form.picture.data)

        db.session.commit()
        flash("Аккаунт оновлено", category=("success"))
        return redirect(url_for('account_bp.account'))
    
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.about_me.data = current_user.about_me

    return render_template('account.html', form=form, cp_form=cp_form)

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)
    form_picture.save(picture_path)
    return picture_fn

@account_blueprint.route('/change_password', methods=['POST'])
def change_password():
    cp_form = ChangePasswordForm()

    if cp_form.validate_on_submit():
        user = User.query.filter_by(email=cp_form.email.data).first()

        if user:
            new_password = cp_form.password.data
            confirm_new_password = cp_form.confirm_password.data

            if user:
                if new_password == confirm_new_password:
                    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                    user.password = hashed_password
                    db.session.commit()

                    flash("Пароль успішно змінено", category=("success"))
                    return redirect(url_for('account_bp.account'))
                else:
                    flash("Паролі не збігаються", category="danger")
        else:
            flash("Користувача з такою поштою не існує", category="danger")

        flash("Ви не змінили пароль", category=("danger"))
        return redirect(url_for('account_bp.account'))

    flash("Ви не набрали пароль. Спробуйте ще раз", category=("danger"))
    return redirect(url_for('account_bp.account'))

@account_blueprint.route("/confirm/<token>")
@login_required
def confirm_email(token):
    email = confirm_token(token)
    new_user = User.query.filter_by(email=current_user.email).first_or_404()
    if new_user.email == email:
        new_user.is_confirmed = True
        new_user.confirmed_on = datetime.now()
        db.session.add(new_user)
        db.session.commit()
        flash("Аккаунт підтверджено", category=("success"))
    else:
        flash("Активація невдала", category=("danger"))
    return redirect(url_for('home_bp.home'))

@account_blueprint.route("/inactive")
@login_required
def inactive():
    if current_user.is_confirmed:
        return redirect(url_for('account_bp.account'))
    return render_template("inactive.html")