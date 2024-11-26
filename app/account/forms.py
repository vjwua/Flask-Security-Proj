from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed
from wtforms import StringField, PasswordField, SubmitField, FileField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo, ValidationError
from flask_login import current_user
from app.auth.models import User

class ChangePasswordForm(FlaskForm):
    email = StringField("Електронна пошта", validators=[DataRequired("Це поле обовʼязкове"), Email()])
    password = PasswordField("Новий пароль", validators=[
                            DataRequired("Пароль повинен від 8 символів, щонайменше одну велику та малу літеру, цифру та спецсимвол."),
                            Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$")
                        ])
    confirm_password = PasswordField("Підтвердити новий пароль", validators=[
                            DataRequired("Пароль повинен від 8 символів, щонайменше одну велику та малу літеру, цифру та спецсимвол."),
                            Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"), EqualTo('password')
                        ])
    submit = SubmitField("Змінити")

class UpdateAccountForm(FlaskForm):
    username = StringField("Імʼя", validators=[DataRequired(message="Імʼя повинен містити від 4 до 20 символів"), Length(min=4, max=20),
    Regexp('^[A-Za-z][A-Za-z0-9_.]*$', message='Імʼя має містити букви, цифри, крапку та нижнє підкреслення')])

    email = StringField("Електронна пошта", validators=[DataRequired(message="Це поле обовʼязкове"), Email()])

    picture = FileField("Оновити аватар", validators=[FileAllowed(['jpg', 'png'])])

    about_me = TextAreaField("Опишіть себе", validators=[Length(max=140)])

    submit = SubmitField("Оновити")

    def validate_email(self, field):
        if field.data != current_user.email:
            if User.query.filter_by(email=field.data).first():
                raise ValidationError('Ця пошта уже використовується.')
        
    def validate_username(self, field):
        if field.data != current_user.username:
            if User.query.filter_by(username=field.data).first():
                raise ValidationError('Це імʼя уже використовується.')