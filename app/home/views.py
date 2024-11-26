from flask import render_template, request

from . import home_blueprint

@home_blueprint.route('/base')
def index():
   return render_template('base.html')

@home_blueprint.route('/home')
@home_blueprint.route('/')
def home():
    return render_template('home.html')