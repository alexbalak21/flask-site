from flask import Blueprint, render_template

views = Blueprint('views', __name__)


@views.get('/')
def home():
    return render_template('home.html')


