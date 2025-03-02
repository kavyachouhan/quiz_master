from flask import Flask, render_template
from quiz_master.extensions import db  # Updated import
from dotenv import load_dotenv
import os

app = Flask(__name__)

load_dotenv()

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SUPABASE_DB_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

db.init_app(app)

with app.app_context():
    from quiz_master.models.models import *  # Updated import
    db.create_all()

    admin_role = Admin.query.filter_by(username = 'admin').first()
    if not admin_role:
        admin_role = Admin(
            username = 'admin',
            email = 'admin@gmail.com'
        )
        admin_role.password = 'admin123'
        db.session.add(admin_role)
    db.session.commit()

from quiz_master.api import *  # Updated import
from quiz_master.routes import *  # Updated import