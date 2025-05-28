from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import json
import os
from datetime import datetime
from openpyxl import Workbook
from io import BytesIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this to a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class BlockData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    block_name = db.Column(db.String(50), nullable=False)
    floors = db.Column(db.String(100), nullable=False)  # JSON string of floor status
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username, is_admin=True).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials')
    return render_template('admin_login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    blocks = BlockData.query.filter_by(user_id=current_user.id).all()
    block_data = {block.block_name: json.loads(block.floors) for block in blocks}
    completed_blocks = {block.block_name: block.completed for block in blocks}
    return render_template('dashboard.html', block_data=block_data, completed_blocks=completed_blocks)

@app.route('/update-block', methods=['POST'])
@login_required
def update_block():
    data = request.json
    block_name = data.get('block')
    floors = data.get('floors')
    
    block = BlockData.query.filter_by(block_name=block_name, user_id=current_user.id).first()
    if not block:
        block = BlockData(block_name=block_name, user_id=current_user.id)
    
    block.floors = json.dumps(floors)
    block.completed = all(floors)
    db.session.add(block)
    db.session.commit()
    
    return {'status': 'success'}

@app.route('/delete-block', methods=['POST'])
@login_required
def delete_block():
    data = request.json
    block_name = data.get('block')
    
    block = BlockData.query.filter_by(block_name=block_name, user_id=current_user.id).first()
    if block:
        db.session.delete(block)
        db.session.commit()
    
    return {'status': 'success'}

@app.route('/report')
@login_required
def report():
    blocks = BlockData.query.filter_by(user_id=current_user.id).all()
    block_summary = []
    
    for block in blocks:
        floors = json.loads(block.floors)
        completed_floors = sum(1 for f in floors if f)
        block_summary.append({
            'block': block.block_name,
            'completed_floors': completed_floors,
            'percent': (completed_floors / len(floors)) * 100
        })
    
    return render_template('report.html', block_summary=block_summary)

@app.route('/download')
@login_required
def download():
    blocks = BlockData.query.filter_by(user_id=current_user.id).all()
    
    wb = Workbook()
    ws = wb.active
    ws.title = "Field Service Report"
    
    # Headers
    ws.append(['Block', 'Floor', 'Status', 'Completed'])
    
    # Data
    for block in blocks:
        floors = json.loads(block.floors)
        for i, status in enumerate(floors, 1):
            ws.append([block.block_name, f'Floor {i}', 'Completed' if status else 'Pending', status])
    
    # Save to BytesIO
    excel_file = BytesIO()
    wb.save(excel_file)
    excel_file.seek(0)
    
    return send_file(
        excel_file,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f'field_service_report_{datetime.now().strftime("%Y%m%d")}.xlsx'
    )

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Create admin user
def create_admin():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            hashed_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
            admin = User(username='admin', password=hashed_password, is_admin=True)
            db.session.add(admin)
            db.session.commit()

if __name__ == '__main__':
    create_admin()
    app.run(debug=True)
