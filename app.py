import os, shutil
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from functools import wraps

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('secret_key')
if not app.secret_key:
    raise ValueError("No secret key for this Flask app")

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('db_url')
if not app.secret_key:
    raise ValueError("No database url for this Flask app")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate (app, db)

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.role_id'))
    dept_id = db.Column(db.Integer, db.ForeignKey('departments.dept_id'))

    def get_id(self):
        return str(self.user_id)

class Role(db.Model):
    __tablename__ = 'roles'
    role_id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(50), unique=True, nullable=False)

class Department(db.Model):
    __tablename__ = 'departments'
    dept_id = db.Column(db.Integer, primary_key=True)
    dept_name = db.Column(db.String(50), unique=True, nullable=False)

class Folder(db.Model):
    __tablename__ = 'folders'
    folder_id = db.Column(db.Integer, primary_key=True)
    folder_name = db.Column(db.String(100), nullable=False)
    dept_id = db.Column(db.Integer, db.ForeignKey('departments.dept_id'))
    time_created = db.Column(db.DateTime, default=db.func.current_timestamp())

class PDF(db.Model):
    __tablename__ = 'pdfs'
    pdf_id = db.Column(db.Integer, primary_key=True)
    folder_id = db.Column(db.Integer, db.ForeignKey('folders.folder_id'))
    pdf_name = db.Column(db.String(100), nullable=False)
    pdf_path = db.Column(db.String(255), nullable=False)
    upload_time = db.Column(db.DateTime, default=db.func.current_timestamp())

class Permission(db.Model):
    __tablename__ = 'permissions'
    permission_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.role_id'))
    folder_id = db.Column(db.Integer, db.ForeignKey('folders.folder_id'))
    read_permission = db.Column(db.Boolean, default=True)
    write_permission = db.Column(db.Boolean, default=False)
    delete_permission = db.Column(db.Boolean, default=False)

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if the current user is logged in and has a 'super-admin' role
        if not current_user.is_authenticated or current_user.role_id != 1:  
            abort(403)  # Forbidden access
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials. Please try again.')
    return render_template('login.html')

@app.route('/home')
@login_required
def home():
    # Dictionary to hold folders and their PDFs
    pdf_structure = {}

    if current_user.role_id == 1:  # Admin can view all folders
        folders = Folder.query.all()
    else:
        folders = Folder.query.filter(
            (Folder.dept_id == current_user.dept_id) | (Folder.dept_id == 4)  # 4 is General
        ).all()
    
    # Iterate through folders and files in the PDFs directory
    for folder in folders:
        pdfs = PDF.query.filter_by(folder_id = folder.folder_id).all()
        pdf_files = [pdf.pdf_name for pdf in pdfs]
        pdf_structure[folder.folder_name] = pdf_files

    return render_template('index.html', pdf_structure=pdf_structure)

@app.route('/admin_dashboard')
@login_required
@super_admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/add_folder', methods=['POST'])
@login_required
def add_folder():
    if current_user.role_id != 1:  # Only admin can add folders
        return jsonify(success=False, error="You do not have permission to add folders.")

    data = request.get_json()
    folder_name = data.get('folderName', '').strip()  # Preserve case and spaces
    dept_name = data.get('deptName', '').strip()

    # Ensure the folder name and department name are not empty
    if not folder_name or not dept_name:
        return jsonify(success=False, error="Folder name and department name cannot be empty.")

    # Check if the department exists
    department = Department.query.filter_by(dept_name=dept_name).first()
    if not department:
        return jsonify(success=False, error="Department not found.")

    # Check for an existing folder with the exact name and department (case-sensitive)
    existing_folder = Folder.query.filter_by(folder_name=folder_name, dept_id=department.dept_id).first()
    if existing_folder:
        return jsonify(success=False, error="Folder with the same name already exists in this department.")

    # Create the new folder entry
    new_folder = Folder(folder_name=folder_name, dept_id=department.dept_id)
    db.session.add(new_folder)
    db.session.commit()

    return jsonify(success=True)

@app.route('/upload_pdf', methods=['POST'])
@login_required
def upload_pdf():
    if current_user.role_id != 1:
        return jsonify(success=False, error="You do not have permission to upload PDFs.")
    
    # Check if a file is uploaded
    if 'pdfFile' not in request.files:
        return jsonify(success=False, error="No file part in the request.")
    
    file = request.files['pdfFile']
    folder_name = request.form.get('folder').strip()
    filename = secure_filename(file.filename.strip())

    # Validate that a folder was selected and file is a PDF
    if not folder_name or file.filename == '':
        return jsonify(success=False, error="Folder or file not specified.")
    
    if not file.filename.lower().endswith('.pdf'):
        return jsonify(success=False, error="Only PDF files are allowed.")

    # Secure the filename and set the path to save the file
    folder = Folder.query.filter_by(folder_name=folder_name).first()
    if not folder:
        return jsonify(success=False, error="Folder not found.")
    
    folder_path = os.path.join(app.static_folder, 'pdffile', folder_name)
    os.makedirs(folder_path, exist_ok=True)
    file_path = os.path.join(folder_path, filename)
    file.save(file_path)

    # Create a new PDF entry
    new_pdf = PDF(folder_id=folder.folder_id, pdf_name=filename, pdf_path=file_path)
    db.session.add(new_pdf)
    db.session.commit()

    return jsonify(success=True)

@app.route('/delete_folder', methods=['POST'])
@login_required
def delete_folder():
    if current_user.role_id != 1:
        return jsonify(success=False, error="You do not have permission to delete folders.")
    
    data = request.get_json()
    folder_name = data.get('folderName', '').strip()
    dept_name = data.get('deptName', '').strip()

    # Check if the department exists
    department = Department.query.filter_by(dept_name=dept_name).first()
    if not department:
        return jsonify(success=False, error="Department not found.")

    # Locate the folder with exact case sensitivity in the specified department
    folder = Folder.query.filter_by(folder_name=folder_name, dept_id=department.dept_id).first()
    if not folder:
        return jsonify(success=False, error="Folder not found.")

    # Remove folder from database
    db.session.delete(folder)
    db.session.commit()

    # Define folder path for deletion from disk
    folder_path = os.path.join(app.static_folder, 'pdffile', folder_name)
    try:
        if os.path.exists(folder_path):
            shutil.rmtree(folder_path)  # Delete the folder and all contents
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e))

@app.route('/delete_pdf', methods=['POST'])
@login_required
def delete_pdf():
    if current_user.role_id != 1:
        return jsonify(success=False, error="You do not have permission to delete PDFs.")

    data = request.get_json()
    folder_name = data.get('folderName').strip()
    pdf_name = data.get('pdfName').strip()

    pdf = PDF.query.join(Folder).filter(
        Folder.folder_name == folder_name,
        PDF.pdf_name == pdf_name
    ).first()

    if not pdf:
        return jsonify(success=False, error="PDF not found.")

    # Path to the original PDF file
    pdf_path = os.path.join(app.static_folder, 'pdffile', folder_name, pdf_name)
    trash_folder = os.path.join(app.static_folder, 'trash')
    trash_path = os.path.join(trash_folder, pdf_name)

    # Ensure the trash folder exists
    os.makedirs(trash_folder, exist_ok=True)

    try:
        # Move the file to the trash folder with the full path
        shutil.move(pdf_path, trash_path)
        db.session.delete(pdf)
        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e))

@app.route('/register', methods=['GET', 'POST'])
@super_admin_required
@login_required
def register():
    roles = Role.query.all()
    departments = Department.query.all()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role_id = request.form.get('role_id')
        dept_id = request.form.get('dept_id')
        
        # Check if the username is already taken
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already taken. Please choose a different one.')
            return redirect(url_for('register'))

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Create a new user with the hashed password
        new_user = User(username=username, password_hash=hashed_password, role_id=role_id, dept_id=dept_id) 
        db.session.add(new_user)
        db.session.commit()
        
        flash('User registered successfully!')
        return redirect(url_for('home'))
    
    return render_template('registration.html', roles=roles, departments=departments)

@app.route('/manage_permissions')
@login_required
@super_admin_required
def manage_permissions():
    permissions = Permission.query.all()
    roles = Role.query.all()
    folders = Folder.query.all()
    return render_template('manage_permissions.html', permissions=permissions, roles=roles, folders=folders)

@app.route('/manage_folders')
@login_required
@super_admin_required
def manage_folders():
    folders = Folder.query.all()
    departments = Department.query.all()
    return render_template('manage_folders.html', folders=folders, departments=departments)

@app.route('/manage_pdfs')
@login_required
@super_admin_required
def manage_pdfs():
    pdfs = PDF.query.all()
    folders = Folder.query.all()
    return render_template('manage_pdfs.html', pdfs=pdfs, folders=folders)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5001)
