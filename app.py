import os, re, shutil
from functools import wraps
from dotenv import load_dotenv
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import case, ForeignKey
from sqlalchemy.orm import relationship
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session, abort, send_from_directory

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
    dept_id = db.Column(db.Integer, db.ForeignKey('departments.dept_id'), nullable=True)

    role = db.relationship('Role', backref='users')
    department = db.relationship('Department', backref='users')

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

    permissions = db.relationship("Permission", back_populates="department")

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
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    dept_id = db.Column(db.Integer, db.ForeignKey('departments.dept_id'), nullable=False)
    read_permission = db.Column(db.Boolean, default=True)
    write_permission = db.Column(db.Boolean, default=False)
    delete_permission = db.Column(db.Boolean, default=False)

    # Define the relationships
    user = db.relationship("User", backref="permissions")
    department = db.relationship("Department", back_populates="permissions", foreign_keys=[dept_id])

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
    pdf_structure = {}

    departments = Department.query.all()
    user_permissions = Permission.query.filter_by(user_id=current_user.user_id).all()

    # Map user permissions
    user_permission_map = {
        perm.dept_id: {
            'write': perm.write_permission,
            'delete': perm.delete_permission
        }
        for perm in user_permissions
    }

    # Add default permissions for departments without explicit permissions
    default_permissions = {
        dept.dept_id: {'write': False, 'delete': False}
        for dept in departments
    }
    permissions = {**default_permissions, **user_permission_map}

    if current_user.role_id == 1:  # Admin can view all folders
        departments = Department.query.order_by(
            case((Department.dept_name == "General", 0), else_=1)
        ).all()
    else:
        departments = Department.query.filter(
            (Department.dept_id == current_user.dept_id) | (Department.dept_id == 4)
        ).order_by(case((Department.dept_name == "General", 0), else_=1)).all()

    for department in departments:
        folders = Folder.query.filter_by(dept_id=department.dept_id).all()
        pdf_structure[department.dept_name] = {}

        # Sort folders by numeric values (including decimals with two places)
        def folder_sort_key(folder):
            parts = re.split(r'(\d+(?:\.\d{1,2})?)', folder.folder_name)
            # Convert numeric parts to float for proper sorting
            return [float(part) if part.replace('.', '', 1).isdigit() else part.lower() for part in parts]

        sorted_folders = sorted(folders, key=folder_sort_key)

        for folder in sorted_folders:
            sanitized_folder_name = sanitize_folder_name(folder.folder_name)
            pdfs = PDF.query.filter_by(folder_id=folder.folder_id).all()
            pdf_files = [pdf.pdf_name for pdf in pdfs]
            pdf_structure[department.dept_name][sanitized_folder_name] = {
                "files": pdf_files,
                "dept_id": folder.dept_id
            }

    return render_template('index.html', pdf_structure=pdf_structure, permissions=permissions)

@app.route('/admin_dashboard')
@login_required
@super_admin_required
def admin_dashboard():
    roles = Role.query.all()
    departments = Department.query.all()
    permissions = Permission.query.all()
    users = User.query.all()
    return render_template(
        'admin_dashboard.html',
        roles=roles,
        departments=departments,
        permissions=permissions,
        users=users
    )

@app.route('/add_folder', methods=['POST'])
@login_required
def add_folder():
    if current_user.role_id != 1:  # Only admin can add folders
        return jsonify(success=False, error="You do not have permission to add folders.")

    data = request.get_json()
    folder_name = data.get('folderName', '').strip()
    dept_name = data.get('deptName', '').strip()

    if not folder_name or not dept_name:
        return jsonify(success=False, error="Folder name and department name cannot be empty.")

    department = Department.query.filter_by(dept_name=dept_name).first()
    if not department:
        return jsonify(success=False, error="Department not found.")

    existing_folder = Folder.query.filter_by(folder_name=folder_name, dept_id=department.dept_id).first()
    if existing_folder:
        return jsonify(success=False, error="Folder with the same name already exists in this department.")

    # Create a new folder entry in the database
    new_folder = Folder(folder_name=folder_name, dept_id=department.dept_id)
    db.session.add(new_folder)
    db.session.commit()

    # Create the actual folder on the file system
    sanitized_folder_name = sanitize_folder_name(folder_name)
    sanitized_dept_name = sanitize_folder_name(dept_name)
    folder_path = os.path.join(app.static_folder, 'pdffile', sanitized_dept_name, sanitized_folder_name)
    os.makedirs(folder_path, exist_ok=True)

    return jsonify(success=True)

def sanitize_folder_name(name):
    """
    Sanitize a folder name by removing invalid characters.
    """
    # Replace invalid characters with an underscore
    sanitized_name = re.sub(r'[<>:"/\\|?*]', "_", name)
    return sanitized_name.strip()  # Remove leading and trailing whitespace


@app.route('/edit_folder', methods=['POST'])
@login_required
def edit_folder():
    if current_user.role_id != 1:
        return jsonify(success=False, error="You do not have permission to edit folders.")
    
    data = request.get_json()
    old_folder_name = data.get('oldFolderName', '').strip()
    new_folder_name = data.get('newFolderName', '').strip()

    # Retrieve the folder based on the old folder name
    folder = Folder.query.filter_by(folder_name=old_folder_name).first()
    if not folder:
        return jsonify(success=False, error="Folder not found.")

    # Check if a folder with the new name already exists in the same department
    existing_folder = Folder.query.filter_by(folder_name=new_folder_name, dept_id=folder.dept_id).first()
    if existing_folder:
        return jsonify(success=False, error="A folder with this name already exists.")

    # Update the folder name in the database
    old_sanitized_folder_name = sanitize_folder_name(old_folder_name)
    new_sanitized_folder_name = sanitize_folder_name(new_folder_name)

    department = Department.query.get(folder.dept_id)
    sanitized_dept_name = sanitize_folder_name(department.dept_name)

    old_folder_path = os.path.join(app.static_folder, 'pdffile', sanitized_dept_name, old_sanitized_folder_name)
    new_folder_path = os.path.join(app.static_folder, 'pdffile', sanitized_dept_name, new_sanitized_folder_name)

    try:
        # Rename the folder in the filesystem
        if os.path.exists(old_folder_path):
            os.rename(old_folder_path, new_folder_path)

        # Update the folder name in the database
        folder.folder_name = new_folder_name

        # Update PDF paths in the database
        pdfs = PDF.query.filter_by(folder_id=folder.folder_id).all()
        for pdf in pdfs:
            old_pdf_path = os.path.join(old_folder_path, pdf.pdf_name)
            new_pdf_path = os.path.join(new_folder_path, pdf.pdf_name)

            # Update the path in the database
            pdf.pdf_path = new_pdf_path

        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, error=f"Failed to rename folder: {e}")

@app.route('/upload_pdf', methods=['POST'])
@login_required
def upload_pdf():
    folder_name = request.form.get('folder').strip()
    sanitized_folder_name = sanitize_folder_name(folder_name)
    folder = Folder.query.filter_by(folder_name=sanitized_folder_name).first()

    if not folder:
        return jsonify(success=False, error="Folder not found.")

    if current_user.role_id != 1:
        permission = Permission.query.filter_by(user_id=current_user.user_id, dept_id=folder.dept_id).first()
        if not permission or not permission.write_permission:
            return jsonify(success=False, error="You do not have permission to upload PDFs.")

    if 'pdfFile' not in request.files:
        return jsonify(success=False, error="No file part in the request.")

    file = request.files['pdfFile']
    filename = secure_filename(file.filename.strip())

    department = Department.query.get(folder.dept_id)
    sanitized_dept_name = sanitize_folder_name(department.dept_name)
    folder_path = os.path.join(app.static_folder, 'pdffile', sanitized_dept_name, sanitized_folder_name)

    os.makedirs(folder_path, exist_ok=True)

    file_path = os.path.join(folder_path, filename)
    file.save(file_path)

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

    # Retrieve the folder based on the folder name
    folder = Folder.query.filter_by(folder_name=folder_name).first()
    if not folder:
        return jsonify(success=False, error="Folder not found.")

    department = Department.query.get(folder.dept_id)
    sanitized_folder_name = sanitize_folder_name(folder_name)
    sanitized_dept_name = sanitize_folder_name(department.dept_name)

    # Define folder path for deletion from disk
    folder_path = os.path.join(app.static_folder, 'pdffile', sanitized_dept_name, sanitized_folder_name)
    
    # Remove folder from database
    db.session.delete(folder)
    db.session.commit()

    try:
        if os.path.exists(folder_path):
            shutil.rmtree(folder_path)  # Delete the folder and all contents
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e))
    
@app.route('/delete_pdf', methods=['POST'])
@login_required
def delete_pdf():
    # Get folder and PDF details
    data = request.get_json()
    folder_name = data.get('folderName').strip()
    pdf_name = data.get('pdfName').strip()

    folder = Folder.query.filter_by(folder_name=folder_name).first()
    if not folder:
        return jsonify(success=False, error="Folder not found.")

    # Admins bypass permission checks
    if current_user.role_id != 1:
        # Check user permissions
        permission = Permission.query.filter_by(user_id=current_user.user_id, dept_id=folder.dept_id).first()
        if not permission or not permission.delete_permission:
            return jsonify(success=False, error="You do not have permission to delete PDFs.")

    # Retrieve the PDF and sanitize paths
    pdf = PDF.query.filter_by(folder_id=folder.folder_id, pdf_name=pdf_name).first()
    if not pdf:
        return jsonify(success=False, error="PDF not found.")

    department = Department.query.get(folder.dept_id)
    sanitized_folder_name = sanitize_folder_name(folder.folder_name)
    sanitized_dept_name = sanitize_folder_name(department.dept_name)
    pdf_path = os.path.join(app.static_folder, 'pdffile', sanitized_dept_name, sanitized_folder_name, pdf_name)

    try:
        # Delete file and database entry
        if os.path.exists(pdf_path):
            os.remove(pdf_path)
        db.session.delete(pdf)
        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e))

@app.route('/add_department', methods=['POST'])
@login_required
@super_admin_required
def add_department():
    dept_name = request.form['dept_name'].strip()
    if not dept_name:
        flash('Department name cannot be empty.')
        return redirect(url_for('admin_dashboard'))

    existing_dept = Department.query.filter_by(dept_name=dept_name).first()
    if existing_dept:
        flash('Department already exists.')
        return redirect(url_for('admin_dashboard'))

    new_department = Department(dept_name=dept_name)
    db.session.add(new_department)
    db.session.commit()

    flash('Department added successfully!')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_department', methods=['POST'])
@login_required
@super_admin_required
def delete_department():
    dept_name = request.form['dept_name'].strip()
    if not dept_name:
        flash('Please select a department to delete.')
        return redirect(url_for('admin_dashboard'))

    department = Department.query.filter_by(dept_name=dept_name).first()
    if not department:
        flash('Department not found.')
        return redirect(url_for('admin_dashboard'))

    try:
        # Delete related folders and their PDFs
        folders = Folder.query.filter_by(dept_id=department.dept_id).all()
        for folder in folders:
            # Delete PDFs in the folder
            PDFs = PDF.query.filter_by(folder_id=folder.folder_id).all()
            for pdf in PDFs:
                # Remove the PDF file from the filesystem
                if os.path.exists(pdf.pdf_path):
                    os.remove(pdf.pdf_path)
                db.session.delete(pdf)
            # Delete the folder record
            sanitized_folder_name = sanitize_folder_name(folder.folder_name)
            sanitized_dept_name = sanitize_folder_name(department.dept_name)
            folder_path = os.path.join(app.static_folder, 'pdffile', sanitized_dept_name, sanitized_folder_name)
            if os.path.exists(folder_path):
                shutil.rmtree(folder_path)  # Remove folder from filesystem
            db.session.delete(folder)

        # Delete the department itself
        db.session.delete(department)
        db.session.commit()
        flash('Department and all associated data deleted successfully!')
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        db.session.rollback()
        flash(f'Error while deleting department: {e}')
        return redirect(url_for('admin_dashboard'))

@app.route('/register', methods=['GET', 'POST'], endpoint='register_user')
@super_admin_required
@login_required
def register_user():
    roles = Role.query.all()
    departments = Department.query.all()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role_id = request.form.get('role_id')
        dept_id = request.form.get('dept_id') or None
        
        # Check if the username is already taken
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already taken. Please choose a different one.')
            return redirect(url_for('register_user'))

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Create a new user with the hashed password
        new_user = User(username=username, password_hash=hashed_password, role_id=role_id, dept_id=dept_id) 
        db.session.add(new_user)
        db.session.commit()
        
        flash('User registered successfully!')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_dashboard.html', roles=roles, departments=departments)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@super_admin_required
def delete_user(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify(success=False, error="User not found."), 404

        # Check for associated records in other tables (e.g., permissions)
        Permission.query.filter_by(user_id=user_id).delete(synchronize_session=False)

        # Delete the user
        db.session.delete(user)
        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        # Log the error for debugging
        print(f"Error while deleting user {user_id}: {e}")
        db.session.rollback()
        return jsonify(success=False, error="Failed to delete user. Please check the logs for details."), 500


@app.route('/add_permission', methods=['POST'])
@login_required
@super_admin_required
def add_permission():
    user_id = request.form.get('user_id')
    dept_id = request.form.get('dept_id')
    write_permission = request.form.get('write_permission') == '1'
    delete_permission = request.form.get('delete_permission') == '1'

    if not user_id or not dept_id:
        return jsonify(success=False, error="User ID and Department ID are required."), 400
    
    existing_permission = Permission.query.filter_by(user_id=user_id, dept_id=dept_id).first()
    if existing_permission:
        return jsonify(success=False, error="Permission already exists for this user and department."), 400

    # Check if the user and department exist
    user = User.query.get(user_id)
    department = Department.query.get(dept_id)

    if not user or not department:
        return jsonify(success=False, error="Invalid user or department."), 400

    # Add the new permission
    new_permission = Permission(
        user_id=user_id,
        dept_id=dept_id,
        write_permission=write_permission,
        delete_permission=delete_permission
    )
    db.session.add(new_permission)
    try:
        db.session.commit()
        print("Permission successfully added.")
        return jsonify(success=True, message="Permission added successfully.")
    except Exception as e:
        print("Error while adding permission:", e)
        db.session.rollback()
        return jsonify(success=False, error="Failed to add permission."), 500

@app.route('/get_permission_data/<int:permission_id>', methods=['GET'])
@login_required
@super_admin_required
def get_permission_data(permission_id):
    permission = Permission.query.get(permission_id)
    if permission:
        return jsonify({
            'read_permission': permission.read_permission,
            'write_permission': permission.write_permission,
            'delete_permission': permission.delete_permission
        })
    return jsonify({'error': 'Permission not found'}), 404

@app.route('/update_permission', methods=['POST'])
@login_required
@super_admin_required
def update_permission():
    data = request.get_json()
    permission_id = data.get('permission_id')
    read_permission = data.get('read_permission')
    write_permission = data.get('write_permission')
    delete_permission = data.get('delete_permission')

    print(f"Updating permission {permission_id}: Read={read_permission}, Write={write_permission}, Delete={delete_permission}")

    permission = Permission.query.get(permission_id)
    if permission:
        permission.read_permission = read_permission
        permission.write_permission = write_permission
        permission.delete_permission = delete_permission
        try:
            db.session.commit()
            print("Permission successfully updated.")
            return jsonify(success=True)
        except Exception as e:
            print("Error while updating permission:", e)
            db.session.rollback()
            return jsonify(success=False, error="Failed to update permission."), 500
    else:
        print("Permission not found.")
        return jsonify(success=False, error="Permission not found"), 404

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5001)