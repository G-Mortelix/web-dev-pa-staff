import os, re, shutil
from functools import wraps
from dotenv import load_dotenv
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import case, ForeignKey
from sqlalchemy.orm import relationship
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

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


# SECTION BREAKS!!
# DATABASE MODELS
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

class UserDepartment(db.Model):
    __tablename__ = 'user_department'
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id', ondelete="CASCADE"), primary_key=True)
    dept_id = db.Column(db.Integer, db.ForeignKey('departments.dept_id', ondelete="CASCADE"), primary_key=True)

    # Relationships for convenience
    user = db.relationship('User', backref=db.backref('user_departments', cascade="all, delete-orphan"))
    department = db.relationship('Department', backref=db.backref('user_departments', cascade="all, delete-orphan"))


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
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials. Please try again.', 'error')
    return render_template('login.html')

# PARTITION FIRST!!!
# FUNCTIONS BELOW ARE ALL ASSOCIATED WITH THE HOMEPAGE

@app.route('/home')
@login_required
def home():
    pdf_structure = {}

    departments = Department.query.all()
    user_permissions = Permission.query.filter_by(user_id=current_user.user_id).all()

    # Map user permissions
    user_permission_map = {}
    for perm in user_permissions:
        if perm.dept_id not in user_permission_map:
            user_permission_map[perm.dept_id] = {'write': False, 'delete': False}
        user_permission_map[perm.dept_id]['write'] |= perm.write_permission
        user_permission_map[perm.dept_id]['delete'] |= perm.delete_permission


    # Add default permissions for departments without explicit permissions
    default_permissions = {
        dept.dept_id: {'write': False, 'delete': False}
        for dept in departments
    }
    permissions = {**default_permissions, **user_permission_map}

    if current_user.role_id == 1:  # Admin can view all folders
        departments = Department.query.all()
    else:
        user_departments = [ud.dept_id for ud in current_user.user_departments]
        # Always include the "General" department (assuming dept_id = 4)
        departments = Department.query.filter(Department.dept_id.in_(user_departments + [4])).all()


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


# SECTION BREAK!!
# ROUTES FOR CONTENT MANAGEMENT
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


# NEW PARTITION!!
# FUNCTIONS BENEATH ARE ALL ASSOCIATED WITH ADMIN DASHBOARD
@app.route('/admin_dashboard')
@login_required
@super_admin_required
def admin_dashboard():
    roles = Role.query.all()
    departments = Department.query.all()
    permissions = Permission.query.all()
    users = User.query.filter(User.role_id != 1).all()

    departments_serialized = [{"dept_id": dept.dept_id, "dept_name": dept.dept_name} for dept in departments]

    return render_template(
        'admin_dashboard.html',
        roles=roles,
        departments=departments_serialized,
        permissions=permissions,
        users=users
    )


# SECTION BREAK!!
# ROUTES FOR MANAGE USERS

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
        dept_ids = request.form.getlist('dept_ids')  # Get list of selected department IDs
        
        # Validate inputs
        if not username or not password or not role_id:
            flash('All fields are required.', 'error')
            return redirect(url_for('register_user'))

        # Check if the username is already taken
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already taken. Please choose a different one.', 'error')
            return redirect(url_for('admin_dashboard'))  # Redirect back to admin dashboard

        if len(dept_ids) > 4:  # Limit departments to 4
            flash('A user cannot be assigned to more than 4 departments.', 'error')
            return redirect(url_for('admin_dashboard'))

        # Hash the password
        hashed_password = generate_password_hash(password)

        primary_dept_id = int(dept_ids[0]) if dept_ids else None  # First selected dept as primary
        new_user = User(username=username, password_hash=hashed_password, role_id=role_id, dept_id=primary_dept_id)
        db.session.add(new_user)
        db.session.flush()  # Flush to get the user_id

        if dept_ids:
            valid_departments = [dept.dept_id for dept in departments]
            for dept_id in dept_ids:
                if int(dept_id) not in valid_departments:
                    flash('Invalid department selected.', 'error')
                    return redirect(url_for('admin_dashboard'))
                user_department = UserDepartment(user_id=new_user.user_id, dept_id=int(dept_id))
                db.session.add(user_department)

        db.session.commit()
        flash('User registered successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_dashboard.html', roles=roles, departments=departments)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@super_admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    departments = Department.query.all()
    roles = Role.query.all()

    if request.method == 'POST':
        username = request.form['username']
        role_id = request.form.get('role_id')
        dept_ids = request.form.getlist('dept_ids')  # Get selected department IDs

        # Check if the username is already taken by another user
        existing_user = User.query.filter(User.username == username, User.user_id != user_id).first()
        if existing_user:
            flash(f"Username '{username}' is already taken by another user.", 'error')
            return redirect(url_for('admin_dashboard'))

        # Validate inputs
        if not dept_ids:
            flash('At least one department must be assigned.', 'error')
            return redirect(url_for('admin_dashboard'))

        if len(dept_ids) > 4:
            flash('A user cannot be assigned to more than 4 departments.', 'error')
            return redirect(url_for('admin_dashboard'))

        # Update username and role
        user.username = username
        user.role_id = int(role_id)

        # Clear and reassign departments
        UserDepartment.query.filter_by(user_id=user.user_id).delete()
        for dept_id in dept_ids:
            user_department = UserDepartment(user_id=user.user_id, dept_id=int(dept_id))
            db.session.add(user_department)

        # Update the user's primary department (users.dept_id) to the first selected department
        user.dept_id = int(dept_ids[0])
        
        db.session.commit()
        flash(f"User '{username}' updated successfully!", 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_dashboard.html', user=user, departments=departments, roles=roles)

@app.route('/get_user_data/<int:user_id>', methods=['GET'])
@login_required
@super_admin_required
def get_user_data(user_id):
    user = User.query.get_or_404(user_id)
    departments = [ud.dept_id for ud in user.user_departments]  # All associated departments

    # Fetch all departments for display
    all_departments = [
        {"dept_id": dept.dept_id, "dept_name": dept.dept_name} for dept in Department.query.all()
    ]

    return jsonify({
        "username": user.username,
        "role_id": user.role_id,
        "departments": departments,  # Send associated department IDs
        "all_departments": all_departments
    })

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@super_admin_required
def delete_user(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            flash("User not found.", "error")
            return redirect(url_for('admin_dashboard'))

        # Check for associated records in other tables (e.g., permissions)
        Permission.query.filter_by(user_id=user_id).delete(synchronize_session=False)

        # Delete the user
        db.session.delete(user)
        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        flash(f"Error while deleting user: {e}", "error")

    return redirect(url_for('admin_dashboard'))


# SECTION BREAK!! 
# ROUTES FOR PERMISSION

@app.route('/add_permission', methods=['POST'])
@login_required
@super_admin_required
def add_permission():
    user_id = request.form.get('user_id')
    dept_id = request.form.get('dept_id')
    write_permission = request.form.get('write_permission') == '1'
    delete_permission = request.form.get('delete_permission') == '1'

    if not user_id or not dept_id:
        flash('User ID and Department ID are required.', 'error')
        return redirect(url_for('admin_dashboard'))  # Ensure a redirect

    existing_permission = Permission.query.filter_by(user_id=user_id, dept_id=dept_id).first()
    if existing_permission:
        flash('Permission already exists for this user and department.', 'error')
        return redirect(url_for('admin_dashboard'))  # Ensure a redirect

    # Check if the user and department exist
    user = User.query.get(user_id)
    if user.role_id == 1:  # Prevent adding permissions for admins
        flash('Cannot add permissions for admins.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    department = Department.query.get(dept_id)
    if not user or not department:
        flash('Invalid user or department.', 'error')
        return redirect(url_for('admin_dashboard'))  # Ensure a redirect
    
    # Validate that the user belongs to the department or has the right permissions
    if user.role_id != 1 and user.dept_id != int(dept_id):  # Admins bypass validation
        flash(f"User '{user.username}' does not belong to the '{department.dept_name}' department.", 'error')
        return redirect(url_for('admin_dashboard'))

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
        flash('Permission added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))  # Success case
    except Exception as e:
        db.session.rollback()
        flash(f'Failed to add permission: {e}', 'error')
        return redirect(url_for('admin_dashboard'))  # Failure case

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
    
    flash('Permission not found.', 'error')
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
            flash('Permission successfully updated.', 'success')
            return jsonify(success=True)
        except Exception as e:
            db.session.rollback()
            flash(f'Failed to update permission: {e}', 'error')
            return jsonify(success=False, error="Failed to update permission."), 500
    else:
        flash('Permission not found.', 'error')
        return jsonify(success=False, error="Permission not found"), 404
    
@app.route('/delete_permission/<int:permission_id>', methods=['DELETE'])
@login_required
@super_admin_required
def delete_permission(permission_id):
    permission = Permission.query.get(permission_id)
    if not permission:
        flash('Permission not found.', 'error')
        return jsonify(success=False, error="Permission not found"), 404

    try:
        db.session.delete(permission)
        db.session.commit()
        flash('Permission successfully deleted.', 'success')
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        flash(f'Failed to delete permission: {e}', 'error')
        return jsonify(success=False, error="Failed to delete permission."), 500


# SECTION BREAKS!!
# ROUTES FOR DEPARTMENTS
@app.route('/add_department', methods=['POST'])
@login_required
@super_admin_required
def add_department():
    dept_name = request.form['dept_name'].strip()
    if not dept_name:
        flash('Department name cannot be empty.', 'error')
        return redirect(url_for('admin_dashboard'))

    existing_dept = Department.query.filter_by(dept_name=dept_name).first()
    if existing_dept:
        flash('Department already exists.', 'error')
        return redirect(url_for('admin_dashboard'))

    new_department = Department(dept_name=dept_name)
    db.session.add(new_department)
    db.session.commit()

    flash('Department added successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_department', methods=['POST'])
@login_required
@super_admin_required
def delete_department():
    dept_name = request.form['dept_name'].strip()
    if not dept_name:
        flash('Please select a department to delete.', 'error')
        return redirect(url_for('admin_dashboard'))

    department = Department.query.filter_by(dept_name=dept_name).first()
    if not department:
        flash('Department not found.', 'error')
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
        flash('Department and all associated data deleted successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        db.session.rollback()
        flash(f'Error while deleting department: {e}', 'error')

    return redirect(url_for('admin_dashboard'))


# LOGOUT
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5001)