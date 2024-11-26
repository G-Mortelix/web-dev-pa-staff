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
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session, abort, send_file

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

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    log_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=True)  # Nullable for anonymous actions
    action = db.Column(db.String(255), nullable=False)  # Description of the action
    target_file = db.Column(db.String(255), nullable=True)  # File accessed or manipulated (if applicable)
    ip_address = db.Column(db.String(50), nullable=True)  # Optional: Store IP for better tracking
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    extra_data = db.Column(db.JSON, nullable=True)  # Store additional data (flexible)

    # Relationships
    user = db.relationship('User', backref='audit_logs')

    def __repr__(self):
        return f"<AuditLog(log_id={self.log_id}, user_id={self.user_id}, action='{self.action}', target_file='{self.target_file}', timestamp={self.timestamp})>"

def master_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role_id != 0:  # Only Master Admin
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role_id not in [0, 1]:  # Master Admin or Admin
            abort(403)  # Forbidden
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
            
            # Log successful login in the audit log
            new_log = AuditLog(
                user_id=user.user_id,  # Log the logged-in user's ID
                action="Logged in",    # Action description
                ip_address=request.remote_addr  # IP address of the client
            )
            db.session.add(new_log)
            db.session.commit()
            
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

    # Determine accessible departments based on the current user's role
    if current_user.role_id == 0:  # Master Admin
        departments = Department.query.all()  # Access all departments
    elif current_user.role_id == 1:  # Admin
        departments = Department.query.all()  # Admin also has access to all departments
    else:  # Regular users
        user_departments = [ud.dept_id for ud in current_user.user_departments]
        # Include the "General" department (assuming dept_id = 4)
        departments = Department.query.filter(Department.dept_id.in_(user_departments + [4])).all()

    # Fetch permissions for the current user
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

    # Build PDF structure for accessible departments
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
    if current_user.role_id not in [0, 1]:
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

    new_log = AuditLog(
        user_id=current_user.user_id,
        action="Created folder",
        target_file=f"{sanitized_dept_name}/{sanitized_folder_name}",
        ip_address=request.remote_addr,
        extra_data={"department": dept_name}
    )
    db.session.add(new_log)
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
    if current_user.role_id not in [0, 1]:
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
        
        new_log = AuditLog(
            user_id=current_user.user_id,
            action="Renamed folder",
            target_file=f"{sanitized_dept_name}/{old_sanitized_folder_name}",
            ip_address=request.remote_addr,
            extra_data={
                "new_folder_name": new_folder_name,
                "department": department.dept_name
            }
        )
        db.session.add(new_log)

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

    if current_user.role_id not in [0, 1]:
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

    # Log the file upload
    new_log = AuditLog(
        user_id=current_user.user_id,
        action="Uploaded file",
        target_file=file_path,
        ip_address=request.remote_addr,
        extra_data={"folder": folder_name, "department": department.dept_name}
    )
    db.session.add(new_log)

    db.session.commit()
    return jsonify(success=True)

@app.route('/delete_folder', methods=['POST'])
@login_required
def delete_folder():
    if current_user.role_id not in [0, 1]:
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
    new_log = AuditLog(
        user_id=current_user.user_id,
        action="Deleted folder",
        target_file=f"{sanitized_dept_name}/{sanitized_folder_name}",
        ip_address=request.remote_addr,
        extra_data={"department": department.dept_name}
    )
    db.session.add(new_log)
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
    if current_user.role_id not in [0, 1]:
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
        # Delete the file and database entry
        if os.path.exists(pdf_path):
            os.remove(pdf_path)
        db.session.delete(pdf)

        # Log the file deletion
        new_log = AuditLog(
            user_id=current_user.user_id,
            action="Deleted file",
            target_file=pdf_path,
            ip_address=request.remote_addr,
            extra_data={"folder": folder_name, "department": department.dept_name}
        )
        db.session.add(new_log)

        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, error=str(e))


# NEW PARTITION!!
# FUNCTIONS BENEATH ARE ALL ASSOCIATED WITH ADMIN DASHBOARD
@app.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
    roles = Role.query.all()
    departments = Department.query.all()
    permissions = Permission.query.all()
    
    # Role-based user fetching
    if current_user.role_id == 0:  # Master Admin
        users = User.query.all()  # Fetch all users
    elif current_user.role_id == 1:  # Admin
        users = User.query.filter(User.role_id == 2).all()  # Fetch only regular users
    else:
        abort(403)  # Regular users cannot access the dashboard

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
@admin_required
@login_required
def register_user():
    roles = Role.query.all()
    departments = Department.query.all()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role_id = request.form.get('role_id')
        dept_ids = request.form.getlist('dept_ids')  # Get list of selected department IDs

        # Role restrictions
        if current_user.role_id == 1 and role_id in [0, 1]:
            flash("You do not have permission to register an admin or master admin.", "error")
            return redirect(url_for('register_user'))

        # Validate inputs
        if not username or not password or not role_id:
            flash('All fields are required.', 'error')
            return redirect(url_for('register_user'))
        
        # Filter out invalid department IDs
        dept_ids = [int(dept_id) for dept_id in dept_ids if dept_id.isdigit()]

        # Set primary department for non-admin roles
        primary_dept_id = dept_ids[0] if dept_ids else None

        # Prevent assigning departments to Admins and Master Admins
        if role_id in [0, 1] and dept_ids:
            flash("Admins and Master Admins cannot be assigned to any department.", "error")
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
@admin_required
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
@admin_required
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
@admin_required
def delete_user(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify(success=False, error="User not found")
            return redirect(url_for('admin_dashboard'))

        # Role-based checks
        if current_user.role_id == 1 and user.role_id != 2:  # Admin cannot delete Admin or Master Admin
            return jsonify(success=False, error="You do not have permission to delete this user.")
        elif current_user.role_id == 0 and user.role_id == 0:  # Master Admin cannot delete another Master Admin
            return jsonify(success=False, error="You cannot delete another Master Admin.")

        # Delete associated records in other tables
        Permission.query.filter_by(user_id=user_id).delete()
        AuditLog.query.filter_by(user_id=user_id).delete()
        UserDepartment.query.filter_by(user_id=user_id).delete()

        # Perform deletion
        db.session.delete(user)
        db.session.commit()
        return jsonify(success=True)
    
        flash("User deleted successfully.", "success")
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting the user: {e}", "error")
        return redirect(url_for('admin_dashboard'))


# SECTION BREAK!! 
# ROUTES FOR PERMISSION

@app.route('/add_permission', methods=['GET', 'POST'])
@login_required
@admin_required
def add_permission():
    users = User.query.filter(User.role_id > 1).all()  # Exclude admins and master admins

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        write_permissions = request.form.getlist('write_permission')  # List of selected department IDs
        delete_permissions = request.form.getlist('delete_permission')

        if not user_id:
            flash('User selection is required.', 'error')
            return redirect(url_for('admin_dashboard'))

        user = User.query.get(user_id)
        if not user or user.role_id in [0, 1]:
            flash('Invalid user selection.', 'error')
            return redirect(url_for('admin_dashboard'))

        user_departments = [ud.dept_id for ud in user.user_departments]

        # Add or update permissions for each department
        for dept_id in user_departments:
            write_permission = str(dept_id) in write_permissions
            delete_permission = str(dept_id) in delete_permissions

            existing_permission = Permission.query.filter_by(user_id=user_id, dept_id=dept_id).first()
            if existing_permission:
                existing_permission.write_permission = write_permission
                existing_permission.delete_permission = delete_permission
            else:
                new_permission = Permission(
                    user_id=user_id,
                    dept_id=dept_id,
                    write_permission=write_permission,
                    delete_permission=delete_permission
                )
                db.session.add(new_permission)

        try:
            db.session.commit()
            flash('Permissions updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Failed to update permissions: {e}', 'error')

        return redirect(url_for('admin_dashboard'))

    return render_template('admin_dashboard.html', users=users)


@app.route('/get_permission_data/<int:user_id>', methods=['GET'])
@login_required
@admin_required
def get_permission_data(user_id):
    permissions = Permission.query.filter_by(user_id=user_id).all()
    if not permissions:
        return jsonify(error="No permissions found for this user"), 404

    serialized_permissions = [
        {
            "dept_id": permission.dept_id,
            "write_permission": permission.write_permission,
            "delete_permission": permission.delete_permission
        }
        for permission in permissions
    ]

    return jsonify(success=True, permissions=serialized_permissions)

@app.route('/update_permission', methods=['POST'])
@login_required
@admin_required
def update_permission():
    data = request.get_json()
    user_id = data.get('user_id')
    updated_permissions = data.get('permissions')  # List of department permissions

    if not user_id or not updated_permissions:
        return jsonify(success=False, error="User ID and permissions are required"), 400

    try:
        for permission_data in updated_permissions:
            dept_id = permission_data.get('dept_id')
            permission = Permission.query.filter_by(user_id=user_id, dept_id=dept_id).first()

            if permission:
                permission.write_permission = permission_data.get('write_permission', permission.write_permission)
                permission.delete_permission = permission_data.get('delete_permission', permission.delete_permission)
            else:
                # Add a new permission if it doesn't exist
                new_permission = Permission(
                    user_id=user_id,
                    dept_id=dept_id,
                    write_permission=permission_data.get('write_permission', False),
                    delete_permission=permission_data.get('delete_permission', False)
                )
                db.session.add(new_permission)

        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, error=str(e))
    
@app.route('/delete_permission/<int:permission_id>', methods=['DELETE'])
@login_required
@admin_required
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
@admin_required
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
@admin_required
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

# SECTION BREAK!!
# MASTER ADMIN SECTION
@app.route('/fetch_audit_logs', methods=['GET'])
@login_required
@admin_required
def fetch_audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()

    serialized_logs = [
        {
            "user": log.user.username if log.user else "System",
            "action": log.action,
            "target_file": log.target_file,
            "ip_address": log.ip_address,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "extra_data": log.extra_data,
        }
        for log in logs
    ]

    return jsonify(success=True, logs=serialized_logs)



# SECTION BREAK!!
# LOG REPORT 
@app.route('/view_pdf/<int:pdf_id>', methods=['GET'])
@login_required
def view_pdf(pdf_id):
    pdf = PDF.query.get_or_404(pdf_id)
    
    # Log the file access
    new_log = AuditLog(
        user_id=current_user.user_id,
        action="Accessed file",
        target_file=pdf.pdf_path,
        ip_address=request.remote_addr
    )
    db.session.add(new_log)
    db.session.commit()

    # Return the PDF viewer (existing functionality)
    return send_file(pdf.pdf_path)


# LOGOUT
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5001)