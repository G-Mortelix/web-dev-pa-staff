from functools import wraps
from datetime import timedelta
from dotenv import load_dotenv
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os, re, shutil, logging, traceback, time, json
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session, abort, send_file

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('secret_key')
if not app.secret_key:
    raise ValueError("No secret key for this Flask app")

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('db_url')
if not app.config['SQLALCHEMY_DATABASE_URI']:
    raise ValueError("No database url for this Flask app")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate (app, db)

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,  # Ensures the connection is alive before using it
    'pool_size': 10,  # Number of connections in the pool
    'pool_timeout': 30,  # Timeout for connection requests
    'pool_recycle': 1800,  # Recycle connections after 30 minutes
}

application = app
app.permanent_session_lifetime = timedelta(minutes=30)  # Adjust as needed

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

## password generation
password = "jy-123"
hashed_password = generate_password_hash(password)

print(f"Hashed Password: {hashed_password}")

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

# Updated model with backref renaming
class Folder(db.Model):
    __tablename__ = 'folders'

    folder_id = db.Column(db.Integer, primary_key=True)
    folder_name = db.Column(db.String(100), nullable=False)
    dept_id = db.Column(db.Integer, db.ForeignKey('departments.dept_id'))
    parent_folder_id = db.Column(db.Integer, db.ForeignKey('folders.folder_id'), nullable=True)  # Self-reference for parent folder
    time_created = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    # Relationship to Department
    department = db.relationship('Department', backref='folders')   

    # Relationship to parent folder
    parent_folder = db.relationship('Folder', remote_side=[folder_id])

    # Relationship to child folders
    child_folders = db.relationship(
        'Folder', 
        backref=db.backref('parent_folder_relation', remote_side=[folder_id]), 
        lazy='dynamic', 
        overlaps="parent_folder"  # Prevents conflict between parent_folder and child_folders
    )

    __table_args__ = (
        db.Index('ix_folders_dept_id', 'dept_id'),
        db.Index('ix_folders_parent_folder_id', 'parent_folder_id'),
    )

    def __repr__(self):
        return f"Folder({self.folder_name}, Parent: {self.parent_folder.folder_name if self.parent_folder else 'None'})"

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

def redirect_root():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/')
def root():
    return redirect_root()

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
            session.permanent = True
            flash('Login successful!', 'success')
            
            # Log successful login in the audit log
            log_audit(
                action="Logged in",    # Action description
            )
            db.session.commit()
            
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials. Please try again.', 'error')
    
    return render_template('login.html')

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Server Error: {error}, Traceback: {traceback.format_exc()}")
    return "Internal Server Error", 500

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Helper function to recursively build folder structure
def build_folder_structure(folder):
    # This function would return a folder structure, including child folders
    folder_data = {
        'folder_id': folder.folder_id,
        'folder_name': folder.folder_name,
        'children': []
    }

    # Include child folders (recursively)
    for child in folder.child_folders:
        folder_data['children'].append(build_folder_structure(child))
    return folder_data
    
@app.route('/home')
@login_required
def home():
    # Get search and filter parameters from the form
    search_query = request.args.get('search', '').strip().lower()  # Search query
    department_filter = request.args.get('department_filter', type=int)  # Department filter

    # Determine accessible departments based on the user's role
    departments = get_accessible_departments()

    # Apply department filter
    if department_filter:
        departments = [d for d in departments if d.dept_id == department_filter]

    # Fetch and map permissions
    permissions = get_user_permissions(departments)

    # Build PDF structure for accessible departments
    pdf_structure = build_pdf_structure(departments, search_query)

    return render_template('index.html', pdf_structure=pdf_structure, permissions=permissions, departments=departments)

def get_accessible_departments():
    """
    Returns the list of departments accessible to the current user.
    """
    if current_user.role_id == 0:  # Master Admin
        return Department.query.all()
    elif current_user.role_id == 1:  # Admin
        return Department.query.all()
    else:  # Regular users
        user_departments = [ud.dept_id for ud in current_user.user_departments]
        return Department.query.filter(Department.dept_id.in_(user_departments + [1])).all()

def get_user_permissions(departments):
    """
    Returns the user's permissions for the given departments.
    """
    user_permissions = Permission.query.filter_by(user_id=current_user.user_id).all()
    user_permission_map = {perm.dept_id: {'write': perm.write_permission, 'delete': perm.delete_permission}
                           for perm in user_permissions}
    
    # Add default permissions for departments without explicit permissions
    default_permissions = {dept.dept_id: {'write': False, 'delete': False} for dept in departments}
    return {**default_permissions, **user_permission_map}

def build_pdf_structure(departments, search_query=None):
    """
    Builds the folder structure for the given departments, filtering based on the search query.
    """
    pdf_structure = {}
    for department in departments:
        # Fetch all folders in the department
        all_folders = Folder.query.filter_by(dept_id=department.dept_id).all()
        sorted_folders = sorted(all_folders, key=folder_sort_key)

        pdf_structure[department.dept_name] = {}

        # Get parent folders (those with no parent folder)
        parent_folders = [folder for folder in sorted_folders if folder.parent_folder_id is None]

        # Loop through parent folders and build the structure
        for parent_folder in parent_folders:
            folder_data = build_folder_data(parent_folder, sorted_folders, search_query)
            if folder_data:
                pdf_structure[department.dept_name][parent_folder.folder_name] = folder_data

    return pdf_structure

def build_folder_data(folder, sorted_folders, search_query=None):
    """
    Builds data for a single folder, including its child and subchild folders,
    while filtering based on the search query.
    """
    # Fetch PDFs for this folder
    pdfs = PDF.query.filter_by(folder_id=folder.folder_id).all()
    pdf_files = [pdf.pdf_name for pdf in pdfs]

    # Get child folders (direct children) for the current folder
    child_folders = [f for f in sorted_folders if f.parent_folder_id == folder.folder_id]

    # Recursively build child folder data and filter based on search query
    child_folder_data = []
    for child in child_folders:
        child_data = build_folder_data(child, sorted_folders, search_query)
        if child_data:  # Include only matching children
            child_folder_data.append(child_data)

    # Include the folder if:
    # - It matches the search query
    # - It has matching children
    # - It has matching PDFs
    if (
        search_query is None or
        search_query in folder.folder_name.lower() or
        child_folder_data
    ):
        return {
            "folder_name": folder.folder_name,
            "folder_id": folder.folder_id,
            "files": pdf_files if search_query in folder.folder_name.lower() else [],
            "child_folders": child_folder_data,
            "dept_id": folder.dept_id,
            "parent_folder_id": folder.parent_folder_id,
        }
    return None  # Exclude folders that do not match


def build_child_data(child, sorted_folders, search_query):
    """
    Builds data for a child folder, including its subchild folders.
    """
    pdfs = PDF.query.filter_by(folder_id=child.folder_id).all()
    pdf_files = [pdf.pdf_name for pdf in pdfs]

    # If search query exists, skip folders that don't match
    if search_query and search_query not in child.folder_name.lower() and not pdf_files:
        return None

    # Get subchild folders (sub-subfolders) for the current child
    subchild_folders = [f for f in sorted_folders if f.parent_folder_id == child.folder_id]
    subchild_data_list = []

    for subchild in subchild_folders:
        subchild_data = build_subchild_data(subchild, search_query)
        if subchild_data:
            subchild_data_list.append(subchild_data)

    return {
        'folder_name': child.folder_name,
        'folder_id': child.folder_id,
        'files': pdf_files,
        'child_folders': subchild_data_list
    }

def build_subchild_data(subchild, search_query):
    """
    Builds data for a subchild folder, including its PDFs.
    """
    pdfs = PDF.query.filter_by(folder_id=subchild.folder_id).all()
    pdf_files = [pdf.pdf_name for pdf in pdfs]

    # If search query exists, skip subfolders that don't match
    if search_query and search_query not in subchild.folder_name.lower() and not pdf_files:
        return None

    return {
        'folder_name': subchild.folder_name,
        'folder_id': subchild.folder_id,
        'files': pdf_files
    }

def folder_sort_key(folder):
    """
    Custom sort function to sort folders by numeric values in their names
    """
    parts = re.split(r'(\d+(?:\.\d{1,2})?)', folder.folder_name)
    return [float(part) if part.replace('.', '', 1).isdigit() else part.lower() for part in parts]



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
    parent_folder_name = data.get('parentFolderName', '').strip()  # Parent folder (may be None)

    if not folder_name or not dept_name:
        return jsonify(success=False, error="Folder name and department name cannot be empty.")

    department = Department.query.filter_by(dept_name=dept_name).first()
    if not department:
        return jsonify(success=False, error="Department not found.")
    
    parent_folder = None
    if parent_folder_name:  # Ensure it's properly assigned
        parent_folder = Folder.query.filter_by(folder_name=parent_folder_name, dept_id=department.dept_id).first()
        if not parent_folder:
            return jsonify(success=False, error="Parent folder not found.")

    # Ensure folder doesn't already exist in the department
    existing_folder = Folder.query.filter_by(folder_name=folder_name, dept_id=department.dept_id).first()
    if existing_folder:
        return jsonify(success=False, error="Folder with the same name already exists in this department.")

    # Create the new folder
    new_folder = Folder(folder_name=folder_name, dept_id=department.dept_id, parent_folder_id=parent_folder.folder_id if parent_folder else None)
    db.session.add(new_folder)
    db.session.commit()

    # Create the actual folder on the file system
    sanitized_folder_name = sanitize_folder_name(folder_name)
    sanitized_dept_name = sanitize_folder_name(dept_name)
    folder_path = os.path.join(app.static_folder, 'pdffile', sanitized_dept_name, sanitized_folder_name)
    os.makedirs(folder_path, exist_ok=True)

    log_audit(
        action="Added Folder",
        extra_data={"folder_name": folder_name, "department": dept_name, "parent_folder": parent_folder_name}
    )

    return jsonify(success=True)

@app.route('/add_subfolder', methods=['POST'])
@login_required
def add_subfolder():
    if current_user.role_id not in [0, 1]:
        return jsonify(success=False, error="You do not have permission to add subfolders.")

    data = request.get_json()
    folder_name = data.get('folderName', '').strip()
    dept_name = data.get('deptName', '').strip()
    parent_folder_name = data.get('parentFolderName', '').strip()  # Parent folder for subfolder

    if not folder_name or not dept_name or not parent_folder_name:
        return jsonify(success=False, error="Folder name, department name, and parent folder name cannot be empty.")

    department = Department.query.filter_by(dept_name=dept_name).first()
    if not department:
        return jsonify(success=False, error="Department not found.")

    parent_folder = Folder.query.filter_by(folder_name=parent_folder_name, dept_id=department.dept_id).first()
    if not parent_folder:
        return jsonify(success=False, error="Parent folder not found.")

    existing_folder = Folder.query.filter_by(folder_name=folder_name, dept_id=department.dept_id).first()
    if existing_folder:
        return jsonify(success=False, error="Folder with the same name already exists in this department.")

    # Create the subfolder with the correct parent_folder_id
    new_folder = Folder(folder_name=folder_name, dept_id=department.dept_id, parent_folder_id=parent_folder.folder_id)
    db.session.add(new_folder)
    db.session.commit()

    # Create the actual subfolder on the file system
    sanitized_folder_name = sanitize_folder_name(folder_name)
    sanitized_dept_name = sanitize_folder_name(dept_name)
    folder_path = os.path.join(app.static_folder, 'pdffile', sanitized_dept_name, sanitized_folder_name)
    os.makedirs(folder_path, exist_ok=True)

    log_audit(
        action="Added Subfolder",
        extra_data={"subfolder_name": folder_name, "parent_folder": parent_folder_name, "department": dept_name}
    )

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

    new_parent_folder_name = data.get('newParentFolderName', '').strip()

    folder = Folder.query.filter_by(folder_name=old_folder_name).first()
    if not folder:
        return jsonify(success=False, error="Folder not found.")

    department = Department.query.get(folder.dept_id)
    if not department:
        return jsonify(success=False, error="Department not found.")

    existing_folder = Folder.query.filter_by(folder_name=new_folder_name, dept_id=folder.dept_id).first()
    if existing_folder:
        return jsonify(success=False, error="A folder with this name already exists.")

    # Build old folder path
    old_folder_path = build_folder_path(department.dept_name, old_folder_name, folder)

    # Optionally change parent folder if needed (not strictly required for just renaming)
    original_parent_folder_id = folder.parent_folder_id
    new_parent_folder = None
    if new_parent_folder_name:
        new_parent_folder = Folder.query.filter_by(folder_name=new_parent_folder_name, dept_id=folder.dept_id).first()
        if not new_parent_folder:
            return jsonify(success=False, error="New parent folder not found.")
        folder.parent_folder_id = new_parent_folder.folder_id
    else:
        # If no new parent folder is specified, keep the original parent
        folder.parent_folder_id = original_parent_folder_id

    # Update the folder name in the DB object (not committed yet)
    folder.folder_name = new_folder_name

    # Build new folder path using the updated folder name
    new_folder_path = build_folder_path(department.dept_name, new_folder_name, folder)

    try:
        # Rename the folder on the filesystem if the old folder exists
        if os.path.exists(old_folder_path):
            os.rename(old_folder_path, new_folder_path)

        # Update all PDF paths
        pdfs = PDF.query.filter_by(folder_id=folder.folder_id).all()
        for pdf in pdfs:
            if pdf.pdf_path.startswith(old_folder_path):
                pdf.pdf_path = pdf.pdf_path.replace(old_folder_path, new_folder_path, 1)

        # Commit changes to DB
        db.session.commit()

        # Log folder edit
        log_audit(
            action="Edited Folder",
            extra_data={"old_name": old_folder_name, "new_name": new_folder_name, "department": department.dept_name}
        )

        return jsonify(success=True)
    except Exception as e:
        # In case of error, rollback to avoid partial changes
        db.session.rollback()

        # If the rename happened but DB commit failed, consider rolling back the filesystem rename
        # But usually, an exception before commit means no DB changes were persisted
        return jsonify(success=False, error=f"Failed to rename folder: {e}")

@app.route('/upload_pdf', methods=['POST'])
@login_required
def upload_pdf():
    folder_name = request.form.get('folder').strip()
    sanitized_folder_name = sanitize_folder_name(folder_name)
    
    # Get the folder object, which is the parent folder
    folder = Folder.query.filter_by(folder_name=sanitized_folder_name).first()

    if not folder:
        return jsonify(success=False, error="Folder not found.")

    # Check user permission
    if current_user.role_id not in [0, 1]:
        permission = Permission.query.filter_by(user_id=current_user.user_id, dept_id=folder.dept_id).first()
        if not permission or not permission.write_permission:
            return jsonify(success=False, error="You do not have permission to upload PDFs.")

    # Check if the file is included in the request
    if 'pdfFile' not in request.files:
        return jsonify(success=False, error="No file part in the request.")
    
    file = request.files['pdfFile']
    
    # Validate the file type (check if it is a PDF)
    if not file or not file.filename.lower().endswith('.pdf'):
        return jsonify(success=False, error="Uploaded file is not a PDF.")

    filename = secure_filename(file.filename.strip())

    # Check if the file is empty
    if len(filename) == 0:
        return jsonify(success=False, error="No file selected.")

    # Retrieve department information
    department = Department.query.get(folder.dept_id)
    sanitized_dept_name = sanitize_folder_name(department.dept_name)

    # Build the correct folder path based on the folder hierarchy
    folder_path = build_folder_path(sanitized_dept_name, sanitized_folder_name, folder)

    # Create the folder structure if it doesn't exist
    os.makedirs(folder_path, exist_ok=True)

    # Define the file path and check if the file already exists
    file_path = os.path.join(folder_path, filename)
    if os.path.exists(file_path):
        # If file already exists, generate a unique filename to avoid overwriting
        base_name, ext = os.path.splitext(filename)
        counter = 1
        while os.path.exists(file_path):
            filename = f"{base_name}_{counter}{ext}"
            file_path = os.path.join(folder_path, filename)
            counter += 1

    # Save the file
    try:
        file.save(file_path)
    except Exception as e:
        return jsonify(success=False, error=f"Failed to save the file: {str(e)}")

    # Add PDF entry to the database
    new_pdf = PDF(folder_id=folder.folder_id, pdf_name=filename, pdf_path=file_path)
    db.session.add(new_pdf)

    # Log the file upload action
    log_audit(
        action="Uploaded file",
        target_file=file_path,
        extra_data={"folder": folder_name, "department": department.dept_name, "filename": filename, "file_size": os.path.getsize(file_path)}
    )

    # Commit the session
    try:
        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, error=f"Failed to commit changes to the database: {str(e)}")


def build_folder_path(department_name: str, folder_name: str, folder: Folder) -> str:
    """
    Helper function to recursively build the folder path.
    This function takes into account subfolders and child subfolders.
    """
    # Start with the root static folder path for PDF files
    root_path = os.path.join(app.static_folder, 'pdffile')

    # Sanitize the department and main folder names
    sanitized_dept_name = sanitize_folder_name(department_name)
    sanitized_folder_name = sanitize_folder_name(folder_name)

    # If the folder is a child folder, recursively build the path by including parent folder
    if folder.parent_folder_id:
        parent_folder = Folder.query.get(folder.parent_folder_id)
        parent_folder_path = build_folder_path(department_name, parent_folder.folder_name, parent_folder)
        return os.path.join(parent_folder_path, sanitized_folder_name)
    
    # Otherwise, return the folder path for the root folder
    return os.path.join(root_path, sanitized_dept_name, sanitized_folder_name)

@app.route('/delete_folder', methods=['POST'])
@login_required
def delete_folder():
    # Check if the user has permission to delete folders
    if current_user.role_id not in [0, 1]:
        return jsonify(success=False, error="You do not have permission to delete folders.")

    data = request.get_json()
    folder_name = data.get('folderName', '').strip()

    # Retrieve the folder based on the folder name
    folder = Folder.query.filter_by(folder_name=folder_name).first()
    if not folder:
        return jsonify(success=False, error="Folder not found.")

    # Define folder paths for deletion (sanitize)
    department = Department.query.get(folder.dept_id)
    sanitized_folder_name = sanitize_folder_name(folder_name)
    sanitized_dept_name = sanitize_folder_name(department.dept_name)
    folder_path = os.path.join(app.static_folder, 'pdffile', sanitized_dept_name, sanitized_folder_name)

    try:
        # Delete associated records in the database
        delete_recursive(folder)

        # Commit database changes
        db.session.commit()

        # Safely delete the folder from the filesystem
        if os.path.exists(folder_path):
            try:
                shutil.rmtree(folder_path)  # Use shutil for recursive deletion
                log_audit(
                    action="Deleted Folder",
                    extra_data={
                        "folder_name": folder_name,
                        "department": department.dept_name
                    }
                )
            except PermissionError as e:
                # Retry after a short delay to handle file locking
                time.sleep(0.5)
                try:
                    shutil.rmtree(folder_path)
                    log_audit(
                        action="Deleted Folder",
                        extra_data={
                            "folder_name": folder_name,
                            "department": department.dept_name,
                            "retry": True
                        }
                    )
                except Exception as final_e:
                    app.logger.error(f"Failed to delete folder: {folder_path}, Error: {final_e}")
                    log_audit(
                        action="Failed to Delete Folder",
                        extra_data={
                            "folder_name": folder_name,
                            "department": department.dept_name,
                            "error": str(final_e)
                        }
                    )
                    return jsonify(success=False, error=f"Failed to delete folder: {final_e}")
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error while deleting folder: {e}")
        log_audit(
            action="Failed to Delete Folder",
            extra_data={
                "folder_name": folder_name,
                "department": department.dept_name,
                "error": str(e)
            }
        )
        return jsonify(success=False, error=f"Failed to delete folder: {e}")


def delete_recursive(folder):
    """
    Recursively delete folder and associated records in the database.
    """
    # Delete all child folders recursively
    child_folders = Folder.query.filter_by(parent_folder_id=folder.folder_id).all()
    for child_folder in child_folders:
        delete_recursive(child_folder)

    # Delete PDFs in this folder before removing it
    pdfs = PDF.query.filter_by(folder_id=folder.folder_id).all()
    for pdf in pdfs:
        try:
            if os.path.exists(pdf.pdf_path):
                os.remove(pdf.pdf_path)
            db.session.delete(pdf)
        except Exception as e:
            app.logger.error(f"Failed to delete PDF: {pdf.pdf_path}, Error: {e}")
            raise e  # Re-raise the exception to handle in the main function

    # Delete the folder itself from the database
    db.session.delete(folder)
    
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
        log_audit(
            action="Deleted file",
            target_file=pdf_path,
            extra_data={"folder": folder_name, "department": department.dept_name}
        )

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
        dept_ids = request.form.getlist('dept_ids')

        if current_user.role_id == 1 and role_id in [0, 1]:
            flash("You do not have permission to register an admin or master admin.", "error")
            return redirect(url_for('register_user'))

        if not username or not password or not role_id:
            flash('All fields are required.', 'error')
            return redirect(url_for('register_user'))

        dept_ids = [int(dept_id) for dept_id in dept_ids if dept_id.isdigit()]
        primary_dept_id = dept_ids[0] if dept_ids else None

        if role_id in [0, 1] and dept_ids:
            flash("Admins and Master Admins cannot be assigned to any department.", "error")
            return redirect(url_for('register_user'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already taken. Please choose a different one.', 'error')
            return redirect(url_for('admin_dashboard'))

        if len(dept_ids) > 4:
            flash('A user cannot be assigned to more than 4 departments.', 'error')
            return redirect(url_for('admin_dashboard'))

        #validate the dept
        if dept_ids:
            valid_departments = [dept.dept_id for dept in departments]
            for dept_id in dept_ids:
                if int(dept_id) not in valid_departments:
                    flash('Invalid department selected.', 'error')
                    return redirect(url_for('admin_dashboard'))

        hashed_password = generate_password_hash(password)
        primary_dept_id = int(dept_ids[0]) if dept_ids else None

        new_user = User(username=username, password_hash=hashed_password, role_id=role_id, dept_id=primary_dept_id)
        db.session.add(new_user)
        db.session.flush()

        for dept_id in dept_ids:
            user_department = UserDepartment(user_id=new_user.user_id, dept_id=int(dept_id))
            db.session.add(user_department)

        db.session.commit()

        # Fetch role name and department names for audit log
        role_name = Role.query.get(role_id).role_name if Role.query.get(role_id) else "Unknown Role"
        department_names = [Department.query.get(int(dept_id)).dept_name for dept_id in dept_ids if Department.query.get(int(dept_id))]

        # Log audit
        log_audit(
            action="Registered User",
            extra_data={"username": username, "role": role_name, "departments": department_names}
        )

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

        # Gather changes for audit logging
        changes = {}
        if user.username != username:
            changes['username'] = {'old': user.username, 'new': username}
        if user.role_id != int(role_id):
            changes['role_id'] = {'old': user.role_id, 'new': int(role_id)}
        old_departments = [ud.dept_id for ud in user.user_departments]
        if set(old_departments) != set(map(int, dept_ids)):
            changes['departments'] = {'old': old_departments, 'new': list(map(int, dept_ids))}

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

        # Remove permissions for departments the user no longer has
        Permission.query.filter(
            Permission.user_id == user.user_id,
            ~Permission.dept_id.in_(dept_ids)
        ).delete(synchronize_session=False)

        try:
            db.session.commit()
            # Log audit
            log_audit(
                action="Edited User",
                extra_data={"user_id": user_id, "changes": changes}
            )
            flash(f"User '{username}' updated successfully!", 'success')
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating user: {e}", 'error')

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
            flash("User not found.", "error")
            return redirect(url_for('admin_dashboard'))

        # Role-based checks
        if current_user.role_id == 1 and user.role_id != 2:  # Admin cannot delete Admin or Master Admin
            flash("You do not have permission to delete this user.", "error")
            return redirect(url_for('admin_dashboard'))
        elif current_user.role_id == 0 and user.role_id == 0:  # Master Admin cannot delete another Master Admin
            flash("You cannot delete another Master Admin.", "error")
            return redirect(url_for('admin_dashboard'))

        # Gather data for optional future audit
        audit_data = {
            "username": user.username,
            "role_id": user.role_id,
            "departments": [ud.dept_id for ud in user.user_departments]
        }

        log_audit(
            action="Deleted User",
            extra_data=audit_data
        )

        # Delete associated records
        Permission.query.filter_by(user_id=user_id).delete()
        AuditLog.query.filter_by(user_id=user_id).delete()
        UserDepartment.query.filter_by(user_id=user_id).delete()

        # Delete the user
        db.session.delete(user)
        db.session.commit()

        return jsonify(success=True)
    
        # Flash success message
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
    users = User.query.filter(User.role_id > 1).all()

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        write_permissions = request.form.getlist('write_permission')
        delete_permissions = request.form.getlist('delete_permission')

        if not user_id:
            flash('User selection is required.', 'error')
            return redirect(url_for('admin_dashboard'))

        user = User.query.get(user_id)
        if not user or user.role_id in [0, 1]:
            flash('Invalid user selection.', 'error')
            return redirect(url_for('admin_dashboard'))

        user_departments = [ud.dept_id for ud in user.user_departments]

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
            # Log audit
            log_audit(
                action="Updated Permissions",
                extra_data={
                    "user_id": user_id,
                    "write_permissions": write_permissions,
                    "delete_permissions": delete_permissions
                }
            )
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
    
    # If no permissions found, return an error
    if not permissions:
        return jsonify(error="No permissions found for this user"), 404

    serialized_permissions = []
    
    # Populate the serialized data with dept_name
    for permission in permissions:
        dept_name = permission.department.dept_name if permission.department else "Unknown"
        serialized_permissions.append({
            "dept_id": permission.dept_id,
            "dept_name": dept_name,  # Add department name here
            "write_permission": permission.write_permission,
            "delete_permission": permission.delete_permission
        })

    return jsonify(success=True, permissions=serialized_permissions)

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

    # Log audit
    log_audit(
        action="Added Department",
        extra_data={"department_name": dept_name}
    )

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
        folders = Folder.query.filter_by(dept_id=department.dept_id).all()
        for folder in folders:
            PDFs = PDF.query.filter_by(folder_id=folder.folder_id).all()
            for pdf in PDFs:
                if os.path.exists(pdf.pdf_path):
                    os.remove(pdf.pdf_path)
                db.session.delete(pdf)
            sanitized_folder_name = sanitize_folder_name(folder.folder_name)
            sanitized_dept_name = sanitize_folder_name(department.dept_name)
            folder_path = os.path.join(app.static_folder, 'pdffile', sanitized_dept_name, sanitized_folder_name)
            if os.path.exists(folder_path):
                shutil.rmtree(folder_path)
            db.session.delete(folder)

        db.session.delete(department)
        db.session.commit()

        # Log audit
        log_audit(
            action="Deleted Department",
            extra_data={"department_name": dept_name}
        )

        flash('Department and all associated data deleted successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        db.session.rollback()
        flash(f'Error while deleting department: {e}', 'error')

    return redirect(url_for('admin_dashboard'))

# SECTION BREAK!!
# LOG REPORT 
@app.route('/view_pdf/<int:pdf_id>', methods=['GET'])
@login_required
def view_pdf(pdf_id):
    pdf = PDF.query.get_or_404(pdf_id)
    
    # Log the file access
    log_audit (
        action="Accessed file",
        target_file=pdf.pdf_path
    )
    db.session.commit()

    # Return the PDF viewer (existing functionality)
    return send_file(pdf.pdf_path)

def log_audit(action, target_file=None, extra_data=None):
    """Helper function to log audit actions."""
    audit_log = AuditLog(
        user_id=current_user.user_id if not current_user.is_anonymous else None,
        action=action,
        target_file=target_file,
        ip_address=request.remote_addr,
        extra_data=extra_data
    )
    db.session.add(audit_log)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error logging audit action: {e}")

@app.route('/fetch_audit_logs', methods=['GET'])
@login_required
@admin_required
def fetch_audit_logs():
    try:
        page = int(request.args.get('page', 1))  # Current page
        per_page = int(request.args.get('per_page', 30))  # Logs per page
        search_user = request.args.get('search', None)  # Search by username
        role = request.args.get('role', None)  # Filter by role

        logs_query = AuditLog.query.join(User).order_by(AuditLog.timestamp.desc())

        # Search by username
        if search_user:
            logs_query = logs_query.filter(User.username.ilike(f"%{search_user}%"))

        # Filter by role (ignore filter if role is empty or None)
        if role and role.strip() != "":
            role = int(role)  # Convert role to integer
            logs_query = logs_query.filter(User.role_id == role)

        # Paginate results
        paginated_logs = logs_query.paginate(page=page, per_page=per_page, error_out=False)

        # Process logs
        serialized_logs = []
        for log in paginated_logs.items:
            # Deserialize and process extra_data
            if log.extra_data:
                try:
                    extra_data = log.extra_data if isinstance(log.extra_data, dict) else json.loads(log.extra_data)
                except Exception as e:
                    print(f"Error parsing extra_data for log ID {log.log_id}: {e}")
                    extra_data = {}

                if log.action == "Uploaded file":
                    processed_extra_data = {
                        "folder": extra_data.get('folder', 'Unknown Folder'),
                        "department": extra_data.get('department', 'Unknown Department'),
                        "filename": extra_data.get('filename', 'Unknown File')
                    }
                elif log.action == "Deleted file":
                    processed_extra_data = {
                        "folder": extra_data.get('folder', 'Unknown Folder'),
                        "department": extra_data.get('department', 'Unknown Department'),
                        "deleted_file": extra_data.get('filename', 'Unknown File')
                    }
                elif log.action == "Added Folder" or log.action == "Deleted Folder":
                    processed_extra_data = {
                        "folder_name": extra_data.get('folder_name', 'Unknown Folder'),
                        "department": extra_data.get('department', 'Unknown Department')
                    }
                elif log.action == "Registered User":
                    processed_extra_data = {
                        "username": extra_data.get('username', 'Unknown Username'),
                        "role": extra_data.get('role', 'Unknown Role'),
                        "departments": extra_data.get('departments', [])
                    }
                elif log.action == "Edited User":
                    processed_extra_data = {
                        "user_id": extra_data.get('user_id', 'Unknown User'),
                        "changes": extra_data.get('changes', {})
                    }
                elif log.action == "Deleted User":
                    processed_extra_data = {
                        "username": extra_data.get('username', 'Unknown Username'),
                        "role_id": extra_data.get('role_id', 'Unknown Role'),
                        "departments": extra_data.get('departments', [])
                    }
                elif log.action == "Updated Permissions":
                    processed_extra_data = {
                        "user_id": extra_data.get('user_id', 'Unknown User'),
                        "write_permission": extra_data.get('write_permission', 'Unknown Permission'),
                        "delete_permission": extra_data.get('delete_permission', 'Unknown Permission')
                    }
                else:
                    # Default handling for other actions
                    processed_extra_data = extra_data
            else:
                processed_extra_data = "No Additional Information"

            # Append processed log
            serialized_logs.append({
                "user": log.user.username if log.user else "System",
                "action": log.action,
                "target_file": log.target_file.split("/")[-1] if log.target_file else "No File Interacted",
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "extra_data": processed_extra_data,
            })

        return jsonify(success=True, logs=serialized_logs, total=paginated_logs.total, page=page, perPage=per_page)
    except Exception as e:
        print(f"Error fetching audit logs: {e}")
        return jsonify(success=False, error="Failed to fetch logs")




# LOGOUT
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port = 5001)