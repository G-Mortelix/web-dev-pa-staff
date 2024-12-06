from functools import wraps
import os, re, shutil, logging
from dotenv import load_dotenv
from flask_migrate import Migrate
from sqlalchemy import ForeignKey
from sqlalchemy.orm import Session
from flask_sqlalchemy import SQLAlchemy
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

# Updated model with backref renaming
class Folder(db.Model):
    __tablename__ = 'folders'

    folder_id = db.Column(db.Integer, primary_key=True)
    folder_name = db.Column(db.String(100), nullable=False)
    dept_id = db.Column(db.Integer, db.ForeignKey('departments.dept_id'))
    parent_folder_id = db.Column(db.Integer, db.ForeignKey('folders.folder_id'), nullable=True)  # Self-reference for parent folder
    time_created = db.Column(db.DateTime, default=db.func.current_timestamp())
    
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

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/home')
@login_required
def home():
    pdf_structure = {}

    # Get search and filter parameters from the form
    search_query = request.args.get('search', '').strip().lower()  # Get search query
    department_filter = request.args.get('department_filter', type=int)

    # Determine accessible departments based on the current user's role
    if current_user.role_id == 0:  # Master Admin
        departments = Department.query.all()  # Access all departments
    elif current_user.role_id == 1:  # Admin
        departments = Department.query.all()  # Admin also has access to all departments
    else:  # Regular users
        user_departments = [ud.dept_id for ud in current_user.user_departments]
        # Include the "General" department (assuming dept_id = 4)
        departments = Department.query.filter(Department.dept_id.in_(user_departments + [4])).all()

    # Apply department filter
    if department_filter:
        departments = [d for d in departments if d.dept_id == department_filter]

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
        all_folders = Folder.query.filter_by(dept_id=department.dept_id).all()

        # Sort folders by numeric values
        def folder_sort_key(folder):
            parts = re.split(r'(\d+(?:\.\d{1,2})?)', folder.folder_name)
            return [float(part) if part.replace('.', '', 1).isdigit() else part.lower() for part in parts]

        sorted_folders = sorted(all_folders, key=folder_sort_key)

        # Initialize dictionary for each department
        pdf_structure[department.dept_name] = {}

        # Create a dictionary to map folder_id to folder data for easy access
        folder_map = {folder.folder_id: folder for folder in sorted_folders}

        # Create a list to track folders we've already added as parents or children
        parent_folders = [folder for folder in sorted_folders if folder.parent_folder_id is None]

        # Loop through parent folders and build the structure
        for folder in parent_folders:
            sanitized_folder_name = sanitize_folder_name(folder.folder_name)
            pdfs = PDF.query.filter_by(folder_id=folder.folder_id).all()
            pdf_files = [pdf.pdf_name for pdf in pdfs]

            # Skip parent folders that don't match the search query and have no matching children
            if search_query and search_query not in folder.folder_name.lower() and not pdf_files:
                continue

            # Get child folders (direct children) for the current folder
            child_folders = [f for f in sorted_folders if f.parent_folder_id == folder.folder_id]

            # Initialize folder data for the parent folder
            parent_data = {
                "files": pdf_files,
                "dept_id": folder.dept_id,
                "parent_folder_id": folder.folder_id,
                "child_folders": []
            }

            # For each child folder, classify as subchild or child
            for child in child_folders:
                child_pdfs = PDF.query.filter_by(folder_id=child.folder_id).all()
                child_pdf_files = [pdf.pdf_name for pdf in child_pdfs]

                # Skip child folders that don't match the search query and have no matching children
                if search_query and search_query not in child.folder_name.lower() and not child_pdf_files:
                    continue

                # Get subchild folders (sub-subfolders) for the child folder
                subchild_folders = [f for f in sorted_folders if f.parent_folder_id == child.folder_id]
                subchild_data_list = []

                for subchild in subchild_folders:
                    subchild_pdfs = PDF.query.filter_by(folder_id=subchild.folder_id).all()
                    subchild_pdf_files = [pdf.pdf_name for pdf in subchild_pdfs]

                    # Skip subchild folders that don't match the search query
                    if search_query and search_query not in subchild.folder_name.lower() and not subchild_pdf_files:
                        continue

                    # Add subchild data
                    subchild_data_list.append({
                        'folder_name': subchild.folder_name,
                        'folder_id': subchild.folder_id,
                        'files': subchild_pdf_files
                    })

                # Add child data
                parent_data["child_folders"].append({
                    'folder_name': child.folder_name,
                    'folder_id': child.folder_id,
                    'files': child_pdf_files,
                    'child_folders': subchild_data_list
                })

            # Add parent folder to department structure
            pdf_structure[department.dept_name][sanitized_folder_name] = parent_data

    return render_template('index.html', pdf_structure=pdf_structure, permissions=permissions, departments=departments)





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
    new_parent_folder_name = data.get('newParentFolderName', '').strip()  # New field for parent folder

    # Retrieve the folder based on the old folder name
    folder = Folder.query.filter_by(folder_name=old_folder_name).first()
    if not folder:
        return jsonify(success=False, error="Folder not found.")
    
    # Preserve the original parent folder ID
    original_parent_folder_id = folder.parent_folder_id

    new_parent_folder = None
    if new_parent_folder_name:
        # Find the new parent folder if provided
        new_parent_folder = Folder.query.filter_by(folder_name=new_parent_folder_name, dept_id=folder.dept_id).first()
        if not new_parent_folder:
            return jsonify(success=False, error="New parent folder not found.")

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

        # Set the parent folder if a new parent is specified, otherwise preserve the original parent
        folder.parent_folder_id = new_parent_folder.folder_id if new_parent_folder else original_parent_folder_id

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
    new_log = AuditLog(
        user_id=current_user.user_id,
        action="Uploaded file",
        target_file=file_path,
        ip_address=request.remote_addr,
        extra_data={"folder": folder_name, "department": department.dept_name, "filename": filename, "file_size": os.path.getsize(file_path)}
    )
    db.session.add(new_log)

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

    # Define a recursive function to delete child folders and the folder itself
    def delete_recursive(folder):
        # Delete all child folders recursively
        child_folders = Folder.query.filter_by(parent_folder_id=folder.folder_id).all()
        for child_folder in child_folders:
            delete_recursive(child_folder)
        
        # Delete PDFs in this folder before removing it
        pdfs = PDF.query.filter_by(folder_id=folder.folder_id).all()
        for pdf in pdfs:
            pdf_path = os.path.join(app.static_folder, 'pdffile', sanitized_dept_name, sanitized_folder_name, pdf.pdf_name)
            try:
                if os.path.exists(pdf_path):
                    os.remove(pdf_path)
                db.session.delete(pdf)
            except Exception as e:
                db.session.rollback()
                return jsonify(success=False, error=f"Failed to delete PDF: {e}")

        # After deleting child PDFs, remove the folder itself from the database
        db.session.delete(folder)

    try:
        # Start the recursive deletion from the current folder
        delete_recursive(folder)
        
        # After all children and the folder are deleted, commit the session
        db.session.commit()
        
        # Finally, remove the folder itself from the filesystem
        if os.path.exists(folder_path):
            os.rmdir(folder_path)

        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, error=f"Failed to delete folder: {e}")
    
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