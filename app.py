import os, shutil
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'proamitycorp'  

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Dummy user class for login demonstration
class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == 'staff' and password == 'proamity1234':
            user = User(id=1)
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials. Please try again.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.')
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    # Dictionary to hold folders and their PDFs
    pdf_structure = {}
    
    # Path to the PDFs directory
    pdf_directory = os.path.join(app.static_folder, 'pdffile')
    
    # Iterate through folders and files in the PDFs directory
    for folder_name in os.listdir(pdf_directory):
        folder_path = os.path.join(pdf_directory, folder_name)
        if os.path.isdir(folder_path):
            pdf_structure[folder_name] = [
                file for file in os.listdir(folder_path) if file.endswith('.pdf')
            ]

    return render_template('index.html', pdf_structure=pdf_structure)

# Secret password for management operations
MANAGEMENT_PASSWORD = "123"

@app.route('/validate_management_password', methods=['POST'])
@login_required
def validate_management_password():
    data = request.get_json()
    password = data.get('password')

    # Check if the password matches
    if password == MANAGEMENT_PASSWORD:
        # Set a session flag to indicate successful authentication
        session['management_authenticated'] = True
        return jsonify(success=True)
    else:
        return jsonify(success=False, error="Incorrect password.")
    
@app.route('/validate_management_password', methods=['GET'])
@login_required
def check_management_authentication():
    # Check if the session flag is set
    if session.get('management_authenticated'):
        return jsonify(authenticated=True)
    else:
        return jsonify(authenticated=False)


@app.route('/add_folder', methods=['POST'])
@login_required
def add_folder():
    if not session.get('management_authenticated'):
        return jsonify(success=False, error="Authentication required.")

    data = request.get_json()
    folder_name = data.get('folderName')
    folder_path = os.path.join(app.static_folder, 'pdffile', folder_name)
    try:
        os.makedirs(folder_path, exist_ok=True)
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e))

@app.route('/delete_folder', methods=['POST'])
@login_required
def delete_folder():
    if not session.get('management_authenticated'):
        return jsonify(success=False, error="Authentication required.")
    
    data = request.get_json()
    folder_name = data.get('folderName')
    folder_path = os.path.join(app.static_folder, 'pdffile', folder_name)
    try:
        os.rmdir(folder_path)
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e))
    

@app.route('/upload_pdf', methods=['POST'])
@login_required
def upload_pdf():
    if not session.get('management_authenticated'):
        return jsonify(success=False, error="Authentication required.")
    
    # Check if a file is uploaded
    if 'pdfFile' not in request.files:
        return jsonify(success=False, error="No file part in the request.")
    
    file = request.files['pdfFile']
    folder_name = request.form.get('folder')

    # Validate that a folder was selected and file is a PDF
    if not folder_name or file.filename == '':
        return jsonify(success=False, error="Folder or file not specified.")
    
    if not file.filename.endswith('.pdf'):
        return jsonify(success=False, error="Only PDF files are allowed.")

    # Secure the filename and set the path to save the file
    filename = secure_filename(file.filename)
    folder_path = os.path.join(app.static_folder, 'pdffile', folder_name)
    file_path = os.path.join(folder_path, filename)
    
    try:
        # Ensure the folder exists
        os.makedirs(folder_path, exist_ok=True)
        
        # Save the uploaded file
        file.save(file_path)
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e))

@app.route('/delete_pdf', methods=['POST'])
@login_required
def delete_pdf():
    if not session.get('management_authenticated'):
        return jsonify(success=False, error="Authentication required.")

    data = request.get_json()
    folder_name = data.get('folderName')
    pdf_name = data.get('pdfName')

    # Path to the original PDF file
    pdf_path = os.path.join(app.static_folder, 'pdffile', folder_name, pdf_name)
    # Path to the trash folder, including the PDF file name
    trash_folder = os.path.join(app.static_folder, 'trash')
    trash_path = os.path.join(trash_folder, pdf_name)

    # Ensure the trash folder exists
    os.makedirs(trash_folder, exist_ok=True)
    
    try:
        # Move the file to the trash folder with the full path
        shutil.move(pdf_path, trash_path)
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e))

if __name__ == '__main__':
    app.run(debug=True, port=5001)
