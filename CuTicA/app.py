from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_pymongo import PyMongo
from pymongo.errors import ServerSelectionTimeoutError
from urllib.parse import quote
import os
import secrets
import base64
from email.mime.text import MIMEText
from dotenv import load_dotenv
import requests
from requests.auth import HTTPDigestAuth

# Load environment variables from .env file
load_dotenv()

# Importing Google API Client Libraries
import google.auth
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import pickle

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MongoDB Atlas configuration
username = os.getenv('MONGO_USERNAME')
password = os.getenv('MONGO_PASSWORD')
atlas_group_id = os.getenv('ATLAS_GROUP_ID')
atlas_api_key_public = os.getenv('ATLAS_API_KEY_PUBLIC')
atlas_api_key_private = os.getenv('ATLAS_API_KEY_PRIVATE')

if username is None or password is None:
    raise ValueError("Environment variables MONGO_USERNAME and MONGO_PASSWORD must be set")

password = quote(password)

def get_public_ip():
    response = requests.get("https://api.ipify.org")
    return response.text

def whitelist_ip_in_mongo(ip):
    resp = requests.post(
        f"https://cloud.mongodb.com/api/atlas/v1.0/groups/{atlas_group_id}/accessList",
        auth=HTTPDigestAuth(atlas_api_key_public, atlas_api_key_private),
        json=[{'ipAddress': ip, 'comment': 'From PythonAnywhere'}]
    )
    if resp.status_code in (200, 201):
        print("MongoDB Atlas accessList request successful", flush=True)
    else:
        print(
            f"MongoDB Atlas accessList request problem: status code was {resp.status_code}, content was {resp.content}",
            flush=True
        )

current_ip = get_public_ip()
whitelist_ip_in_mongo(current_ip)

app.config["MONGO_URI"] = f"mongodb+srv://bhagavath11ab:01012002@cluster0.tsgk9f6.mongodb.net/cutica_db?retryWrites=true&w=majority"
mongo = PyMongo(app)

SCOPES = ['https://www.googleapis.com/auth/gmail.send']
creds = None

current_dir = os.path.dirname(os.path.abspath(__file__))
auth_dir = os.path.join(current_dir, 'auth')
credentials_path = os.path.join(auth_dir, 'credentials.json')
token_path = os.path.join(auth_dir, 'token.pickle')

if os.path.exists(token_path):
    with open(token_path, 'rb') as token:
        creds = pickle.load(token)

if not creds or not creds.valid:
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
    else:
        flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
        creds = flow.run_local_server(port=0)
    with open(token_path, 'wb') as token:
        pickle.dump(creds, token)

service = build('gmail', 'v1', credentials=creds)

def send_email(to, subject, body):
    message = MIMEText(body)
    message['to'] = to
    message['subject'] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    message = {'raw': raw}
    try:
        message = (service.users().messages().send(userId='me', body=message).execute())
        print('Message Id: %s' % message['id'])
        return message
    except Exception as error:
        print(f'An error occurred: {error}')
        return None

@app.route('/')
def main_home():
    return render_template('main_home.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/signup')
def signup_page():
    return render_template('signup.html')

@app.route('/forgot_password')
def forgot_password_page():
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = mongo.db.password_resets.find_one({'token': token})
    if not user:
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('login_page'))
    
    if request.method == 'POST':
        new_password = request.form.get('newPassword')
        mongo.db.users.update_one({'email': user['email']}, {'$set': {'password': new_password}})
        mongo.db.password_resets.delete_one({'token': token})
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login_page'))

    return render_template('reset_password.html', token=token)

@app.route('/home/<username>')
def home(username):
    return render_template('home.html', username=username)

@app.route('/login', methods=['POST'])
def login():
    try:
        email = request.form.get('loginEmail')
        password = request.form.get('loginPassword')
        user = mongo.db.users.find_one({'email': email})
        if user:
            session['username'] = user['username']
            session['email'] = email
            session['role'] = user.get('role', 'user')
            if user['password'] == password:
                flash('Login successful!', 'success')
                if session['role'] == 'admin':
                    return redirect(url_for('dashboard_page'))  # Correct endpoint name
                else:
                    return redirect(url_for('home', username=user['username']))
            else:
                flash('Wrong password. Please try again.', 'danger')
                return redirect(url_for('login_page'))
        else:
            flash('Invalid email. Please try again.', 'danger')
            return redirect(url_for('login_page'))
    except ServerSelectionTimeoutError:
        flash('Could not connect to MongoDB. Please try again later.', 'danger')
        return redirect(url_for('login_page'))

@app.route('/Dashboard')
def dashboard_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    dashboard = mongo.db.dashboard.find_one({'user': session['username']})
    return render_template('dashboard.html', dashboard=dashboard)

@app.route('/Account')
def account_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    accounts = mongo.db.account.find_one({'user': session['username']})
    return render_template('account.html', accounts=accounts)

@app.route('/View_Class_Details')
def view_class_details_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    view_class_details = mongo.db.view_class_details.find_one({'user': session['username']})
    return render_template('view_class_details.html', view_class_details=view_class_details)

@app.route('/Notification')
def notification_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    notification = mongo.db.notification.find_one({'user': session['username']})
    return render_template('notification.html', notification=notification)

@app.route('/Help')
def help_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    help = mongo.db.help.find_one({'user': session['username']})
    return render_template('help.html', help=help)


@app.route('/Customers')
def customers_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    customers = mongo.db.customers.find_one({'user': session['username']})
    return render_template('customers.html', customers=customers)


@app.route('/signup', methods=['POST'])
def signup():
    try:
        username = request.form.get('signUpUsername')
        email = request.form.get('signUpEmail')
        password = request.form.get('signUpPassword')
        user = mongo.db.users.find_one({'email': email})
        if user:
            flash('Email already exists', 'danger')
            return redirect(url_for('signup_page'))
        else:
            mongo.db.users.insert_one({'username': username, 'email': email, 'password': password, 'role': 'admin'})
            flash('Sign up successful!', 'success')
            return redirect(url_for('login_page'))
    except ServerSelectionTimeoutError:
        flash('Could not connect to MongoDB. Please try again later.', 'danger')
        return redirect(url_for('signup_page'))

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    try:
        email = request.form.get('forgotPasswordEmail')
        user = mongo.db.users.find_one({'email': email})
        if user:
            token = secrets.token_urlsafe(32)
            mongo.db.password_resets.insert_one({'email': email, 'token': token})
            reset_url = url_for('reset_password', token=token, _external=True)
            subject = 'Password Reset Request'
            body = f'Click the link to reset your password: {reset_url}'
            send_email(email, subject, body)
            flash('A password reset link has been sent to your email.', 'info')
        else:
            flash('Email not found', 'danger')
        return redirect(url_for('forgot_password_page'))
    except ServerSelectionTimeoutError:
        flash('Could not connect to MongoDB. Please try again later.', 'danger')
        return redirect(url_for('forgot_password_page'))

@app.route('/settings')
def settings_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    settings = mongo.db.settings.find_one({'user': session['username']})
    return render_template('settings.html', settings=settings)



@app.route('/support_team')
def support_team():
    admin_email = session.get('email')
    support_members = mongo.db.support_team.find({'admin_email': admin_email})
    return render_template('support_team.html', support_members=support_members)


@app.route('/add_support')
def add_support():
    return render_template('add_support.html')

@app.route('/add_class')
def add_class():
    return render_template('add_class.html')

@app.route('/email_config')
def email_config():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    return render_template('email_config.html')

@app.route('/view_class_details')
def view_class_details():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    return render_template('view_class_details.html')


@app.route('/classification_config')
def classification_config():
    # Check if user is logged in
    if 'username' not in session:
        return redirect(url_for('login_page'))

    classes = list(mongo.db.add_class.find())  
    return render_template('classification_config.html', classes=classes)


@app.route('/password_change')
def password_change():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    return render_template('password_change.html')

@app.route('/email_change')
def email_change():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    return render_template('email_change.html')


@app.route('/new_support_credentials', methods=['POST'])
def new_support_credentials():
    name = request.form.get('name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    admin_email = session.get('email')

    # Generate random password and support ID
    password = secrets.token_urlsafe(12)
    support_id = secrets.randbelow(1000)  # Generate a random support ID (0-999)

    # Insert support member into users collection
    mongo.db.users.insert_one({'username': name, 'email': email, 'password': password, 'role': 'support'})

    # Insert support member details into support_team collection
    mongo.db.support_team.insert_one({'support_id': support_id, 'name': name, 'email': email, 'phone': phone, 'admin_email': admin_email})

    # Send email with credentials
    subject = 'Your Support Account Credentials'
    body = f'Username: {email}\nPassword: {password}\nSupport ID: {support_id}'
    send_email(email, subject, body)

    flash('Support member added and credentials sent!', 'success')
    return redirect(url_for('support_team'))

@app.route('/new_class_credentials', methods=['POST'])
def new_class_credentials():
    # Retrieve data from the POST request
    name = request.form.get('name')
    description = request.form.get('description')

    class_id = secrets.randbelow(10000)  # Generate a random class_id

    # Insert class details into 'add_class' collection in MongoDB
    mongo.db.add_class.insert_one({'class_id': class_id, 'class_name': name, 'description': description})

    # Flash message for success and redirect to classification_config route
    flash('Class added successfully', 'success')
    return redirect(url_for('classification_config'))

@app.route('/delete_class/<class_id>', methods=['DELETE'])
def delete_class(class_id):
    try:
        result = mongo.db.add_class.delete_one({'class_id': int(class_id)})
        if result.deleted_count == 1:
            return jsonify({'success': True}), 200
        else:
            return jsonify({'success': False, 'error': 'Class not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

'''
this is the retrieving of data from the mongodb database
'''
@app.route('/get_data')
def get_data():
    # Retrieve data for issues, grouped by type and status
    issues_pipeline = [
        {
            "$group": {
                "_id": {
                    "type": "$issue_type",
                    "status": "$status"
                },
                "count": {"$sum": 1}
            }
        }
    ]
    issues = mongo.db.issues.aggregate(issues_pipeline)

    # Prepare the issues data structure
    issues_data = {}
    for issue in issues:
        issue_type = issue["_id"]["type"]
        status = issue["_id"]["status"]
        if issue_type not in issues_data:
            issues_data[issue_type] = {"solved": 0, "unsolved": 0}
        if status == "solved":
            issues_data[issue_type]["solved"] += issue["count"]
        else:
            issues_data[issue_type]["unsolved"] += issue["count"]

    issues_data = [{"type": k, "solved": v["solved"], "unsolved": v["unsolved"]} for k, v in issues_data.items()]

    # Retrieve data for resolution status
    resolution_pipeline = [
        {"$group": {"_id": "$status", "count": {"$sum": 1}}}
    ]
    resolution = mongo.db.issues.aggregate(resolution_pipeline)
    resolution_data = [{"status": res["_id"], "count": res["count"]} for res in resolution]

    return jsonify({
        "issues_data": issues_data,
        "resolution_data": resolution_data
    })


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login_page'))

if __name__ == '__main__':
    app.run(debug=True)
