# app.py

from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from dotenv import load_dotenv
import json
import datetime
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import requests

# --- New Imports for Gmail API & DB ---
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import pickle
import pytz
from tzlocal import get_localzone
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import LargeBinary

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_super_secret_key')

# Use a path within the app's working directory for SQLite DB.
# This will allow the app to start without PermissionError on Render's free tier.
# WARNING: Data will NOT persist across deploys/restarts on Render's free tier with this setup.
DATABASE_DIR = os.path.join(os.getcwd(), 'data') # <-- পরিবর্তিত: os.getcwd() ব্যবহার করা হয়েছে
DATABASE_PATH = os.path.join(DATABASE_DIR, 'app.db')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///' + DATABASE_PATH)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Ensure the data directory exists. Use exist_ok=True to prevent errors
# if the directory already exists from a previous run within the same container instance.
os.makedirs(DATABASE_DIR, exist_ok=True) # <-- পরিবর্তিত: exist_ok=True যোগ করা হয়েছে

db = SQLAlchemy(app)

# --- User Management (Database Models) ---
class User(UserMixin, db.Model):
    id = db.Column(db.String(50), primary_key=True)
    password = db.Column(db.String(100), nullable=False)
    gmail_credentials_pickle = db.Column(LargeBinary, nullable=True)
    
    monitored_senders_json = db.Column(db.Text, default="[]") 
    sms_logs_json = db.Column(db.Text, default="[]")

    def __init__(self, id, password):
        self.id = id
        self.password = password

    def get_id(self):
        return self.id

    def get_monitored_senders(self):
        return json.loads(self.monitored_senders_json)

    def set_monitored_senders(self, senders_list):
        self.monitored_senders_json = json.dumps(senders_list)

    def get_sms_logs(self):
        return json.loads(self.sms_logs_json)

    def set_sms_logs(self, logs_list):
        self.sms_logs_json = json.dumps(logs_list)

# Database initialization (for Flask 3.x and gunicorn)
# This code block will run when the 'app' object is created and imported by gunicorn
with app.app_context():
    db.create_all()
    if not User.query.filter_by(id="testuser").first():
        default_user = User(id="testuser", password="testpassword")
        db.session.add(default_user)
        db.session.commit()
        print("Default 'testuser' added to database.")
    print("Database initialized (tables created and default user added if needed).")


# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# --- Routes (Updated to use DB) ---

@app.route('/')
@login_required
def index():
    current_user_obj = User.query.get(current_user.id)
    gmail_connected = bool(current_user_obj.gmail_credentials_pickle)
    sms_logs = sorted(current_user_obj.get_sms_logs(), key=lambda x: x['timestamp'], reverse=True)[:5]
    return render_template('dashboard.html', gmail_connected=gmail_connected, user_data=current_user_obj, sms_logs=sms_logs)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(id=username).first()

        if user and user.password == password:
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    current_user_obj = User.query.get(current_user.id)
    if request.method == 'POST':
        sender_email = request.form.get('sender_email').strip()
        recipient_phone = request.form.get('recipient_phone').strip()
        
        if sender_email and recipient_phone:
            monitored_senders = current_user_obj.get_monitored_senders()
            new_sender = {
                "sender_email": sender_email,
                "recipient_phone": recipient_phone,
                "enabled": True
            }
            monitored_senders.append(new_sender)
            current_user_obj.set_monitored_senders(monitored_senders)
            db.session.commit()
            flash('Sender added successfully!', 'success')
        else:
            flash('Please provide both sender email and recipient phone.', 'danger')
        
        return redirect(url_for('settings'))
    
    return render_template('settings.html', monitored_senders=current_user_obj.get_monitored_senders())

@app.route('/delete_sender/<int:index>')
@login_required
def delete_sender(index):
    current_user_obj = User.query.get(current_user.id)
    monitored_senders = current_user_obj.get_monitored_senders()
    if 0 <= index < len(monitored_senders):
        monitored_senders.pop(index)
        current_user_obj.set_monitored_senders(monitored_senders)
        db.session.commit()
        flash('Sender deleted successfully!', 'success')
    else:
        flash('Invalid sender index.', 'danger')
    return redirect(url_for('settings'))

# --- Gmail API Integration (Updated to use DB) ---

SCOPES = ['https://www.googleapis.com/auth/userinfo.email', 'openid' , 'https://www.googleapis.com/auth/userinfo.profile' , 'https://www.googleapis.com/auth/gmail.modify']
CLIENT_SECRETS_FILE = os.path.join(os.getcwd(), 'client_secrets.json') # Temp file for flow setup - Use working directory

def create_client_secrets_file():
    client_id = os.getenv('GOOGLE_CLIENT_ID')
    client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
    if not client_id or not client_secret:
        raise ValueError("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be set in .env")

    secrets = {
        "web": {
            "client_id": client_id,
            "project_id": "your-project-id",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": client_secret,
            "redirect_uris": [os.getenv('FLASK_REDIRECT_URI', 'http://127.0.0.1:5000/callback')]
        }
    }
    with open(CLIENT_SECRETS_FILE, 'w') as f:
        json.dump(secrets, f, indent=4)

@app.route('/connect_gmail')
@login_required
def connect_gmail():
    try:
        create_client_secrets_file()
        
        flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
        flow.redirect_uri = url_for('oauth2callback', _external=True)
        authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
        
        session['oauth_state'] = state
        return redirect(authorization_url)
    except Exception as e:
        flash(f"Error initiating Gmail connection: {e}", 'danger')
        return redirect(url_for('index'))

@app.route('/callback')
@login_required
def oauth2callback():
    state = session.get('oauth_state')
    if not state or state != request.args.get('state'):
        flash('Invalid OAuth state. Please try connecting Gmail again.', 'danger')
        return redirect(url_for('index'))

    try:
        create_client_secrets_file()
        
        flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
        flow.redirect_uri = url_for('oauth2callback', _external=True)

        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)

        credentials = flow.credentials

        # Save credentials to DB
        current_user_obj = User.query.get(current_user.id)
        current_user_obj.gmail_credentials_pickle = pickle.dumps(credentials) # Store as binary
        db.session.commit() # Save to DB

        flash('Gmail connected successfully!', 'success')
    except Exception as e:
        flash(f"Error connecting Gmail: {e}", 'danger')
    
    # Remove client_secrets.json after use
    if os.path.exists(CLIENT_SECRETS_FILE):
        os.remove(CLIENT_SECRETS_FILE)

    return redirect(url_for('index'))


# --- SMS Sending Function (No change here) ---
def send_sms(recipient_phone, message):
    url = "https://bulksmsbd.net/api/smsapi"
    api_key = os.getenv('BULKSMSBD_API_KEY')
    sender_id = os.getenv('BULKSMSBD_SENDER_ID')

    if not api_key or not sender_id:
        print("Error: BulkSMSBD API key or Sender ID not set in .env. SMS will not be sent.")
        return False

    if not recipient_phone.startswith('880'):
        if recipient_phone.startswith('+880'):
            recipient_phone = recipient_phone[1:]
        else:
            if recipient_phone.startswith('0'):
                recipient_phone = '88' + recipient_phone
            else:
                recipient_phone = '880' + recipient_phone
            
    recipient_phone = ''.join(filter(str.isdigit, recipient_phone))

    params = {
        "api_key": api_key,
        "senderid": sender_id,
        "number": recipient_phone,
        "message": message
    }

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        response_data = response.json()
        
        print(f"SMS API Response for {recipient_phone}: {response_data}")

        if response_data.get("response_code") == "200":
            return True
        else:
            print(f"SMS sending failed according to BulkSMSBD API: {response_data.get('response_message', 'Unknown error')}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error sending SMS via BulkSMSBD API: {e}")
        return False


# --- Background Job (Check Gmail for new mails - Updated to use DB) ---
def check_gmail_for_new_mails():
    with app.app_context():
        try:
            # আপনার স্থানীয় টাইমজোন সেট করুন (যেমন Asia/Dhaka)
            try:
                local_tz = get_localzone()
            except pytz.UnknownTimeZoneError:
                local_tz = pytz.timezone('Asia/Dhaka')
            
            now_local = datetime.datetime.now(local_tz)

            print(f"Checking Gmail for new mails at {now_local.strftime('%Y-%m-%d %H:%M:%S %Z%z')}")
            
            # Fetch all users from DB for background job
            all_users = User.query.all() # Get all users from DB
            
            for user_obj in all_users: # Iterate through each user
                user_id = user_obj.id
                creds_pickle = user_obj.gmail_credentials_pickle # Get pickled creds from DB
                monitored_senders = user_obj.get_monitored_senders() # Get senders from DB

                print(f"User: {user_id}, Gmail Creds Exist: {bool(creds_pickle)}, Monitored Senders Count: {len(monitored_senders)}")

                if not creds_pickle or not monitored_senders:
                    print(f"Skipping user {user_id}: No Gmail credentials or no senders configured.")
                    continue

                creds = None
                try:
                    creds = pickle.loads(creds_pickle) # Load from binary

                    if not creds or not creds.valid:
                        if creds and creds.expired and creds.refresh_token:
                            print(f"User {user_id}: Gmail token expired, attempting refresh.")
                            creds.refresh(Request())
                            user_obj.gmail_credentials_pickle = pickle.dumps(creds) # Save refreshed creds back to DB
                            db.session.commit()
                        else:
                            print(f"User {user_id}: Gmail token is invalid or expired and cannot be refreshed. Clearing token in DB.")
                            user_obj.gmail_credentials_pickle = None
                            db.session.commit()
                            continue
                    
                    service = build('gmail', 'v1', credentials=creds)

                    query = "is:unread"
                    print(f"User {user_id}: Querying Gmail with '{query}'.")
                    results = service.users().messages().list(userId='me', q=query).execute()
                    messages = results.get('messages', [])

                    if not messages:
                        print(f"User {user_id}: No new unread messages found from Gmail API.")
                        continue

                    print(f"User {user_id}: Found {len(messages)} unread messages.")
                    for message in messages:
                        msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
                        
                        headers = msg['payload']['headers']
                        from_email = next((header['value'] for header in headers if header['name'] == 'From'), 'Unknown Sender')
                        subject = next((header['value'] for header in headers if header['name'] == 'Subject'), 'No Subject')
                        
                        import re
                        match = re.search(r'<(.+?)>', from_email)
                        clean_from_email = match.group(1) if match else from_email.strip()
                        
                        print(f"Processing message ID: {message['id']}, From: '{clean_from_email}', Subject: '{subject}'")

                        is_monitored_match = False
                        for sender_config in monitored_senders:
                            print(f"Checking sender config: {sender_config['sender_email'].lower()} against '{clean_from_email.lower()}' (enabled: {sender_config['enabled']})")
                            if sender_config["enabled"] and clean_from_email.lower() == sender_config["sender_email"].lower():
                                is_monitored_match = True
                                print(f"Match found for {user_id}: From '{clean_from_email}', Subject '{subject}'")
                                
                                service.users().messages().modify(userId='me', id=message['id'], body={'removeLabelIds': ['UNREAD']}).execute()
                                print(f"Marked message {message['id']} as read.")

                                sms_message = f"📩 New Mail from {clean_from_email}\n\nSubject: \"{subject}\"\n\nTime: {now_local.strftime('%I:%M%p')}\n\n✅ Mail2SMS BD"
                                
                                sms_success = send_sms(sender_config["recipient_phone"], sms_message)

                                log_entry = {
                                    "timestamp": datetime.datetime.now().isoformat(),
                                    "from_email": clean_from_email,
                                    "subject": subject,
                                    "sms_status": "Sent" if sms_success else "Failed",
                                    "recipient_phone": sender_config["recipient_phone"]
                                }
                                sms_logs = user_obj.get_sms_logs()
                                sms_logs.append(log_entry)
                                user_obj.set_sms_logs(sms_logs)
                                db.session.commit()
                                
                                if sms_success:
                                    print(f"SMS sent successfully to {sender_config['recipient_phone']} for new mail from {clean_from_email}.")
                                else:
                                    print(f"Failed to send SMS to {sender_config['recipient_phone']} for new mail from {clean_from_email}.")
                                break
                        if not is_monitored_match:
                            print(f"No monitored sender matched for email from '{clean_from_email}'. Not sending SMS.")

                except Exception as e:
                    print(f"Error during Gmail API call or processing for user {user_id}: {e}")
        except Exception as e_outer:
            print(f"An unexpected error occurred in check_gmail_for_new_mails: {e_outer}")


# --- Scheduler Setup ---
scheduler = BackgroundScheduler()
scheduler.add_job(func=check_gmail_for_new_mails, trigger="interval", minutes=2)
scheduler.start()

# Shut down the scheduler when the app exits
atexit.register(lambda: scheduler.shutdown())


if __name__ == '__main__':
    if os.getenv('FLASK_REDIRECT_URI') is None:
        os.environ['FLASK_REDIRECT_URI'] = 'http://127.0.0.1:5000/callback'
        print(f"Set FLASK_REDIRECT_URI to: {os.environ['FLASK_REDIRECT_URI']}")
    
    app.run(debug=True)
