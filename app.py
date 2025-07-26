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

# --- New Imports for Gmail API ---
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import pickle # To save/load user credentials securely
import pytz # <-- নতুন ইম্পোর্ট
from tzlocal import get_localzone # <-- নতুন ইম্পোর্ট


# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_super_secret_key') # Replace with a strong secret key
app.config['UPLOAD_FOLDER'] = 'uploads' # Used for storing tokens, etc.

# Ensure the upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- User Management (Updated to store tokens and logs) ---
# In a real app, you'd use a database like SQLite or PostgreSQL
# We'll use a simple JSON file for persistence for MVP
USERS_FILE = os.path.join(app.config['UPLOAD_FOLDER'], 'users.json')

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {
        "testuser": {
            "password": "testpassword", # In real app, store hashed passwords
            "gmail_token_path": None, # Path to the pickled token file
            "monitored_senders": [], # List of {"sender_email": "", "recipient_phone": "", "enabled": True}
            "sms_logs": [] # List of {"timestamp": "", "from_email": "", "subject": "", "sms_status": ""}
        }
    }

def save_users(users_data):
    with open(USERS_FILE, 'w') as f:
        json.dump(users_data, f, indent=4)

USERS = load_users() # Load users data when app starts

class User(UserMixin):
    def __init__(self, id):
        self.id = id

    def get_id(self):
        return self.id

    @staticmethod
    def get(user_id):
        if user_id in USERS:
            return User(user_id)
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# --- Routes ---

@app.route('/')
@login_required
def index():
    user_data = USERS.get(current_user.id)
    gmail_connected = bool(user_data and user_data.get("gmail_token_path") and os.path.exists(user_data["gmail_token_path"]))
    # Display last 5 SMS logs
    sms_logs = sorted(user_data.get("sms_logs", []), key=lambda x: x['timestamp'], reverse=True)[:5]
    return render_template('dashboard.html', gmail_connected=gmail_connected, user_data=user_data, sms_logs=sms_logs)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_data = USERS.get(username)

        if user_data and user_data["password"] == password: # In real app, check hashed password
            user = User(username)
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
    user_data = USERS.get(current_user.id)
    if request.method == 'POST':
        sender_email = request.form.get('sender_email').strip()
        recipient_phone = request.form.get('recipient_phone').strip()
        
        if sender_email and recipient_phone:
            new_sender = {
                "sender_email": sender_email,
                "recipient_phone": recipient_phone,
                "enabled": True
            }
            user_data["monitored_senders"].append(new_sender)
            flash('Sender added successfully!', 'success')
        else:
            flash('Please provide both sender email and recipient phone.', 'danger')
        
        USERS[current_user.id] = user_data 
        save_users(USERS) # Save to JSON file
        
        return redirect(url_for('settings'))
    
    return render_template('settings.html', monitored_senders=user_data.get("monitored_senders", []))

@app.route('/delete_sender/<int:index>')
@login_required
def delete_sender(index):
    user_data = USERS.get(current_user.id)
    if 0 <= index < len(user_data.get("monitored_senders", [])):
        user_data["monitored_senders"].pop(index)
        USERS[current_user.id] = user_data 
        save_users(USERS) # Save to JSON file
        flash('Sender deleted successfully!', 'success')
    else:
        flash('Invalid sender index.', 'danger')
    return redirect(url_for('settings'))

# --- UPDATED: Gmail API Integration ---

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/userinfo.email', 'openid' , 'https://www.googleapis.com/auth/userinfo.profile']
CLIENT_SECRETS_FILE = os.path.join(app.config['UPLOAD_FOLDER'], 'client_secrets.json') # Temp file for flow setup

# Create client_secrets.json dynamically from .env variables
def create_client_secrets_file():
    client_id = os.getenv('GOOGLE_CLIENT_ID')
    client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
    if not client_id or not client_secret:
        raise ValueError("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be set in .env")

    secrets = {
        "web": {
            "client_id": client_id,
            "project_id": "your-project-id", # Can be dummy or actual project ID
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

        # Save credentials to a file specific to the user
        token_path = os.path.join(app.config['UPLOAD_FOLDER'], f'token_{current_user.id}.pickle')
        with open(token_path, 'wb') as token:
            pickle.dump(credentials, token)

        user_data = USERS.get(current_user.id)
        user_data["gmail_token_path"] = token_path
        USERS[current_user.id] = user_data
        save_users(USERS) # Save updated user data

        flash('Gmail connected successfully!', 'success')
    except Exception as e:
        flash(f"Error connecting Gmail: {e}", 'danger')
    
    # Clean up the temporary client_secrets.json file
    if os.path.exists(CLIENT_SECRETS_FILE):
        os.remove(CLIENT_SECRETS_FILE)

    return redirect(url_for('index'))


# --- SMS Sending Function ---
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


# --- Background Job (Check Gmail for new mails) ---
# This function will be called by APScheduler
import pytz # <-- নতুন ইম্পোর্ট
from tzlocal import get_localzone # <-- নতুন ইম্পোর্ট

def check_gmail_for_new_mails():
    with app.app_context(): # Needed to access Flask app context (e.g., USERS, flash)
        try: # Add a try-except block around the entire function for broader error catching
            # আপনার স্থানীয় টাইমজোন সেট করুন (যেমন Asia/Dhaka)
            try:
                local_tz = get_localzone()
            except pytz.UnknownTimeZoneError:
                local_tz = pytz.timezone('Asia/Dhaka')
            
            # বর্তমান সময় স্থানীয় টাইমজোনে
            now_local = datetime.datetime.now(local_tz)

            print(f"Checking Gmail for new mails at {now_local.strftime('%Y-%m-%d %H:%M:%S %Z%z')}") # <--- পরিবর্তিত লাইন
            
            for user_id, user_data in USERS.items():
                token_path = user_data.get("gmail_token_path")
                monitored_senders = user_data.get("monitored_senders", [])

                print(f"User: {user_id}, Gmail Token Path: {token_path}, Monitored Senders: {monitored_senders}") # <-- নতুন ডিবাগিং প্রিন্ট

                if not token_path or not os.path.exists(token_path) or not monitored_senders:
                    print(f"Skipping user {user_id}: No Gmail token or no senders configured, or token file missing.") # <-- পরিবর্তিত প্রিন্ট
                    continue

                creds = None
                try:
                    with open(token_path, 'rb') as token:
                        creds = pickle.load(token)

                    if not creds or not creds.valid:
                        if creds and creds.expired and creds.refresh_token:
                            print(f"User {user_id}: Gmail token expired, attempting refresh.") # <-- নতুন ডিবাগিং প্রিন্ট
                            creds.refresh(Request())
                        else:
                            print(f"User {user_id}: Gmail token is invalid or expired and cannot be refreshed. Clearing token.")
                            user_data["gmail_token_path"] = None
                            save_users(USERS)
                            continue 
                    
                    with open(token_path, 'wb') as token:
                        pickle.dump(creds, token)
                    print(f"User {user_id}: Gmail credentials loaded and refreshed if needed.") # <-- নতুন ডিবাগিং প্রিন্ট

                    service = build('gmail', 'v1', credentials=creds)

                    query = "is:unread" # Check unread mails
                    print(f"User {user_id}: Querying Gmail with '{query}'.") # <-- নতুন ডিবাগিং প্রিন্ট
                    results = service.users().messages().list(userId='me', q=query).execute()
                    messages = results.get('messages', [])

                    if not messages:
                        print(f"User {user_id}: No new unread messages found from Gmail API.") # <-- পরিবর্তিত প্রিন্ট
                        continue

                    print(f"User {user_id}: Found {len(messages)} unread messages.") # <-- নতুন ডিবাগিং প্রিন্ট
                    for message in messages:
                        msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
                        
                        headers = msg['payload']['headers']
                        from_email = next((header['value'] for header in headers if header['name'] == 'From'), 'Unknown Sender')
                        subject = next((header['value'] for header in headers if header['name'] == 'Subject'), 'No Subject')
                        
                        import re
                        match = re.search(r'<(.+?)>', from_email)
                        clean_from_email = match.group(1) if match else from_email.strip()
                        
                        print(f"Processing message ID: {message['id']}, From: '{clean_from_email}', Subject: '{subject}'") # <-- নতুন ডিবাগিং প্রিন্ট

                        is_monitored_match = False # Flag to check if any sender config matched this email
                        for sender_config in monitored_senders:
                            print(f"Checking sender config: {sender_config['sender_email'].lower()} against '{clean_from_email.lower()}' (enabled: {sender_config['enabled']})") # <-- নতুন ডিবাগিং প্রিন্ট
                            if sender_config["enabled"] and clean_from_email.lower() == sender_config["sender_email"].lower():
                                is_monitored_match = True
                                print(f"Match found for {user_id}: From '{clean_from_email}', Subject '{subject}'")
                                
                                service.users().messages().modify(userId='me', id=message['id'], body={'removeLabelIds': ['UNREAD']}).execute()
                                print(f"Marked message {message['id']} as read.") # <-- নতুন ডিবাগিং প্রিন্ট

                                # SMS মেসেজেও স্থানীয় সময় ব্যবহার করুন
                                sms_message = f"📩 New Mail from {clean_from_email}\n\nSubject: \"{subject}\"\n\nTime: {now_local.strftime('%I:%M%p')}\n\n✅ Mail2SMS BD" # <--- পরিবর্তিত লাইন
                                
                                sms_success = send_sms(sender_config["recipient_phone"], sms_message)

                                log_entry = {
                                    "timestamp": datetime.datetime.now().isoformat(), # Log এ UTC থাকুক, পরে UI তে কনভার্ট করা যাবে
                                    "from_email": clean_from_email,
                                    "subject": subject,
                                    "sms_status": "Sent" if sms_success else "Failed",
                                    "recipient_phone": sender_config["recipient_phone"]
                                }
                                user_data["sms_logs"].append(log_entry)
                                save_users(USERS)
                                
                                if sms_success:
                                    print(f"SMS sent successfully to {sender_config['recipient_phone']} for new mail from {clean_from_email}.")
                                else:
                                    print(f"Failed to send SMS to {sender_config['recipient_phone']} for new mail from {clean_from_email}.")
                                break # Break after finding a match and processing for this message
                        if not is_monitored_match:
                            print(f"No monitored sender matched for email from '{clean_from_email}'. Not sending SMS.") # <-- নতুন ডিবাগিং প্রিন্ট

                except Exception as e:
                    print(f"Error during Gmail API call or processing for user {user_id}: {e}") # <-- পরিবর্তিত প্রিন্ট
        except Exception as e_outer:
            print(f"An unexpected error occurred in check_gmail_for_new_mails for {user_id}: {e_outer}") # <-- নতুন ডিবাগিং প্রিন্ট


# --- Scheduler Setup ---
scheduler = BackgroundScheduler()
# Schedule the job to run every 5 minutes
scheduler.add_job(func=check_gmail_for_new_mails, trigger="interval", minutes=5)
scheduler.start()

# Shut down the scheduler when the app exits
atexit.register(lambda: scheduler.shutdown())


if __name__ == '__main__':
    # Set FLASK_REDIRECT_URI environment variable for local development if not already set
    # This is important for the Google OAuth callback to work correctly
    if os.getenv('FLASK_REDIRECT_URI') is None:
        os.environ['FLASK_REDIRECT_URI'] = 'http://127.0.0.1:5000/callback'
        print(f"Set FLASK_REDIRECT_URI to: {os.environ['FLASK_REDIRECT_URI']}")
    
    app.run(debug=True) # debug=True is for development, set to False in production
