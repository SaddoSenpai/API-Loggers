from flask import (Flask, request, jsonify, Response, render_template_string, 
                   session, redirect, url_for, flash)
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
import json
import datetime
import os
import time
import uuid
import secrets

# --- APP INITIALIZATION ---
app = Flask(__name__)
# Load secret key from environment variables for session security
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-super-secret-key-for-local-dev')
CORS(app)
bcrypt = Bcrypt(app)

# --- DATABASE SETUP ---
try:
    mongo_uri = os.environ.get('MONGO_URI')
    client = MongoClient(mongo_uri)
    db = client.get_database('api_logs_db') # You can name your database anything
    users_collection = db.users
    logs_collection = db.logs
    print("MongoDB connection successful.")
except Exception as e:
    print(f"!!! FATAL: MongoDB connection failed. Reason: {e}")
    client = None


# --- HTML TEMPLATES ---

HOME_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>API Key Manager</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f4f4f9; color: #333; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: #fff; padding: 40px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); text-align: center; max-width: 400px; width: 90%; }
        h1, h2 { color: #4a4a4a; }
        input[type=text] { width: 90%; padding: 10px; margin-bottom: 20px; border: 1px solid #ddd; border-radius: 4px; }
        button { background-color: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; width: 95%; font-size: 16px; transition: background-color 0.2s; }
        button:hover { background-color: #0056b3; }
        .flash { padding: 15px; margin-bottom: 20px; border-radius: 4px; }
        .flash.success { background-color: #d4edda; color: #155724; }
        .flash.error { background-color: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Log Viewer</h1>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash {{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <h2>Login with API Key</h2>
        <form action="{{ url_for('login') }}" method="post">
            <input type="text" name="api_key" placeholder="Enter your API Key" required>
            <button type="submit">View My Logs</button>
        </form>
        
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        
        <h2>Create a new API Key</h2>
        <form action="{{ url_for('generate_key') }}" method="post">
            <button type="submit">Generate New Key</button>
        </form>
    </div>
</body>
</html>
"""

LOGS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>Your API Logs</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; background: #f4f4f9; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 1000px; margin: 0 auto; background: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
        h1 { color: #4a4a4a; border-bottom: 2px solid #eaeaea; padding-bottom: 10px; display: flex; justify-content: space-between; align-items: center; }
        .log-entry { border: 1px solid #ddd; border-radius: 8px; margin-bottom: 25px; overflow: hidden; }
        .log-header { background: #f7f7f7; padding: 10px 15px; border-bottom: 1px solid #ddd; font-weight: bold; }
        .log-body { padding: 15px; }
        .message-block { margin-bottom: 15px; }
        .message-header { color: #5a5a5a; margin-top: 0; display: flex; justify-content: space-between; align-items: center; font-weight: bold; font-family: monospace; font-size: 14px; }
        pre { background: #2d2d2d; color: #f2f2f2; padding: 15px; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; font-family: 'Courier New', Courier, monospace; margin-top: 5px; }
        .copy-btn { background: #6c757d; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; transition: background-color 0.2s; }
        .copy-btn:hover { background: #5a6268; }
        .logout-btn { font-size: 14px; color: #007bff; text-decoration: none; font-weight: normal; }
        .empty-log { text-align: center; color: #777; padding: 40px; }
        .role-system { border-left: 4px solid #6f42c1; padding-left: 10px; }
        .role-user { border-left: 4px solid #007bff; padding-left: 10px; }
        .role-assistant { border-left: 4px solid #28a745; padding-left: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Your Logs <a href="{{ url_for('logout') }}" class="logout-btn">Logout</a></h1>
        {% if logs %}
            {% for log in logs %}
            <div class="log-entry">
                <div class="log-header">Log Timestamp: {{ log.friendly_timestamp }}</div>
                <div class="log-body">
                    {% if log.messages %}
                        {% for message in log.messages %}
                        <div class="message-block role-{{ message.role or 'unknown' }}">
                            <div class="message-header">
                                <span>ROLE: {{ message.role or 'N/A' }}</span>
                                <button class="copy-btn" onclick="copyToClipboard(this)">Copy</button>
                            </div>
                            <pre>{{ message.content or '' }}</pre>
                        </div>
                        {% endfor %}
                    {% else %}
                        <p>No messages found in this log entry.</p>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        {% else %}
            <div class="empty-log">
                <p>No logs found. Use your API Key to send a request to the /v1/chat/completions endpoint first!</p>
            </div>
        {% endif %}
    </div>
    <script>
        function copyToClipboard(button) {
            const pre = button.parentElement.nextElementSibling;
            if (navigator.clipboard) {
                navigator.clipboard.writeText(pre.innerText).then(() => {
                    button.innerText = 'Copied!';
                    setTimeout(() => { button.innerText = 'Copy'; }, 2000);
                }).catch(err => {
                    console.error('Failed to copy text: ', err);
                });
            }
        }
    </script>
</body>
</html>
"""

# --- AUTHENTICATION & HOME ROUTES ---

@app.route('/', methods=['GET'])
def home():
    if 'user_id' in session:
        return redirect(url_for('view_logs'))
    return render_template_string(HOME_TEMPLATE)

@app.route('/generate-key', methods=['POST'])
def generate_key():
    if not client:
        flash("Database not connected. Cannot generate key.", "error")
        return redirect(url_for('home'))

    new_key = secrets.token_urlsafe(32)
    hashed_key = bcrypt.generate_password_hash(new_key).decode('utf-8')
    
    users_collection.insert_one({'hashed_key': hashed_key, 'created_at': datetime.datetime.utcnow()})
    
    # This renders a self-contained page to display the new key with a copy button
    key_display_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8"><title>Your New API Key</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f4f4f9; color: #333; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        </style>
    </head>
    <body>
        <div style="font-family: sans-serif; text-align: center; padding: 40px; background: #fff; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">
            <h2>Your New API Key:</h2>
            <p>Copy it now, you will not see it again.</p>
            <div style="background: #e9ecef; padding: 15px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; word-wrap: break-word; text-align: left;">
                <code id="apiKey" style="flex-grow: 1;">{{ new_key }}</code>
                <button onclick="copyKey(this)" style="margin-left: 15px; background: #6c757d; color: white; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer; transition: background-color 0.2s;">Copy</button>
            </div>
            <br>
            <a href="/" style="color: #007bff; text-decoration: none;">Go back to Login</a>
        </div>
        <script>
            function copyKey(button) {
                const keyText = document.getElementById('apiKey').innerText;
                navigator.clipboard.writeText(keyText).then(() => {
                    button.innerText = 'Copied!';
                    setTimeout(() => { button.innerText = 'Copy'; }, 2000);
                }).catch(err => {
                    console.error('Failed to copy text: ', err);
                });
            }
        </script>
    </body>
    </html>
    """
    return render_template_string(key_display_template, new_key=new_key)


@app.route('/login', methods=['POST'])
def login():
    if not client:
        flash("Database not connected. Cannot log in.", "error")
        return redirect(url_for('home'))

    submitted_key = request.form.get('api_key')
    if not submitted_key:
        flash("API Key is required.", "error")
        return redirect(url_for('home'))

    users = users_collection.find()
    user_found = None
    for user in users:
        if bcrypt.check_password_hash(user['hashed_key'], submitted_key):
            user_found = user
            break
            
    if user_found:
        session['user_id'] = str(user_found['_id'])
        return redirect(url_for('view_logs'))
    else:
        flash("Invalid API Key.", "error")
        return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out.", "success")
    return redirect(url_for('home'))


# --- LOG VIEWING ROUTE ---

@app.route('/logs')
def view_logs():
    if 'user_id' not in session:
        flash("You must be logged in to view logs.", "error")
        return redirect(url_for('home'))
    
    if not client:
        return "Database is not connected.", 500

    user_logs = logs_collection.find({'user_id': session['user_id']}).sort('timestamp', -1)
    
    processed_logs = []
    for log in user_logs:
        timestamp_obj = log['timestamp']
        friendly_timestamp = timestamp_obj.strftime('%A, %B %d, %Y - %I:%M:%S %p UTC')
        
        # Get the entire messages array to be passed to the template
        messages = log.get('data', {}).get('messages', [])
        
        processed_logs.append({
            'friendly_timestamp': friendly_timestamp,
            'messages': messages
        })
        
    return render_template_string(LOGS_TEMPLATE, logs=processed_logs)


# --- CORE API LOGGING ROUTE ---

@app.route('/v1/chat/completions', methods=['POST', 'OPTIONS'])
def log_and_respond():
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Authorization header is missing or invalid. It must be in 'Bearer YOUR_KEY' format."}), 401
        
    try:
        api_key = auth_header.split(' ')[1]
    except IndexError:
        return jsonify({"error": "Bearer token is malformed."}), 401

    if not client:
        return jsonify({"error": "Database service is temporarily unavailable"}), 503

    users = users_collection.find()
    user_found = None
    for user in users:
        if bcrypt.check_password_hash(user['hashed_key'], api_key):
            user_found = user
            break
            
    if not user_found:
        return jsonify({"error": "Invalid API Key"}), 401

    try:
        input_data = request.get_json()
        log_entry = {
            'user_id': str(user_found['_id']),
            'timestamp': datetime.datetime.utcnow(),
            'data': input_data
        }
        logs_collection.insert_one(log_entry)
    except Exception as e:
        print(f"!!! ERROR: Could not log request to DB. Reason: {e}")
        return jsonify({"error": "Internal server error during logging"}), 500

    is_streaming = input_data.get("stream", False)
    if is_streaming:
        return Response(stream_generator(), headers={'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive'})
    else:
        return jsonify(non_stream_response())


# --- HELPER FUNCTIONS ---

def _build_cors_preflight_response():
    """Builds a response for CORS preflight requests."""
    response = Response()
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add('Access-Control-Allow-Headers', "Content-Type,Authorization")
    response.headers.add('Access-Control-Allow-Methods', "GET,POST,OPTIONS")
    return response

def non_stream_response():
    """Generates the standard, single JSON response."""
    return {
      "id": f"chatcmpl-{uuid.uuid4()}",
      "object": "chat.completion",
      "created": int(time.time()),
      "model": "logger-v6",
      "choices": [{
          "index": 0,
          "message": {
              "role": "assistant",
              "content": "(System: Logged successfully.)"
          },
          "finish_reason": "stop"
      }],
      "usage": {
          "prompt_tokens": 0,
          "completion_tokens": 0,
          "total_tokens": 0
      }
    }

def stream_generator():
    """Generates a mock streaming response to satisfy clients."""
    completion_id = f"chatcmpl-{uuid.uuid4()}"
    model_name = "logger-v6"
    
    chunk_one = {
      "id": completion_id, "object": "chat.completion.chunk", "created": int(time.time()), "model": model_name,
      "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": None}]
    }
    yield f"data: {json.dumps(chunk_one)}\n\n"
    time.sleep(0.05)

    chunk_two = {
      "id": completion_id, "object": "chat.completion.chunk", "created": int(time.time()), "model": model_name,
      "choices": [{"index": 0, "delta": {"content": "(System: Logged successfully.)"}, "finish_reason": None}]
    }
    yield f"data: {json.dumps(chunk_two)}\n\n"
    time.sleep(0.05)

    chunk_three = {
      "id": completion_id, "object": "chat.completion.chunk", "created": int(time.time()), "model": model_name,
      "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
    }
    yield f"data: {json.dumps(chunk_three)}\n\n"
    
    yield "data: [DONE]\n\n"


# --- APP RUNNER ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

