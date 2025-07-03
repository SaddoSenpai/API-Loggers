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
    # In a real app, you might have a fallback or exit strategy.
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
        .key-display { margin-top: 20px; background-color: #e9ecef; padding: 15px; border-radius: 4px; word-wrap: break-word; text-align: left; }
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
        h3 { color: #5a5a5a; margin-top: 0; display: flex; justify-content: space-between; align-items: center; }
        pre { background: #2d2d2d; color: #f2f2f2; padding: 15px; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; font-family: 'Courier New', Courier, monospace; }
        .copy-btn { background: #6c757d; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; transition: background-color 0.2s; }
        .copy-btn:hover { background: #5a6268; }
        .logout-btn { font-size: 14px; color: #007bff; text-decoration: none; font-weight: normal; }
        .empty-log { text-align: center; color: #777; padding: 40px; }
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
                    {% if log.system_content %}
                        <div>
                            <h3>System Prompt <button class="copy-btn" onclick="copyToClipboard(this)">Copy</button></h3>
                            <pre>{{ log.system_content }}</pre>
                        </div>
                    {% endif %}
                    {% if log.user_content %}
                         <div>
                            <h3>Latest User Prompt <button class="copy-btn" onclick="copyToClipboard(this)">Copy</button></h3>
                            <pre>{{ log.user_content }}</pre>
                        </div>
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
    
    # In a real production app, you would never pass the key in the template like this,
    # but for this tool's purpose, it's a simple way to display it once.
    key_display_page = HOME_TEMPLATE + """
    <div class="key-display">
        <strong>Key generated successfully!</strong><br>
        Copy it now, you will not see it again.<br><br>
        <code>{{ new_key }}</code>
    </div>
    """
    return render_template_string(key_display_page, new_key=new_key)


@app.route('/login', methods=['POST'])
def login():
    if not client:
        flash("Database not connected. Cannot log in.", "error")
        return redirect(url_for('home'))

    submitted_key = request.form.get('api_key')
    if not submitted_key:
        flash("API Key is required.", "error")
        return redirect(url_for('home'))

    # Iterate through all users to check the key.
    # Note: For very large user bases, a more direct lookup would be better,
    # but this is secure and fine for thousands of users.
    users = users_collection.find()
    user_found = None
    for user in users:
        if bcrypt.check_password_hash(user['hashed_key'], submitted_key):
            user_found = user
            break
            
    if user_found:
        # Store the user's database ID in the session, not the key itself
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

    # Fetch logs only for the logged-in user, sorted newest first
    user_logs = logs_collection.find({'user_id': session['user_id']}).sort('timestamp', -1)
    
    processed_logs = []
    for log in user_logs:
        timestamp_obj = log['timestamp']
        # Format timestamp to a more readable string
        friendly_timestamp = timestamp_obj.strftime('%A, %B %d, %Y - %I:%M:%S %p UTC')
        
        messages = log.get('data', {}).get('messages', [])
        
        system_content = ""
        user_content = ""

        # Find the system prompt
        for msg in messages:
            if msg.get('role') == 'system':
                system_content = msg.get('content', '')
                break # Found it, no need to continue
        
        # Find the last user prompt
        for msg in reversed(messages):
            if msg.get('role') == 'user':
                user_content = msg.get('content', '')
                break # Found it, no need to continue

        processed_logs.append({
            'friendly_timestamp': friendly_timestamp,
            'system_content': system_content,
            'user_content': user_content
        })
        
    return render_template_string(LOGS_TEMPLATE, logs=processed_logs)


# --- CORE API LOGGING ROUTE ---

@app.route('/v1/chat/completions', methods=['POST', 'OPTIONS'])
def log_and_respond():
    # Handle CORS preflight requests sent by browsers
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    
    # API Key Authentication
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Authorization header is missing or invalid. It must be in 'Bearer YOUR_KEY' format."}), 401
        
    # Extract the key from the "Bearer <key>" string
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

    # --- Log the request to MongoDB ---
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

    # --- Respond with stream or non-stream ---
    is_streaming = input_data.get("stream", False)
    if is_streaming:
        return Response(stream_generator(), headers={'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive'})
    else:
        return jsonify(non_stream_response())


# --- HELPER FUNCTIONS ---

def _build_cors_preflight_response():
    """Builds a response for CORS preflight requests."""
    response = Response()
    # Allow requests from any origin
    response.headers.add("Access-Control-Allow-Origin", "*")
    # Specify allowed headers, including custom ones like Authorization
    response.headers.add('Access-Control-Allow-Headers', "Content-Type,Authorization")
    # Specify allowed HTTP methods
    response.headers.add('Access-Control-Allow-Methods', "GET,POST,OPTIONS")
    return response

def non_stream_response():
    """Generates the standard, single JSON response."""
    return {
      "id": f"chatcmpl-{uuid.uuid4()}",
      "object": "chat.completion",
      "created": int(time.time()),
      "model": "logger-v5",
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
    model_name = "logger-v5"
    
    # First chunk defines the role
    chunk_one = {
      "id": completion_id, "object": "chat.completion.chunk", "created": int(time.time()), "model": model_name,
      "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": None}]
    }
    yield f"data: {json.dumps(chunk_one)}\n\n"
    time.sleep(0.05)

    # Second chunk sends the actual content
    chunk_two = {
      "id": completion_id, "object": "chat.completion.chunk", "created": int(time.time()), "model": model_name,
      "choices": [{"index": 0, "delta": {"content": "(System: Logged successfully.)"}, "finish_reason": None}]
    }
    yield f"data: {json.dumps(chunk_two)}\n\n"
    time.sleep(0.05)

    # Third chunk signals the end of the stream
    chunk_three = {
      "id": completion_id, "object": "chat.completion.chunk", "created": int(time.time()), "model": model_name,
      "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
    }
    yield f"data: {json.dumps(chunk_three)}\n\n"
    
    # Final message required by the spec
    yield "data: [DONE]\n\n"


# --- APP RUNNER ---
if __name__ == '__main__':
    # The host and port are typically managed by the hosting platform (like Replit)
    app.run(host='0.0.0.0', port=8080)
    