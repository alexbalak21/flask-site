from flask import Flask, session, redirect, url_for, request
from datetime import timedelta

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Use a strong, random secret key
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Ensure HTTPS is used
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session expiry

@app.route('/')
def index():
    return 'Welcome to the secure Flask app!'

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # Use SSL for development
    
#Regenerate Session IDs
@app.route('/login', methods=['POST'])
def login():
    # Authenticate user
    session.permanent = True  # Use permanent sessions
    session['user_id'] = request.form['user_id']
    session.modified = True  # Regenerate session ID
    return redirect(url_for('index'))


#Implement SameSite Attribute
@app.after_request
def apply_caching(response):
    response.headers["Set-Cookie"] = "session={}; SameSite=Lax; HttpOnly; Secure".format(session.sid)
    return response

#IP Address and User-Agent Validation
@app.before_request
def check_session():
    if 'user_id' in session:
        if session.get('ip') != request.remote_addr or session.get('user_agent') != request.user_agent.string:
            session.clear()  # Invalidate session
            return redirect(url_for('login'))
    else:
        session['ip'] = request.remote_addr
        session['user_agent'] = request.user_agent.string


# Logout Mechanism               
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Multi-Factor Authentication (MFA)
@app.route('/verify', methods=['POST'])
def verify():
    # Verify MFA code
    if request.form['mfa_code'] == 'expected_code':
        session['mfa_verified'] = True
        return redirect(url_for('index'))
    return 'Verification failed', 401