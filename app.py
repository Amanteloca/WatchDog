import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import hashlib
import secrets

app = Flask(__name__,template_folder="templates")

# Root route
@app.route('/')
def root():
    return redirect(url_for('login'))

# Configure logging to a file
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

# Use a fixed secret key for the Flask app
app.secret_key =' watch_dog_1'

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'watchdoglogin'

# Initialize MySQL
mysql = MySQL(app)

# Error handlers
@app.errorhandler(404)
def page_not_found(error):
    app.logger.error('Page not found: %s', request.path)
    return render_template('error.html', error=404), 404

@app.errorhandler(500)
def internal_server_error(error):
    app.logger.error('Server Error: %s', error)
    return render_template('error.html', error=500), 500

# Home route
@app.route('/watchdoglogin/home')
def home():
    # Check if the user is logged in
    if 'loggedin' in session:
        # User is logged in, show them the home page
        return render_template('home.html', username=session['username'])
    # User is not logged in, redirect to login page
    return redirect(url_for('login'))


# Login route
@app.route('/watchdoglogin/', methods=['GET', 'POST'])
def login():
    # Output a message if something goes wrong...
    msg = ''

    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']

        try:
            # Retrieve the hashed password
            # Encode password and secret_key as bytes
            password_bytes = password.encode('utf-8')
            secret_key_bytes = app.secret_key.encode('utf-8')

            # Combine password and secret_key bytes before hashing
            combined_bytes = password_bytes + secret_key_bytes

            # Hash the combined bytes
            hash_object = hashlib.sha1(combined_bytes)
            password = hash_object.hexdigest()

            # Check if account exists using MySQL
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password,))

            # Fetch one record and return result
            account = cursor.fetchone()

            # If account exists in accounts table in our database
            if account:
                # Create session data, we can access this data in other routes
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']

                # Check if the user has selected "Remember Me"
                if 'remember' in request.form:
                    # Create a response object to set the permanent cookie
                    response = make_response(redirect(url_for('home')))
                    response.set_cookie('username', username, max_age=30 * 24 * 60 * 60)  # 30 days expiration
                    return response

                # Redirect based on user role
                if account['username'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('home'))
            else:
                # Account doesn't exist or username/password incorrect
                msg = 'Incorrect username/password!'

        except Exception as e:
            app.logger.error('Error in login route: %s', str(e))
            return render_template('error.html', error=500), 500

    # Show the login form with message (if any)
    return render_template('index.html', msg=msg)

# Logout route
@app.route('/watchdoglogin/logout')
def logout():
    # Remove session data, this will log the user out
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    # Redirect to login page
    return redirect(url_for('login'))


# Function to check if any accounts exist
def has_any_accounts():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT COUNT(*) FROM accounts')
    count = cursor.fetchone()['COUNT(*)']
    return count > 0

# Registration route
@app.route('/watchdoglogin/register', methods=['GET', 'POST'])
def register():
    # Output message if something goes wrong...
    msg = ''

    # Check if "username", "password", "confirm_password", and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'confirm_password' in request.form and 'email' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']

        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()

        # If account exists show error and validation checks
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not confirm_password or not email:
            msg = 'Please fill out the form!'
        elif password != confirm_password:
            msg = 'Password and confirmation do not match!'
        else:
            # Hash the password
            hash_value = password + app.secret_key
            hash_value = hashlib.sha1(hash_value.encode())
            password_hashed = hash_value.hexdigest()

            # Set the default role
            role = 'user'

            # Check if this is the first account being created (admin)
            if not has_any_accounts():
                role = 'admin'

            # Account doesn't exist, and the form data is valid,
            # so insert the new account into the accounts table with the role
            cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s)', (username, password_hashed, email, role,))
            mysql.connection.commit()
            msg = 'You have successfully registered!'

    # Render the registration form template for both GET and POST requests
    return render_template('register.html', msg=msg)



# profile route 
@app.route('/watchdoglogin/profile')
def profile():
    # Check if the user is logged in
    if 'loggedin' in session:
        # We need all the account info for the user so we can display it on the profile page
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('profile.html', account=account)
    # User is not logged in redirect to login page
    return redirect(url_for('login'))

# Edit profile route
@app.route('/watchdoglogin/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    # Check if the user is logged in
    if 'loggedin' in session:
        # Fetch user details
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        user = cursor.fetchone()

        if request.method == 'POST':
            # Handle form submission to update the user's profile
            new_username = request.form['username']
            new_email = request.form['email']

            # Perform necessary validation checks before updating

            # Update the user's profile in the database
            cursor.execute('UPDATE accounts SET username = %s, email = %s WHERE id = %s',
                           (new_username, new_email, session['id']))
            mysql.connection.commit()

            # Redirect to the profile page after successful update
            return redirect(url_for('profile'))

        # Render the edit profile form with the current user details
        return render_template('edit_profile.html', user=user)

    # User is not logged in, redirect to the login page
    return redirect(url_for('login'))


# Admin route to manage accounts
@app.route('/admin/manage_accounts')
def manage_accounts():
    try:
        # Check if the user is logged in and is an admin
        if 'loggedin' in session and 'username' in session and session['username'] == 'admin':
            # Fetch all accounts from the database
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts')
            accounts = cursor.fetchall()

            # Render the admin view with the list of accounts
            return render_template('admin/manage_accounts.html', accounts=accounts)
        # If not logged in or not an admin, redirect to the login page
        return redirect(url_for('login'))
    except Exception as e:
        app.logger.error('Error fetching accounts: %s', str(e))
        app.logger.error('MySQL error: %s', cursor._last_executed)
        return render_template('error.html', error=500), 500

# Admin route to edit settings
@app.route('/admin/edit_settings', methods=['GET', 'POST'])
def edit_settings():
    # Check if the user is logged in and is an admin
    if 'loggedin' in session and 'username' in session and session['username'] == 'admin':
        # Fetch current settings from the database
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM settings')
        current_settings = cursor.fetchone()

        if request.method == 'POST':
            # Handle form submission to update settings in the database
            new_setting_value = request.form['setting_value']

            # Perform necessary validation checks before updating

            # Update the settings in the database
            cursor.execute('UPDATE settings SET setting_value = %s WHERE id = %s',
                           (new_setting_value, current_settings['id']))
            mysql.connection.commit()

            # Redirect to the admin dashboard after successful update
            return redirect(url_for('admin_dashboard'))

        # Render the admin view with the current settings
        return render_template('admin/edit_settings.html', current_settings=current_settings)
    # If not logged in or not an admin, redirect to the login page
    return redirect(url_for('login'))


# Admin Dashboard route
@app.route('/admin/dashboard')
def admin_dashboard():
    # Render the admin_dashboard.html template
    return render_template('admin/admin_dashboard.html')

# Route to manage email templates
@app.route('/admin/manage_email_templates')
def manage_email_templates():
    try:
        # Check if the user is logged in and is an admin
        if 'loggedin' in session and 'username' in session and session['username'] == 'admin':
            # Fetch all email templates from the database
            email_templates = EmailTemplate.query.all()

            # Render the 'manage_email_template.html' template with the email templates
            return render_template('manage_email_template.html', email_templates=email_templates)

        # If not logged in or not an admin, redirect to the login page
        return redirect(url_for('login'))

    except Exception as e:
        # Handle exceptions appropriately
        app.logger.error('Error fetching email templates: %s', str(e))
        return render_template('error.html', error=500), 500
