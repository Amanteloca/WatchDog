import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import hashlib
import secrets

app = Flask(__name__)

# Root route
@app.route('/')
def root():
    return redirect(url_for('login'))

# Configure logging to a file
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

# Generate a random secret key for extra protection
app.secret_key = secrets.token_hex(24)

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'pythonlogin'

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
@app.route('/pythonlogin/home')
def home():
    # Check if the user is logged in
    if 'loggedin' in session:
        # User is logged in, show them the home page
        return render_template('home.html', username=session['username'])
    # User is not logged in, redirect to login page
    return redirect(url_for('login'))


# Login route
@app.route('/pythonlogin/', methods=['GET', 'POST'])
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

                # Redirect to home page
                return redirect(url_for('home'))
            else:
                # Account doesn't exist or username/password incorrect
                msg = 'Incorrect username/password!'
                print("Incorrect username/password!")

        except Exception as e:
            app.logger.error('Error in login route: %s', str(e))
            return render_template('error.html', error=500), 500

    # Show the login form with message (if any)
    return render_template('index.html', msg=msg)


# Logout route
@app.route('/pythonlogin/logout')
def logout():
    # Remove session data, this will log the user out
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    # Redirect to login page
    return redirect(url_for('login'))


# Registration route
@app.route('/pythonlogin/register', methods=['GET', 'POST'])
def register():
    # Output message if something goes wrong...
    msg = ''

    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
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
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            # Hash the password
            hash_value = password + app.secret_key
            hash_value = hashlib.sha1(hash_value.encode())
            password_hashed = hash_value.hexdigest()

            # Account doesn't exist, and the form data is valid,
            # so insert the new account into the accounts table
            cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s)', (username, password_hashed, email,))
            mysql.connection.commit()
            msg = 'You have successfully registered!'

    # Render the registration form template for both GET and POST requests
    return render_template('register.html', msg=msg)

