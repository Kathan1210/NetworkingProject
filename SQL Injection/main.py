from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re

app = Flask(__name__)

# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'vaidya8'

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'admin'
app.config['MYSQL_DB'] = 'loginDb'

# Intializing MySQL
mysql = MySQL(app)

# http://localhost:5000/pythonlogin/ 
@app.route('/pythonlogin/', methods=['GET', 'POST'])
def login():
    message = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:

        username = request.form['username']
        password = request.form['password']

        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # cursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password,))
        cursor.execute("SELECT * FROM Info WHERE name = '%s' AND password = '%s'" % (username, password))
        print("SELECT * FROM Info WHERE name = '%s' AND password = '%s'" % (username, password))

        # Fetch one record and return result
        result = cursor.fetchone()
        # If account exists in accounts table in out database
        if result:
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            session['id'] = result['id']
            session['username'] = result['name']
            # Redirect to home page
            return redirect(url_for('home'))
        else:
            # Account doesnt exist or username/password incorrect
            message = 'Incorrect username/password!'
    # Show the login form with message (if any)
    return render_template('index.html', message=message)

# http://localhost:5000/python/logout - this will be the logout page
@app.route('/pythonlogin/logout')
def logout():
    # Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   # Redirect to login page
   return redirect(url_for('login'))

# http://localhost:5000/pythinlogin/register - this will be the registration page, we need to use both GET and POST requests
@app.route('/pythonlogin/register', methods=['GET', 'POST'])
def register():
    # Output message if something goes wrong...
    message = ''
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM Info WHERE name = %s', (username,))
        result = cursor.fetchone()
        # If account exists show error and validation checks
        if result:
            message = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            message = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            message = 'Username must contain only characters and numbers!'
        elif not username or not password or not email:
            message = 'Please fill out the form!'
        else:
            # Account doesnt exists and the form data is valid, now insert new account into accounts table
            cursor.execute('INSERT INTO Info VALUES (NULL, %s, %s, %s)', (username, password, email,))
            mysql.connection.commit()
            message = 'You have successfully registered!'

    elif request.method == 'POST':
        # Form is empty... (no POST data)
        message = 'Please fill out the form!'
    # Show registration form with message (if any)
    return render_template('register.html', message=message)

# http://localhost:5000/pythinlogin/home - this will be the home page, only accessible for loggedin users
@app.route('/pythonlogin/home')
def home():
    # Check if user is loggedin
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return render_template('home.html', username=session['username'])
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


if __name__=="__main__":
    app.run(debug=True)