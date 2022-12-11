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

mysql = MySQL(app)

@app.route('/pythonlogin/', methods=['GET', 'POST'])
def signin():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:

        u_name = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        cursor.execute("SELECT * FROM Info WHERE name = '%s' AND password = '%s'" % (u_name, password))
        print("SELECT * FROM Info WHERE name = '%s' AND password = '%s'" % (u_name, password))
        result = cursor.fetchone()

        if result:
            session['loggedin'] = True
            session['id'] = result['id']
            session['u_name'] = result['name']
            return redirect(url_for('home'))
        else:
            msg = 'Please enter valid username and password!'
            print(msg)
    return render_template('index.html', msg=msg)

@app.route('/pythonlogin/logout')
def signout():
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('u_name', None)
   # Redirect to login page
   return redirect(url_for('signin'))

@app.route('/pythonlogin/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        u_name = request.form['username']
        password = request.form['password']
        email = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM Info WHERE name = %s', (u_name,))
        result = cursor.fetchone()
        if result:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', u_name):
            msg = 'Username must contain only characters and numbers!'
        elif not u_name or not password or not email:
            msg = 'Please fill out the form!'
        else:
            cursor.execute('INSERT INTO Info VALUES (NULL, %s, %s, %s)', (u_name, password, email,))
            mysql.connection.commit()
            msg = 'You have successfully registered!'
        print(msg)

    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('register.html', msg=msg)

@app.route('/pythonlogin/home')
def home():
    if 'loggedin' in session:
        return render_template('home.html', username=session['u_name'])
    return redirect(url_for('signin'))

if __name__=="__main__":
    app.run(debug=True)