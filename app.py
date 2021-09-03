import datetime
from functools import wraps
from urllib import request
import jwt
from flask import  jsonify,  make_response
from flask_sqlalchemy import SQLAlchemy
from marshmallow import Schema, fields
from flask import Flask, request, session, redirect, url_for, render_template, flash
import psycopg2
import psycopg2.extras
import re


from werkzeug.security import generate_password_hash, check_password_hash



app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost/API101'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = 'zingallo-secrete-key'
DB_HOST = "localhost"
DB_NAME = "API101"
DB_USER = "postgres"
DB_PASS = ""

db = SQLAlchemy(app)
conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST)


# id
# message
# phonenumber


class Contact(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    message = db.Column(db.String(255), nullable=False)
    phonenumber = db.Column(db.Integer(), nullable=False)

    def __repr__(self):
        return self.message

    @classmethod
    def get_all(cls):
        return cls.query.all()

    @classmethod
    def get_by_id(cls, id):
        return cls.query.get_or_404(id)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()


class ContactSchema(Schema):
    id = fields.Integer()
    message = fields.String()
    phonenumber = fields.Integer()


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('token') #http://127.0.0.1:5000/route?token=alshfjfjdklsfj89549834ur

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 403


            data = jwt.decode(token.encode('UTF-8'), 'SECRET_KEY')

            return jsonify({'message' : 'Token is invalid!'}), 403

        return f(*args, **kwargs)

    return decorated

@app.route('/')
def home():
    # Check if user is loggedin

    entries = Contact.query.all()
    return render_template('API home.html', entries=entries)
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return render_template('API home.html', username=session['username'])
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


@app.route('/login/', methods=['GET', 'POST'])
def login():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        print(password)
        # Check if account exists using MySQL
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        # Fetch one record and return result
        account = cursor.fetchone()

        if account:
            password_rs = account['password']
            print(password_rs)
            # If account exists in users table in out database
            if check_password_hash(password_rs, password):
                # Create session data, we can access this data in other routes
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']

                # Redirect to home page
                return redirect(url_for('home'))

            else:
                # Account doesnt exist or username/password incorrect
                flash('Incorrect username/password')
        else:
            # Account doesnt exist or username/password incorrect
            flash('Incorrect username/password')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        fullname = request.form['fullname']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        _hashed_password = generate_password_hash(password)

        # Check if account exists using MySQL
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()
        print(account)
        # If account exists show error and validation checks
        if account:
            flash('Account already exists!')
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!')
        elif not re.match(r'[A-Za-z0-9]+', username):
            flash('Username must contain only characters and numbers!')
        elif not username or not password or not email:
            flash('Please fill out the form!')
        else:
            # Account doesnt exists and the form data is valid, now insert new account into users table
            cursor.execute("INSERT INTO users (fullname, username, password, email) VALUES (%s,%s,%s,%s)",
                           (fullname, username, _hashed_password, email))
            conn.commit()
            flash('You have successfully registered!')
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        flash('Please fill out the form!')
    # Show registration form with message (if any)
    return render_template('register.html')


@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    # Redirect to login page
    return redirect(url_for('login'))


@app.route('/profile')
def profile():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    # Check if user is loggedin
    if 'loggedin' in session:
        cursor.execute('SELECT * FROM users WHERE id = %s', [session['id']])
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('profile.html', account=account)

    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

@app.route('/Get_Token')
def Get_Token():
    auth = request.authorization

    if auth and auth.password == 'Token':
        token = jwt.encode({'user': auth.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=525600)},
                           app.config['SECRET_KEY'])

        return jsonify({'token': token})

    return make_response('Could not verify!', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})


@app.route('/contact', methods=['GET'])
@token_required
def get_all_contacts():
    contacts = Contact.get_all()

    serializer = ContactSchema(many=True)

    data = serializer.dump(contacts)

    return jsonify(
        data
    )


@app.route('/contact', methods=['POST'])
@token_required
def create_a_contact():
    data = request.get_json()

    new_contact = Contact(
        message=data.get('message'),
        phonenumber=data.get('phonenumber')

    )

    new_contact.save()

    serializer = ContactSchema()

    data = serializer.dump(new_contact)

    return jsonify(
        data
    ), 201


@app.route('/contact/<int:id>', methods=['GET'])
@token_required
def get_contact(id):
    contact = Contact.get_by_id(id)

    serializer = ContactSchema()

    data = serializer.dump(contact)

    return jsonify(
        data
    ), 200


@app.route('/contact/<int:id>', methods=['PUT'])
@token_required
def update_contact(id):
    update_contact = Contact.get_by_id(id)

    data = request.get_json()

    update_contact.message = data.get('message')
    update_contact.phonenumber = data.get('phonenumber')

    db.session.commit()

    serializer = ContactSchema()

    contact_data = serializer.dump(update_contact)

    return jsonify(contact_data), 200


@app.route('/contact/<int:id>', methods=['DELETE'])
@token_required
def delete_contact(id):
    Contact_to_delete = Contact.get_by_id(id)

    Contact_to_delete.delete()

    return jsonify({"message": "Deleted"}), 204



@app.errorhandler(404)
def not_found(error):
    return jsonify({"message": "Resource not found"}), 404


@app.errorhandler(500)
def internal_server(error):
    return jsonify({"message": "There is a problem"}), 500


if __name__ == '__main__':
    app.run(debug=True)
