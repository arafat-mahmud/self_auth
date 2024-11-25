# import os from flask import Flask, render_template, request, redirect, url_for, session, flash from 
# flask_sqlalchemy import SQLAlchemy from flask_bcrypt import Bcrypt from flask_admin import Admin # 
# Import Flask-Admin from flask_admin.contrib.sqla import ModelView # Import ModelView to add models to 
# admin


import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView



# Create Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Use a random secret key for better security

# Updated the database URI to use a relative path in the 'instance' folder
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(basedir, 'instance', 'db.sql3')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable unnecessary tracking of modifications

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)  # Unique email constraint
    password = db.Column(db.String(150), nullable=False)

# Create the database tables if they do not exist (only once, ensure DB is clean)
with app.app_context():
    db.create_all()

# Initialize Flask-Admin
admin = Admin(app, name='Self Auth Admin', template_mode='bootstrap3')  # Set the admin title and template
admin.add_view(ModelView(User, db.session))  # Add User model to the admin interface

# Home route
@app.route('/')
def home():
    return render_template('home.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Find the user by email
        user = User.query.filter_by(email=email).first()
        
        # Validate password
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id  # Store user ID in session
            return redirect(url_for('welcome', username=user.name))  # Redirect to the welcome page
        else:
            flash('Invalid email or password', 'danger')  # Flash error message if invalid login
    return render_template('login.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        
        # Check if email is already registered (database check)
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('This email is already registered. Please login or use a different email.', 'danger')
            return render_template('register.html')  # Render register page again with message
        
        # Hash the password before storing it
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Create new user and add to database
        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))  # Redirect to login after successful registration
    
    return render_template('register.html')

# Welcome route
@app.route('/welcome')
def welcome():
    if 'user_id' not in session:  # Check if user is logged in
        return redirect(url_for('login'))  # Redirect to login if not logged in
    user = User.query.get(session['user_id'])  # Get the logged-in user by ID
    return render_template('welcome.html', username=user.name)  # Display welcome message

# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove the user ID from the session
    return redirect(url_for('home'))  # Redirect to home page after logout

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
