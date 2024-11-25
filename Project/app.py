from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)

# Configure PostgreSQL database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Akhila%40910@127.0.0.1:5432/DemoProject'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    address = db.Column(db.Text, nullable=False)
    pan_card_number = db.Column(db.String(10), unique=True, nullable=False)
    aadhar_number = db.Column(db.String(12), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)  # Increased length to 256

    def __init__(self, full_name, email, phone_number, address, pan_card_number, aadhar_number, password):
        self.full_name = full_name
        self.email = email
        self.phone_number = phone_number
        self.address = address
        self.pan_card_number = pan_card_number
        self.aadhar_number = aadhar_number
        self.password_hash = generate_password_hash(password)

@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    
    # Extract data from the request
    full_name = data.get('full_name')
    email = data.get('email')
    phone_number = data.get('phone_number')
    address = data.get('address')
    pan_card_number = data.get('pan_card_number')
    aadhar_number = data.get('aadhar_number')
    password = data.get('password')
    confirm_password = data.get('confirm_password')
    
    # Basic validation (you can expand these based on your requirements)
    if not re.match(r"^[A-Z]{5}[0-9]{4}[A-Z]{1}$", pan_card_number):
        return jsonify({'error': 'Invalid PAN format'}), 400
    if not re.match(r"^\d{12}$", aadhar_number):
        return jsonify({'error': 'Aadhar number must be 12 digits'}), 400
    if not re.match(r"^[6-9]\d{9}$", phone_number):
        return jsonify({'error': 'Invalid phone number format'}), 400
    if password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password should be at least 8 characters long'}), 400
    
    # Save the new user in the database
    new_user = User(full_name, email, phone_number, address, pan_card_number, aadhar_number, password)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully!'}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'User with this email, PAN, or Aadhaar already exists'}), 409
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    # Get email and password from the request
    email = data.get('email')
    password = data.get('password')
    
    # Find user by email
    user = User.query.filter_by(email=email).first()
    
    # Check if user exists and if the password is correct
    if user and check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Login successful!'}), 200
    else:
        return jsonify({'error': 'Invalid email or password'}), 401

if __name__ == '__main__':
    # Ensure tables are created within the application context
    with app.app_context():
        try:
            db.create_all()
            print("Tables created successfully.")
        except Exception as e:
            print("Error creating tables:", str(e))
    app.run(debug=True)
