from logging.handlers import RotatingFileHandler
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_jwt_extended.exceptions import NoAuthorizationError, RevokedTokenError
import logging
from flask_jwt_extended import (
    JWTManager, get_jwt, jwt_required, create_access_token,
    create_refresh_token, get_jwt_identity, verify_jwt_in_request
)

# Constants
JWT_SECRET_KEY = 'your_secret_key'
JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=1)
SQLALCHEMY_DATABASE_URI = 'sqlite:///library.db'

# Initialize Flask app
app = Flask(__name__)

# JWT and Database configuration
app.config.update(
    JWT_TOKEN_LOCATION=['headers'],
    JWT_BLACKLIST_TOKEN_CHECKS=['access', 'refresh'],
    JWT_BLACKLIST_ENABLED=True,
    JWT_COOKIE_CSRF_PROTECT=False,
    JWT_SECRET_KEY=JWT_SECRET_KEY,
    JWT_ACCESS_TOKEN_EXPIRES=JWT_ACCESS_TOKEN_EXPIRES,
    JWT_REFRESH_TOKEN_EXPIRES=JWT_REFRESH_TOKEN_EXPIRES,
    SQLALCHEMY_DATABASE_URI=SQLALCHEMY_DATABASE_URI
)

# Initialize extensions
db = SQLAlchemy(app)
CORS(app)
jwt = JWTManager(app)
blacklist = set()  # Consider using Redis for a persistent blacklist

def setup_logging():
    """Set up logging for the application."""
    log_file_handler = RotatingFileHandler('app.log', maxBytes=1024 * 1024, backupCount=5)
    log_file_handler.setLevel(logging.DEBUG)
    log_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    app.logger.addHandler(log_file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    app.logger.addHandler(console_handler)
    app.logger.setLevel(logging.DEBUG)

setup_logging()

@app.before_request
def log_request_info():
    """Log request headers and body before handling the request."""
    app.logger.debug("Request Headers: %s", request.headers)
    app.logger.debug("Request Body: %s", request.get_data())

@app.after_request
def log_response_info(response):
    """Log response status, headers, and body after handling the request."""
    app.logger.debug("Response Status: %s", response.status)
    app.logger.debug("Response Headers: %s", response.headers)
    app.logger.debug("Response Body: %s", response.get_data())
    return response

@app.errorhandler(Exception)
def handle_exception(error):
    """Global exception handler to catch unhandled exceptions."""
    app.logger.error("Unhandled Exception: %s", error, exc_info=True)
    return jsonify({'error': 'An unexpected error occurred'}), 500

@jwt.token_in_blocklist_loader
def check_if_token_is_blacklisted(jwt_header, jwt_payload):
    """Check if token is blacklisted."""
    jti = jwt_payload['jti']
    return jti in blacklist

def fetch_user(user_id):
    """Fetch user by ID and log a warning if the user does not exist."""
    user = User.query.get(user_id)
    if not user:
        app.logger.warning("User with ID %s not found.", user_id)
    return user

def admin_required(func):
    """Decorator to restrict access to admin users only."""
    @jwt_required()
    def wrapper(*args, **kwargs):
        token_data = get_jwt_identity()
        if token_data.get('role') != 'admin':
            app.logger.warning("Access denied. Admin only.")
            return jsonify({"error": "Access denied. Admin only."}), 403
        return func(*args, **kwargs)
    return wrapper

# Models
class User(db.Model):
    """User model for storing user details."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    type = db.Column(db.String(20), nullable=False, default='user')
    status = db.Column(db.String(30), nullable=False, default="Active") 
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    gender = db.Column(db.String(30), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    city = db.Column(db.String(30), nullable=False)
    address = db.Column(db.String(30), nullable=False)
    phone_number = db.Column(db.Integer, nullable=False)
    user_loans = db.relationship('Loan', back_populates='borrower', lazy=True)

class Book(db.Model):
    """Book model for storing book details."""
    __tablename__ = 'books'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(30), unique=True, nullable=False)
    author = db.Column(db.String(30), nullable=False)
    category = db.Column(db.String(30), nullable=False)
    year_published = db.Column(db.Integer, nullable=False)
    summary = db.Column(db.String(300), nullable=False)
    type_borrow = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(30), nullable=False, default="Borrow")  
    img = db.Column(db.String(500), nullable=True)
    book_loans = db.relationship('Loan', back_populates='loaned_book', lazy=True)

class Loan(db.Model):
    """Loan model for managing book loans."""
    __tablename__ = 'loans'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cust_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False)
    status = db.Column(db.String(30), nullable=False, default="Borrow")
    loan_date = db.Column(db.DateTime, nullable=False) 
    return_date = db.Column(db.DateTime, nullable=False)
    borrower = db.relationship('User', back_populates='user_loans')
    loaned_book = db.relationship('Book', back_populates='book_loans')

# Route functions
@app.route('/register', methods=['POST'])
def register():
    """Register a new user."""
    data = request.json
    if User.query.filter_by(email=data.get('email')).first():
        app.logger.info("Email %s already exists.", data['email'])
        return jsonify({'error': 'Email already exists'}), 400
    
    user_data = User(
        email=data.get('email'),
        password_hash=generate_password_hash(data.get('password')),
        first_name=data.get('first_name'),
        last_name=data.get('last_name'),
        gender=data.get('gender'),
        age=data.get('age'),
        city=data.get('city'),
        address=data.get('address'),
        phone_number=data.get('phone_number')
    )
    try:
        db.session.add(user_data)
        db.session.commit()
        app.logger.info("User %s registered successfully", data['email'])
        return jsonify({'message': f"User {data['email']} registered successfully"}), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error("Error registering user: %s", e, exc_info=True)
        return jsonify({'error': 'Failed to register user'}), 500

# User login route
@app.route('/login', methods=['POST'])
def login():
    """Authenticate user and provide access and refresh tokens."""
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        app.logger.info("Invalid email or password for user: %s", email)
        return jsonify({'error': 'Invalid email or password'}), 401

    if user.status != 'Active':
        app.logger.info("Inactive account for user: %s", email)
        return jsonify({'error': 'User account is not active'}), 403

    access_token = create_access_token(identity={'email': user.email, 'role': user.type, 'user_id': user.id})
    refresh_token = create_refresh_token(identity={'email': user.email, 'role': user.type, 'user_id': user.id})

    app.logger.info("User %s logged in successfully", email)
    return jsonify({
        'message': 'Logged in successfully',
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user_id': user.id,
        'user_name': f"{user.first_name} {user.last_name}"
    }), 200

# Logout route
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout user by adding tokens to the blacklist."""
    token_data = get_jwt_identity()
    jti = get_jwt()["jti"]
    refresh_token_jti = request.json.get('refresh_token_jti')

    blacklist.add(jti)
    blacklist.add(refresh_token_jti)

    app.logger.info("User %s successfully logged out", token_data.get('email'))
    return jsonify({"message": "Successfully logged out"}), 200

# Refresh token route
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh the access token using a valid refresh token."""
    try:
        jwt_data = get_jwt()
        app.logger.info("Refreshing access token for %s", jwt_data)

        current_user = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user)
        new_refresh_token = create_refresh_token(identity=current_user)

        return jsonify({
            'message': 'Access token refreshed',
            'access_token': new_access_token,
            'refresh_token': new_refresh_token
        }), 200
    except (NoAuthorizationError, RevokedTokenError) as e:
        app.logger.error("Failed to refresh token: %s", str(e))
        return jsonify({'error': 'Failed to refresh token'}), 401

# Token validation route
@app.route('/validate-token', methods=['POST'])
def validate_token():
    """Validate the access token."""
    try:
        verify_jwt_in_request()
        user_identity = get_jwt_identity()
        app.logger.info("Token is valid for user: %s", user_identity)
        return jsonify({'message': 'Token is valid', 'user': user_identity}), 200
    except Exception as e:
        app.logger.error("Token validation failed: %s", e)
        return jsonify({'error': 'Invalid or expired token'}), 401

# Admin-only route to add books
@app.route('/add_books', methods=['POST'])
@admin_required
def add_books():
    """Add a new book to the library. Admins only."""
    data = request.json
    if Book.query.filter_by(name=data.get('name')).first():
        app.logger.info("Book %s already exists.", data.get('name'))
        return jsonify({'error': 'Book already exists'}), 400

    book = Book(
        name=data.get('name'),
        author=data.get('author'),
        category=data.get('category'),
        year_published=data.get('year_published'),
        summary=data.get('summary'),
        type_borrow=data.get('type_borrow'),
        img=data.get('img')
    )

    db.session.add(book)
    db.session.commit()
    app.logger.info("Book %s added successfully", book.name)
    return jsonify({'message': f"Book {book.name} added successfully"}), 201

# Borrow route
@app.route('/borrow', methods=['POST'])
@jwt_required()
def borrow():
    """Borrow a book by providing user and book IDs."""
    token_data = get_jwt_identity()
    data = request.json

    user = User.query.get(data.get('cust_id'))
    if not user:
        app.logger.info("User %s not found", data.get('cust_id'))
        return jsonify({'error': 'User does not exist'}), 400

    book = Book.query.get(data.get('book_id'))
    if not book:
        app.logger.info("Book %s not found", data.get('book_id'))
        return jsonify({'error': 'Book does not exist'}), 400

    if book.status != "Borrow":
        app.logger.info("Book %s is already borrowed", book.name)
        return jsonify({'message': 'Book is already borrowed'}), 400

    loan_date = datetime.now()
    return_date = loan_date + timedelta(days={1: 10, 2: 5}.get(book.type_borrow, 2))

    loan = Loan(cust_id=user.id, book_id=book.id, loan_date=loan_date, return_date=return_date, status="Borrow")
    book.status = "Unavailable"

    db.session.add(loan)
    db.session.commit()
    app.logger.info("Book %s borrowed by %s", book.name, user.email)
    return jsonify({'user_name': f"{user.first_name} {user.last_name}", 'loan_date': loan_date, 'return_date': return_date})

# View books route
@app.route('/view', methods=['GET'])
def view_books():
    """View all books in the library."""
    books = Book.query.all()
    books_list = [{
        'id': book.id,
        'name': book.name,
        'author': book.author,
        'category': book.category,
        'year_published': book.year_published,
        'summary': book.summary,
        'type_borrow': book.type_borrow,
        'status': book.status,
        'img': book.img
    } for book in books]
    app.logger.info("Viewed %d books", len(books_list))
    return jsonify(books_list), 200

# Search books route
@app.route('/search/<selc>/<kw>', methods=['GET'])
def search_books(selc, kw):
    """Search for books based on column and keyword."""
    valid_columns = ['name', 'author', 'category', 'year_published']
    if selc not in valid_columns:
        app.logger.info("Invalid search field: %s", selc)
        return jsonify({"error": "Invalid search field"}), 400

    books = Book.query.filter(getattr(Book, selc).ilike(f"%{kw}%")).all()
    if not books:
        app.logger.info("No books found for search: %s = %s", selc, kw)
        return jsonify({"message": "No books found"}), 400

    books_list = [{
        'id': book.id,
        'name': book.name,
        'author': book.author,
        'category': book.category,
        'year_published': book.year_published,
        'summary': book.summary,
        'type_borrow': book.type_borrow,
        'status': book.status,
        'img': book.img
    } for book in books]
    app.logger.info("Found %d books for search: %s = %s", len(books_list), selc, kw)
    return jsonify(books_list), 200

# Route to view user profile details
@app.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    token_data = get_jwt_identity()  # Retrieve token data
    app.logger.info(f"Token Data: {token_data}")

    # Get the user ID from the token data
    user_id = token_data.get('user_id') if isinstance(token_data, dict) else token_data
    app.logger.info(f"User ID: {user_id}")

    # Verify if the user ID is valid
    if not user_id:
        app.logger.info('Error: User ID is missing or invalid')
        return jsonify({'error': 'User ID is missing or invalid'}), 400

    # Retrieve the user details from the database
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Collect data for books currently borrowed by the user
    borrowed_books_data = []
    for loan in user.user_loans:
        if loan.status == "Borrow":  
            book_data = {
                'id': loan.loaned_book.id,
                'title': loan.loaned_book.name,
                'author': loan.loaned_book.author,
                'img': loan.loaned_book.img,
                'borrow_date': loan.loan_date.strftime('%Y-%m-%d'),
                'return_date': loan.return_date.strftime('%Y-%m-%d') if loan.return_date else None
            }
            borrowed_books_data.append(book_data)
    
    app.logger.info(f"Profile loaded for {token_data}")

    # Return the user's profile and borrowed book details
    return jsonify({
        'username': f"{user.first_name} {user.last_name}",
        'borrowed_books': borrowed_books_data
    }), 200

# Route to return a borrowed book
@app.route('/return-book', methods=['POST'])
@jwt_required()
def return_book():
    token_data = get_jwt_identity()  # Retrieve token data
    app.logger.info(f"Incoming request data by: {token_data}")

    # Get the book ID from the request JSON data
    data = request.get_json()
    book_id = data.get('book_id')

    # Validate that the book ID is provided
    if not book_id:
        return jsonify({'error': 'Book ID is missing'}), 400

    # Retrieve the user ID from the token
    user_id = get_jwt_identity().get('user_id')
    app.logger.info(f"User ID: {user_id}, Book ID: {book_id}")

    # Find the loan record for the book with status "Borrow"
    loan = Loan.query.filter_by(cust_id=user_id, book_id=book_id, status="Borrow").first()
    if not loan:
        return jsonify({'error': 'Loan record not found or already returned'}), 400

    # Update the loan status to "Returned" and set the return date to the current date
    loan.status = "Returned"
    loan.return_date = datetime.now()

    # Update the book status back to "Borrow" (available for borrowing)
    book = Book.query.get(book_id)
    book.status = "Borrow"

    # Commit the changes to the database
    db.session.commit()
    app.logger.info(f"Book returned successfully by: {token_data}")

    return jsonify({'message': 'Book returned successfully'}), 200

# Route to edit book details
@app.route('/book_edit/<int:book_id>', methods=['POST'])
@jwt_required() 
def book_edit(book_id):
    token_data = get_jwt_identity()  # Retrieve token data
    user_role = token_data.get('role')  # Get user role from token

    # Check if the user is an admin
    if user_role != 'admin':
        app.logger.info(f"Access denied for {token_data}")
        return jsonify({"error": "You do not have access to this resource"}), 403

    # Retrieve the book from the database by its ID
    book = Book.query.get(book_id)
    if not book:
        return jsonify({"error": "Book not found"}), 404

    # Update the book details with data from the request
    data = request.json
    book.name = data.get('name', book.name)
    book.author = data.get('author', book.author)
    book.category = data.get('category', book.category)
    book.year_published = data.get('year_published', book.year_published)
    book.summary = data.get('summary', book.summary)
    book.type_borrow = data.get('type_borrow', book.type_borrow)
    book.status = data.get('status', book.status)
    book.img = data.get('img', book.img)

    # Commit changes to the database or roll back in case of error
    try:
        db.session.commit()
        app.logger.info(f"Book '{book.name}' updated successfully by {token_data}")
        return jsonify({"message": f"Book '{book.name}' updated successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to update book", "details": str(e)}), 500

# Route to view or update user information, accessible only to admins
@app.route('/users', methods=['GET', 'POST'])
@jwt_required()
def users():
    token_data = get_jwt_identity()  # Retrieve token data
    user_role = token_data.get('role')  # Get user role from token
    app.logger.info(f"User endpoint requested by {token_data}")

    # Check if the user is an admin
    if user_role != 'admin':
        return jsonify({"error": "You do not have access to this resource"}), 403

    # GET request: Retrieve all users
    if request.method == 'GET':
        users = User.query.all()
        users_list = []
        for user in users:
            users_list.append({
                'id': user.id,
                'email': user.email,
                'type': user.type,
                'status': user.status,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'gender': user.gender,
                'age': user.age,
                'city': user.city,
                'address': user.address,
                'phone_number': user.phone_number
            })
        return jsonify(users_list), 200

    # POST request: Update an existing user’s information
    elif request.method == 'POST':
        data = request.json
        user_id = data.get('id')

        # Validate that user ID is provided
        if not user_id:
            return jsonify({"error": "User ID is required to update"}), 400

        # Retrieve the user by ID
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Update the user details
        user.first_name = data.get('first_name', user.first_name)
        user.last_name = data.get('last_name', user.last_name)
        user.gender = data.get('gender', user.gender)
        user.age = data.get('age', user.age)
        user.city = data.get('city', user.city)
        user.address = data.get('address', user.address)
        user.phone_number = data.get('phone_number', user.phone_number)
        user.status = data.get('status', user.status)

        # Commit changes to the database or roll back in case of error
        try:
            db.session.commit()
            app.logger.info(f"User {user.first_name} {user.last_name} updated successfully by {token_data}")
            return jsonify({"message": f"User '{user.first_name} {user.last_name}' updated successfully!"}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": "Failed to update user", "details": str(e)}), 500

# Route to check if the user has admin access
@app.route('/aprove', methods=['GET'])
@jwt_required()
def admin_check():
    token_data = get_jwt_identity()  # Retrieve token data
    user_role = token_data.get('role')  # Get user role from token
    app.logger.info(f"User attempting to access admin page: {token_data}")

    # Allow access only if the user is an admin
    if user_role == 'admin':
        app.logger.info(f"Access granted for admin: {token_data}")
        return jsonify({"message": "Access granted"}), 200
    else:
        app.logger.info(f"Access denied to admin page for: {token_data}")
        return jsonify({"error": "Access denied. Admin only."}), 403

# Route to view all loan records, accessible only to admins
@app.route('/view_loans', methods=['GET'])
@jwt_required()
def view_loans():
    token_data = get_jwt_identity()  # Retrieve token data
    user_role = token_data.get('role')  # Get user role from token
    app.logger.info(f"Loan view endpoint requested by {token_data}")

    # Allow access only if the user is an admin
    if user_role != 'admin':
        return jsonify({"error": "You do not have access to this resource"}), 403

    # Retrieve all loans and their details
    loans = Loan.query.all()
    loans_list = []
    for loan in loans:
        loans_list.append({
            'loan_id': loan.id,
            'book_name': loan.loaned_book.name,
            'book_author': loan.loaned_book.author,
            'book_category': loan.loaned_book.category,
            'loan_date': loan.loan_date.strftime('%Y-%m-%d'),
            'return_date': loan.return_date.strftime('%Y-%m-%d'),
            'loan_status': loan.status,
            'user_email': loan.borrower.email
        })

    app.logger.info("Loans view loaded successfully")
    return jsonify(loans_list), 200

# Start the Flask app with loggers and database setup
if __name__ == '__main__':
    # Rotating file handler for logging
    log_file_handler = RotatingFileHandler('app.log', maxBytes=1024 * 1024, backupCount=5)
    log_file_handler.setLevel(logging.INFO) 
    log_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

    app.logger.addHandler(log_file_handler)

    # Console handler for logging
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    app.logger.addHandler(console_handler)

    # Create all database tables
    with app.app_context():
        db.create_all()

    # Start the Flask app
    app.run(debug=True)
