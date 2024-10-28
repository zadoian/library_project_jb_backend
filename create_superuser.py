import getpass  # To securely handle password input
from app import app, db  # Import the Flask app and database instances
from app import User  # Import the User model to create the Superuser
from werkzeug.security import generate_password_hash  # To securely hash passwords

# Run this script within the Flask application context
with app.app_context():
    # Prompt for Superuser creation details
    print("Create Superuser")

    # Collect necessary user details for the Superuser account
    first_name = input("First Name: ")
    last_name = input("Last Name: ")
    email = input("Email: ")
    password = getpass.getpass("Password: ")  # Get password securely
    gender = input("Gender: ")
    age = int(input("Age: "))
    city = input("City: ")
    address = input("Address: ")
    phone_number = input("Phone Number: ")

    # Check if the email is already in use
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        print("Error: A user with this email already exists.")
    else:
        # Hash the password for secure storage
        hashed_password = generate_password_hash(password)

        # Create a new User object with 'admin' type to designate Superuser role
        superuser = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password_hash=hashed_password,
            gender=gender,
            age=age,
            city=city,
            address=address,
            phone_number=phone_number,
            type='admin'  # Designate this user as an admin
        )

        # Add and commit the new Superuser to the database
        db.session.add(superuser)
        db.session.commit()
        print(f"Superuser {first_name} {last_name} created successfully.")
