
# Library Management System

This project is a full-stack web-based Library Management System, featuring user and admin interfaces for managing book borrowing, user accounts, and session handling. The system is built with Flask for the backend and a combination of HTML, CSS, and JavaScript (with Axios and Bootstrap) for the frontend.

## Table of Contents
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)

---

## Features

- **User Registration & Authentication**: Secure JWT-based user registration and login, with session handling.
- **Book Management**: Admins can add books, while users can view, search, and borrow available books.
- **Admin Dashboard**: Admins have a dedicated dashboard to manage users and books.
- **Session Management**: Token-based session management with automatic logout after inactivity.
- **Responsive Design**: Built with Bootstrap, ensuring mobile and desktop compatibility.

## Technologies Used

- **Frontend**: HTML, CSS (Bootstrap), JavaScript (Axios, Toastify).
- **Backend**: Flask, Flask-JWT-Extended, SQLAlchemy.
- **Database**: SQLite
- **Utilities**: JWT for authentication, Axios for HTTP requests, Toastify for notifications.

## Project Structure

```plaintext
library_management_system/
├── forntend/
│   ├── about.html            # About page
│   ├── admin.html            # Admin dashboard
│   ├── index.html            # Homepage with book display
│   ├── login.html            # Login page
│   ├── profile.html          # User profile page
│   ├── register.html         # Registration page
│   ├── css/
│   │   └── style.css         # CSS for frontend styling
│   └── js/
│       ├── about.js          # JavaScript for About page
│       ├── admin.js          # JavaScript for Admin dashboard
│       ├── index.js          # JavaScript for Homepage
│       ├── login.js          # JavaScript for Login page
│       ├── profile.js        # JavaScript for Profile page
│       └── register.js       # JavaScript for Registration page
├── backend/
│   ├── app.py                # Main backend application file with API routes and configurations
│   ├── create_superuser.py   # Script to create an admin user
│   ├── requirements.txt      # Required packages for the backend
│   ├── instance/
│   │   └── library.db        # SQLite database
│   └── app.log               # Application log file for tracking actions
└── README.md                 # Project documentation
```

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd library_management_system
   ```

2. **Backend Setup**:
    - Navigate to the backend directory:
      ```bash
      cd backend
      ```
    - Create and activate a virtual environment:
      ```bash
      python3 -m venv venv
      source venv/bin/activate   # On Windows use `venv\Scripts\activate`
      ```
    - Install dependencies:
      ```bash
      pip install -r requirements.txt
      ```
    - Set up the database and create tables by running:
      ```bash
      python app.py
      ```
    - Create an admin user by running the `create_superuser.py` script:
      ```bash
      python create_superuser.py
      ```

3. **Frontend Setup**:
   No additional setup required; frontend files are already included.

## Usage

1. **Start the Backend Server**:
   From the backend directory, run:
   ```bash
   flask run
   ```

2. **Access the Application**:
   Open `http://127.0.0.1:5000` in your browser to view the homepage.

3. **Admin Login**:
   Log in using the admin credentials created in the setup to access the admin dashboard.
   or use - email: a@a.com  password: 123

## API Endpoints

- **POST /register**: Register a new user.
- **POST /login**: Log in and receive access and refresh tokens.
- **POST /logout**: Logout by blacklisting the access token.
- **POST /refresh**: Refresh access token.
- **POST /add_books**: Admin-only route to add new books.
- **POST /borrow**: Borrow a book.
- **GET /view**: View all books in the library.
- **GET /search/<field>/<keyword>**: Search for books based on a specific field.

---

## Logging and Error Handling
- The backend logs all actions to `app.log`.
- Error handling for various routes ensures that unauthorized access and incorrect data inputs are managed effectively.



## API Endpoints

### Authentication and User Management
- **POST /register** - Register a new user with details (email, password, etc.). Returns success message if registration is successful.
- **POST /login** - Log in to receive access and refresh tokens. Requires email and password.
- **POST /logout** - Logs the user out by blacklisting the access token.
- **POST /refresh** - Refresh the access token using a valid refresh token.
- **GET /validate-token** - Validates if the provided token is still active.

### Admin-only Endpoints
- **POST /add_books** - Adds a new book to the library. Requires admin privileges.
- **POST /update_user** - Updates user details by admin.
- **GET /view_loans** - Views all active book loans (available to admins).

### Book and Loan Management
- **POST /borrow** - Allows a user to borrow a book by providing book and user IDs.
- **POST /return** - Returns a borrowed book and updates its availability.
- **GET /view** - View all available books in the library with details.
- **GET /search/<field>/<keyword>** - Search for books by a specific field (e.g., author, category, year_published).

### Profile and User-related Endpoints
- **GET /profile** - Retrieve current user's profile details.
- **GET /my_loans** - View current user's active and past loans.

---

## Logging and Error Handling

- All user and admin actions are logged to `app.log`, including login attempts, book borrow/return actions, and admin management tasks.
- Custom error messages provide feedback for failed login attempts, inactive accounts, and invalid token usage.

## Manipulate DB
You can use DB Browser for SQLite to Manipulate the DB
Links to download: https://sqlitebrowser.org/dl/

## Usage Notes

- **Admin Access**: Certain routes are restricted to admin users only. Use the `create_superuser.py` script to create an admin account if none exists.
- **Session Timeout**: User sessions automatically time out after 30 minutes of inactivity, requiring re-authentication.
- **Inactivity**: Users will be logged out automatically after 20 minutes of inactivity as a security feature.

