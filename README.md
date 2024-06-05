
# Flask Forum Application

## Made by @c4gwn
## License: MIT
## Date: 19.05.2024

This repository contains a Flask-based forum application that allows users to create topics, post messages, send private messages, and more. This README provides detailed instructions for setup, configuration, and usage.

## Table of Contents

1. [Installation](#installation)
2. [Configuration](#configuration)
3. [Running the Application](#running-the-application)
4. [HTTP Endpoints](#http-endpoints)
   - [GET /](#get-)
   - [GET /topic/<topic_id>](#get-topictopic_id)
   - [POST /new_topic](#post-new_topic)
   - [POST /topic/<topic_id>/new_post](#post-topictopic_idnew_post)
   - [POST /register](#post-register)
   - [POST /login](#post-login)
   - [POST /logout](#post-logout)
5. [JavaScript Usage Examples](#javascript-usage-examples)

## Installation

To set up this Flask application on your local machine, follow these steps:

### Prerequisites

- Python 3.x
- Flask
- Flask-SQLAlchemy
- Flask-Login
- Werkzeug

### Clone the Repository

```bash
git clone https://github.com/pyroalww/Forum-Backend
cd Forum-Backend
```

### Create a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Set Up the Database

Create the SQLite database and the necessary tables:

```bash
flask db init
flask db migrate -m "Initial migration."
flask db upgrade
```

### Configuration

Open `config.py` and update the configuration settings as needed. Key configuration options include:

- `SQLALCHEMY_DATABASE_URI`: The database URI, e.g., `sqlite:///forum.db`
- `SECRET_KEY`: A secret key for session management
- `UPLOAD_FOLDER`: Directory for user uploads
- `MAX_CONTENT_LENGTH`: Maximum size for uploaded files
- `ALLOWED_EXTENSIONS`: Allowed file extensions for uploads
- `ADMIN_USERS`: List of admin usernames

### Running the Application

To run the application, execute:

```bash
flask run
```

The application will be available at `http://127.0.0.1:5000/`.

## HTTP Endpoints

### GET /

Renders the home page with a list of topics.

#### Request

```http
GET /
```

#### Response

Renders `index.html` with topics.

### GET /topic/<topic_id>

Renders a specific topic with its posts.

#### Request

```http
GET /topic/<topic_id>
```

#### Response

Renders `index.html` with the specified topic and its posts.

### POST /new_topic

Creates a new topic.

#### Request

```http
POST /new_topic
Content-Type: application/x-www-form-urlencoded

title=New Topic Title
```

#### Response

Redirects to the new topic page.

### POST /topic/<topic_id>/new_post

Creates a new post in a specified topic.

#### Request

```http
POST /topic/<topic_id>/new_post
Content-Type: application/x-www-form-urlencoded

content=This is the content of the new post.
```

#### Response

Redirects to the topic page with the new post.

### POST /register

Registers a new user.

#### Request

```http
POST /register
Content-Type: application/x-www-form-urlencoded

username=newuser
email=newuser@example.com
password=password123
```

#### Response

Redirects to the login page.

### POST /login

Logs in an existing user.

#### Request

```http
POST /login
Content-Type: application/x-www-form-urlencoded

username=existinguser
password=password123
```

#### Response

Redirects to the home page upon successful login.

### POST /logout

Logs out the current user.

#### Request

```http
POST /logout
```

#### Response

Redirects to the home page.

## JavaScript Usage Examples

### Fetch API for Making HTTP Requests

#### Example: Registering a New User

```javascript
const registerUser = async () => {
    const response = await fetch('/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'password123'
        })
    });

    if (response.ok) {
        console.log('User registered successfully');
    } else {
        console.error('Error registering user');
    }
};
registerUser();
```

#### Example: Logging In a User

```javascript
const loginUser = async () => {
    const response = await fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
            'username': 'existinguser',
            'password': 'password123'
        })
    });

    if (response.ok) {
        console.log('User logged in successfully');
    } else {
        console.error('Error logging in user');
    }
};
loginUser();
```

#### Example: Creating a New Topic

```javascript
const createNewTopic = async () => {
    const response = await fetch('/new_topic', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
            'title': 'New Topic Title'
        })
    });

    if (response.ok) {
        console.log('New topic created successfully');
    } else {
        console.error('Error creating new topic');
    }
};
createNewTopic();
```

### Handling File Uploads

#### Example: Uploading a User Avatar

```javascript
const uploadAvatar = async (userId, file) => {
    const formData = new FormData();
    formData.append('avatar', file);

    const response = await fetch(`/user/${userId}/upload_avatar`, {
        method: 'POST',
        body: formData
    });

    if (response.ok) {
        console.log('Avatar uploaded successfully');
    } else {
        console.error('Error uploading avatar');
    }
};

// Example usage:
const fileInput = document.querySelector('input[type="file"]');
fileInput.addEventListener('change', (event) => {
    const file = event.target.files[0];
    uploadAvatar(1, file);  // Replace 1 with the actual user ID
});
```

### Real-time Notifications

To implement real-time notifications, you can use WebSockets. Here’s a basic example using Flask-SocketIO:

#### Install Flask-SocketIO

```bash
pip install flask-socketio
```

#### Update Your Flask App

Add the following to your Flask app:

```python
from flask_socketio import SocketIO, emit

socketio = SocketIO(app)

@app.route('/mention', methods=['POST'])
@login_required
def mention_user():
    data = request.json
    mentioned_user_id = data['mentioned_user_id']
    post_content = data['post_content']
    mentioned_user = User.query.get_or_404(mentioned_user_id)
    notification_message = f'{current_user.username} mentioned you in a post: {post_content[:50]}...'
    new_notification = Notification(user=mentioned_user, message=notification_message)
    db.session.add(new_notification)
    db.session.commit()
    emit('notification', {'message': notification_message}, to=mentioned_user_id)
    return jsonify({'status': 'success'})

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        join_room(current_user.id)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        leave_room(current_user.id)
```

#### Update Your Frontend

Add SocketIO to your JavaScript:

```html
<script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>
<script>
    const socket = io();

    socket.on('connect', () => {
        console.log('Connected to server');
    });

    socket.on('notification', (data) => {
        console.log('Notification received:', data.message);
        // Display notification to the user
    });

    socket.on('disconnect', () => {
        console.log('Disconnected from server');
    });
</script>
```

To run the application with SocketIO, update the `flask run` command to:

```bash
socketio.run(app)
```

With these detailed instructions and examples, you should be able to set up, run, and extend the Flask forum application effectively. Feel free to modify and enhance the application as needed.
