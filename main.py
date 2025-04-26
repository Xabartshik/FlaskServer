from flask import Flask, request, jsonify
from flask_socketio import SocketIO, join_room, leave_room, emit
import jwt
import bcrypt
import uuid
import re

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
users_db = {}
SECRET_KEY = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'  # Замените на ваш безопасный ключ


def verify_token(auth_header=None):
    if auth_header is None:
        auth_header = request.headers.get('Authorization')
    print(f"Verifying token with header: {auth_header}")
    if not auth_header or not auth_header.startswith('Bearer '):
        print("No Authorization header or wrong format")
        return None
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        print(f"Decoded token payload: {payload}")
        return payload['user_id']
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {e}")
        return None


@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")


@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")
    for email, user in users_db.items():
        if user.get('sid') == request.sid:
            user['status'] = 'offline'
            user['sid'] = None
            print(f"User {user['user_id']} set to offline")
            emit('user_status', {'user_id': user['user_id'], 'status': 'offline'}, broadcast=True)


@socketio.on('register')
def handle_register(data):
    user_id = data.get('user_id')
    token = data.get('token')
    print(f"Registering socket for user {user_id} with token {token}")
    if user_id and token:
        auth_header = f"Bearer {token}"
        if verify_token(auth_header) == user_id:
            for email, user in users_db.items():
                if user['user_id'] == user_id:
                    user['sid'] = request.sid
                    user['status'] = 'online'
                    join_room(user_id)
                    print(f"User {user_id} registered with SID {request.sid}, joined room {user_id}")
                    emit('user_status', {'user_id': user_id, 'status': 'online'}, broadcast=True)
                    break
        else:
            print(f"Invalid token for user {user_id}")
            emit('error', {'message': 'Invalid token'})
    else:
        print("Invalid register data")
        emit('error', {'message': 'Invalid register data'})


@socketio.on('message')
def handle_message(data):
    print(f"Received Socket.IO message: {data}")
    from_id = data.get('from')
    to_id = data.get('to')
    token = data.get('token')
    if from_id and to_id and token:
        auth_header = f"Bearer {token}"
        if verify_token(auth_header) == from_id:
            for email, user in users_db.items():
                if user['user_id'] == to_id:
                    print(f"Forwarding message {data['type']} from {from_id} to {to_id} in room {to_id}")
                    emit('message', data, room=to_id)
                    break
            else:
                print(f"User {to_id} not found in users_db")
                emit('error', {'message': 'Recipient not found'}, room=from_id)
        else:
            print(f"Invalid token for user {from_id}")
            emit('error', {'message': 'Invalid token'}, room=from_id)
    else:
        print("Invalid message format or missing fields")
        emit('error', {'message': 'Invalid message format'}, room=from_id)


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    public_key = data.get('public_key')
    identifier = data.get('identifier')

    if not all([username, email, password, public_key, identifier]) or not re.match(r'^[a-z0-9_]+$', identifier):
        print(f"Invalid input: {data}")
        return jsonify({'error': 'Invalid input'}), 400

    if email in users_db or any(u['identifier'] == identifier for u in users_db.values()):
        print(f"User or identifier exists: {email}, {identifier}")
        return jsonify({'error': 'User or identifier already exists'}), 400

    user_id = str(uuid.uuid4())
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users_db[email] = {
        'user_id': user_id,
        'username': username,
        'email': email,
        'password': hashed_password,
        'public_key': public_key,
        'identifier': identifier,
        'status': 'offline',
        'sid': None,
    }
    token = jwt.encode({'user_id': user_id}, SECRET_KEY, algorithm='HS256')
    print(f"Generated token for {email}: {token}")
    return jsonify({
        'user_id': user_id,
        'username': username,
        'email': email,
        'status': 'offline',
        'public_key': public_key,
        'identifier': identifier,
        'token': token,
    }), 200


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = users_db.get(email)
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        token = jwt.encode({'user_id': user['user_id']}, SECRET_KEY, algorithm='HS256')
        print(f"Generated token for {email}: {token}")
        return jsonify({
            'user_id': user['user_id'],
            'username': user['username'],
            'email': user['email'],
            'status': user['status'],
            'public_key': user['public_key'],
            'identifier': user['identifier'],
            'token': token,
        }), 200
    print(f"Invalid credentials for {email}")
    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/refresh', methods=['POST'])
def refresh_token():
    user_id_from_token = verify_token()
    if user_id_from_token is None:
        print("Refresh token failed: Unauthorized")
        return jsonify({'error': 'Unauthorized'}), 401
    new_token = jwt.encode({'user_id': user_id_from_token}, SECRET_KEY, algorithm='HS256')
    print(f"Refreshed token for user {user_id_from_token}: {new_token}")
    return jsonify({'token': new_token}), 200


@app.route('/user/<user_id>', methods=['GET'])
def get_user(user_id):
    user_id_from_token = verify_token()
    if user_id_from_token is None:
        return jsonify({'error': 'Unauthorized'}), 401
    user = next((u for u in users_db.values() if u['user_id'] == user_id), None)
    if user:
        return jsonify({
            'user_id': user['user_id'],
            'username': user['username'],
            'email': user['email'],
            'status': user['status'],
            'public_key': user['public_key'],
            'identifier': user['identifier'],
        }), 200
    return jsonify({'error': 'User not found'}), 404


@app.route('/user_by_identifier', methods=['GET'])
def get_user_by_identifier():
    user_id_from_token = verify_token()
    if user_id_from_token is None:
        return jsonify({'error': 'Unauthorized'}), 401
    identifier = request.args.get('identifier')
    user = next((u for u in users_db.values() if u['identifier'] == identifier), None)
    if user:
        return jsonify({
            'user_id': user['user_id'],
            'username': user['username'],
            'email': user['email'],
            'status': user['status'],
            'public_key': user['public_key'],
            'identifier': user['identifier'],
        }), 200
    return jsonify({'error': 'User not found'}), 404


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', allow_unsafe_werkzeug=True, port=5000)
