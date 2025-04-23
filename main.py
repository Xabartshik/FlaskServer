from flask import Flask, request
from flask_socketio import SocketIO, emit
import ssl

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")  # Ограничьте в продакшене

# Хранилище подключённых устройств
peers = {}

@socketio.on('connect')
def handle_connect():
    print(f"Устройство подключено: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    for peer_id, sid in list(peers.items()):
        if sid == request.sid:
            del peers[peer_id]
            print(f"Устройство отключено: {peer_id}")
            break

@socketio.on('message')
def handle_message(data):
    print(f"Получено: {data}")
    message_type = data.get('type')
    from_id = data.get('from')
    to_id = data.get('to')

    if message_type == 'register':
        peer_id = data.get('id')
        peers[peer_id] = request.sid
        print(f"Зарегистрировано: {peer_id}")
    elif message_type in ['offer', 'answer', 'candidate']:
        if to_id in peers:
            emit('message', data, room=peers[to_id])
        else:
            print(f"Целевое устройство {to_id} не найдено")

if __name__ == '__main__':
    # Для локальных тестов без HTTPS
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)