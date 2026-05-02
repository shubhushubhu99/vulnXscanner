import os
import secrets

from flask import Flask

from extensions import socketio
from routes.api import api_bp
from routes.scanners import scanners_bp
from routes.views import views_bp
from socket_events import register_socket_events


app = Flask(
    __name__,
    template_folder='../templates',
    static_folder='../static',
)

socketio.init_app(app)

# Prefer env-provided secret key; generate a per-process fallback if missing
app.config['SECRET_KEY'] = (
    os.environ.get('FLASK_SECRET_KEY')
    or os.environ.get('SECRET_KEY')
    or secrets.token_hex(32)
)


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.socket.io; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' wss: ws:; "
        "font-src 'self';"
    )
    response.headers.remove('Server')
    return response


register_socket_events()

app.register_blueprint(views_bp)
app.register_blueprint(api_bp)
app.register_blueprint(scanners_bp)


if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 5000))
    HOST = os.environ.get('HOST', '127.0.0.1')
    socketio.run(app, host=HOST, port=PORT, debug=True, allow_unsafe_werkzeug=True)
