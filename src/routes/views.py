from flask import Blueprint, render_template, request
from app import latest_results   # ⚠️ temporary (we’ll fix later)
from app import load_history, save_message

views_bp = Blueprint('views', __name__)

@views_bp.route('/', methods=['GET'])
def landing():
    return render_template('landing_v2.html')

@views_bp.route('/dashboard', methods=['GET'])
def dashboard():
    return render_template(
        'dashboard.html',
        results=latest_results['results'],
        original_target=latest_results['target'],
        deep_scan=latest_results['deep_scan'],
        active_page='dashboard'
    )

@views_bp.route('/history', methods=['GET'])
def history_page():
    history = load_history()
    print(f"Loading history page. Found {len(history)} items.")
    return render_template(
        'history.html',
        history=history,
        active_page='history'
    )

@views_bp.route('/settings', methods=['GET'])
def settings_page():
    """Settings page for scanner configuration"""
    return render_template('settings.html', active_page='settings')

@views_bp.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')

        if not all([name, email, subject, message]):
            return render_template('contact.html', error="All fields are required.", active_page='contact')

        message_data = {
            'name': name,
            'email': email,
            'subject': subject,
            'message': message
        }

        if save_message(message_data):
            return render_template('contact.html', success="Your message has been sent successfully!", active_page='contact')
        else:
            return render_template('contact.html', error="There was an error sending your message. Please try again later.", active_page='contact')

    return render_template('contact.html', active_page='contact')
