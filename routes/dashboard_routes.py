from flask import Blueprint, render_template, redirect, url_for, jsonify
from auth.authentication import login_required
from database.models import get_dashboard_stats, get_recent_logs

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
def root():
    return redirect(url_for('dashboard.dashboard_view'))

@dashboard_bp.route('/dashboard')
@login_required
def dashboard_view():
    stats = get_dashboard_stats()
    recent_logs = get_recent_logs(limit=15)
    return render_template('dashboard.html', stats=stats, recent_logs=recent_logs)

@dashboard_bp.route('/api/dashboard/stats')
@login_required
def dashboard_stats_api():
    stats = get_dashboard_stats()
    return jsonify({'success': True, 'stats': stats})

@dashboard_bp.route('/api/dashboard/recent-logs')
@login_required
def dashboard_logs_api():
    logs = get_recent_logs(limit=25)
    return jsonify({'success': True, 'logs': logs})
