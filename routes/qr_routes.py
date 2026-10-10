from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, session
from datetime import datetime, timezone, timedelta
from auth.authentication import login_required, role_required
from qr.generator import generate_secure_qr
from database.models import (
    get_all_qr_codes, 
    get_qr_code, 
    revoke_qr_code, 
    get_all_revocations
)

qr_bp = Blueprint('qr', __name__)

@qr_bp.route('/generate')
@login_required
@role_required('ADMIN')
def generate_view():
    return render_template('generate.html')

@qr_bp.route('/api/qr/generate', methods=['POST'])
@login_required
@role_required('ADMIN')
def api_generate():
    data = request.get_json() or {}
    qr_type = data.get('type', 'STUDENT_ID').upper()
    fields_data = data.get('data', {})
    expires_at_iso = data.get('expires_at')
    is_one_time = bool(data.get('is_one_time', False))
    simulate_expired = bool(data.get('simulate_expired', False))

    if not fields_data:
        return jsonify({'success': False, 'error': 'No data payload provided'}), 400

    # If simulate_expired is requested, set expiry to 2 days ago
    if simulate_expired:
        now = datetime.now(timezone.utc)
        expires_at_iso = (now - timedelta(days=2)).strftime('%Y-%m-%dT%H:%M:%SZ')

    try:
        result = generate_secure_qr(
            qr_type=qr_type,
            data_dict=fields_data,
            expires_at_iso=expires_at_iso,
            is_one_time=is_one_time,
            save_to_db=True
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': f"Generation failed: {str(e)}"}), 500

@qr_bp.route('/revoked')
@login_required
@role_required('ADMIN')
def revoked_view():
    all_qrs = get_all_qr_codes()
    revocations = get_all_revocations()
    return render_template('revoked.html', qrs=all_qrs, revocations=revocations)

@qr_bp.route('/api/qr/revoke', methods=['POST'])
@login_required
@role_required('ADMIN')
def api_revoke():
    data = request.get_json() or {}
    qr_id = data.get('qr_id', '').strip()
    reason = data.get('reason', 'Revoked by administrator').strip()
    revoked_by = session.get('username', 'admin')

    if not qr_id:
        return jsonify({'success': False, 'error': 'QR ID is required'}), 400

    qr_item = get_qr_code(qr_id)
    if not qr_item:
        return jsonify({'success': False, 'error': f'QR code {qr_id} not found'}), 404

    success = revoke_qr_code(qr_id, reason, revoked_by)
    if success:
        return jsonify({
            'success': True,
            'message': f"QR code {qr_id} successfully revoked",
            'qr_id': qr_id,
            'reason': reason
        })
    else:
        return jsonify({'success': False, 'error': "Failed to revoke QR code"}), 500

@qr_bp.route('/api/qr/list')
@login_required
def api_list():
    qrs = get_all_qr_codes()
    return jsonify({'success': True, 'qrs': qrs})

@qr_bp.route('/api/qr/<qr_id>')
@login_required
def api_get_qr(qr_id):
    qr_item = get_qr_code(qr_id)
    if not qr_item:
        return jsonify({'success': False, 'error': 'QR code not found'}), 404
    return jsonify({'success': True, 'qr': qr_item})
