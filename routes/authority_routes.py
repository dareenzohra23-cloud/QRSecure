from flask import Blueprint, render_template, jsonify, flash, redirect, url_for
from auth.authentication import login_required, role_required
from crypto.key_manager import KeyManager
from database.models import get_active_authority, get_authority_history, rotate_authority_in_db

authority_bp = Blueprint('authority', __name__)

@authority_bp.route('/authority')
@login_required
@role_required('ADMIN')
def authority_view():
    authority = get_active_authority()
    history = get_authority_history()
    return render_template('authority.html', authority=authority, history=history)

@authority_bp.route('/api/authority/public-key')
@login_required
def get_public_key():
    authority = get_active_authority()
    if not authority:
        return jsonify({'success': False, 'error': 'Authority not found'}), 404
        
    return jsonify({
        'success': True,
        'authority_name': authority['authority_name'],
        'certificate_id': authority['certificate_id'],
        'fingerprint': authority['fingerprint'],
        'key_algorithm': authority['key_algorithm'],
        'public_key_pem': authority['public_key'],
        'valid_from': authority['valid_from'],
        'valid_until': authority['valid_until'],
        'status': authority['status']
    })

@authority_bp.route('/api/authority/rotate-keys', methods=['POST'])
@login_required
@role_required('ADMIN')
def rotate_keys():
    try:
        km = KeyManager()
        _, new_pub_pem, new_fingerprint = km.rotate_keys()
        new_record = rotate_authority_in_db(new_pub_pem, new_fingerprint)
        return jsonify({
            'success': True,
            'message': 'RSA keypair rotated successfully. New certificate issued.',
            'new_certificate': new_record
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f'Key rotation failed: {str(e)}'}), 500
