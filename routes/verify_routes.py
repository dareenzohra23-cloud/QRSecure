from flask import Blueprint, render_template, request, jsonify
from auth.authentication import login_required
from qr.validator import verify_qr_payload

verify_bp = Blueprint('verify', __name__)

@verify_bp.route('/verify')
@login_required
def verify_view():
    return render_template('verify.html')

@verify_bp.route('/api/verify', methods=['POST'])
@login_required
def api_verify():
    data = request.get_json() or {}
    raw_payload = data.get('payload')
    method = data.get('method', 'Camera')
    public_key_override = data.get('public_key_override')

    if not raw_payload:
        return jsonify({'success': False, 'error': 'No QR payload provided for verification'}), 400

    result = verify_qr_payload(
        raw_payload=raw_payload,
        verification_method=method,
        public_key_pem_override=public_key_override
    )
    return jsonify(result)
