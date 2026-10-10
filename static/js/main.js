// QR-Secure Core Client Utilities
function copyToClipboard(text, btnElement) {
  navigator.clipboard.writeText(text).then(() => {
    if (btnElement) {
      const originalText = btnElement.innerHTML;
      btnElement.innerHTML = '<i class="bi bi-check2"></i> Copied!';
      btnElement.classList.add('btn-success');
      setTimeout(() => {
        btnElement.innerHTML = originalText;
        btnElement.classList.remove('btn-success');
      }, 2000);
    }
  }).catch(err => {
    console.error('Failed to copy: ', err);
  });
}

function formatDate(isoStr) {
  if (!isoStr) return '-';
  try {
    const d = new Date(isoStr);
    return d.toLocaleString();
  } catch (e) {
    return isoStr;
  }
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  
  const toastEl = document.createElement('div');
  toastEl.className = `toast align-items-center text-bg-${type} border-0 mb-2`;
  toastEl.setAttribute('role', 'alert');
  toastEl.setAttribute('aria-live', 'assertive');
  toastEl.setAttribute('aria-atomic', 'true');
  
  toastEl.innerHTML = `
    <div class="d-flex">
      <div class="toast-body">${message}</div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
    </div>
  `;
  container.appendChild(toastEl);
  const bsToast = new bootstrap.Toast(toastEl, { delay: 4000 });
  bsToast.show();
  toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
}
