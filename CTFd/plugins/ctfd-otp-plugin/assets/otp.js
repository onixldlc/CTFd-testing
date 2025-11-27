/**
 * CTFd OTP Plugin - Client-side functionality
 */

(function() {
    'use strict';

    /**
     * Initialize OTP input field behavior
     */
    function initOTPInput() {
        const otpInputs = document.querySelectorAll('input[name="token"]');
        
        otpInputs.forEach(function(input) {
            // Only allow numeric input
            input.addEventListener('input', function(e) {
                this.value = this.value.replace(/[^0-9]/g, '');
            });

            // Auto-focus on load
            if (input.getAttribute('autofocus') !== null) {
                input.focus();
            }
        });
    }

    // QR code generation is handled server-side

    /**
     * Copy secret to clipboard
     */
    function initCopySecret() {
        const copyButtons = document.querySelectorAll('.copy-secret');
        
        copyButtons.forEach(function(button) {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                const secret = this.dataset.secret;
                
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(secret).then(function() {
                        showToast('Secret copied to clipboard!', 'success');
                    }).catch(function(err) {
                        console.error('Failed to copy:', err);
                        fallbackCopyToClipboard(secret);
                    });
                } else {
                    fallbackCopyToClipboard(secret);
                }
            });
        });
    }

    /**
     * Fallback clipboard copy for older browsers
     */
    function fallbackCopyToClipboard(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-9999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();

        try {
            document.execCommand('copy');
            showToast('Secret copied to clipboard!', 'success');
        } catch (err) {
            console.error('Fallback copy failed:', err);
            showToast('Failed to copy secret', 'danger');
        }

        document.body.removeChild(textArea);
    }

    /**
     * Show toast notification
     */
    function showToast(message, type) {
        // Check if Bootstrap toast is available
        if (typeof bootstrap !== 'undefined' && bootstrap.Toast) {
            const toastHtml = `
                <div class="toast align-items-center text-white bg-${type}" role="alert">
                    <div class="d-flex">
                        <div class="toast-body">${message}</div>
                        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                    </div>
                </div>
            `;
            
            let toastContainer = document.querySelector('.toast-container');
            if (!toastContainer) {
                toastContainer = document.createElement('div');
                toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
                document.body.appendChild(toastContainer);
            }
            
            toastContainer.insertAdjacentHTML('beforeend', toastHtml);
            const toastEl = toastContainer.lastElementChild;
            const toast = new bootstrap.Toast(toastEl);
            toast.show();
            
            toastEl.addEventListener('hidden.bs.toast', function() {
                toastEl.remove();
            });
        } else {
            // Fallback to alert
            alert(message);
        }
    }

    /**
     * Initialize all OTP functionality
     */
    function init() {
        initOTPInput();
        initCopySecret();
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Expose some functions globally if needed
    window.CTFdOTP = {
        showToast: showToast
    };
})();
