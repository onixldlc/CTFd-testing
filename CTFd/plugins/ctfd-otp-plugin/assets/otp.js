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

            // Submit form when 6 digits are entered
            input.addEventListener('input', function(e) {
                if (this.value.length === 6) {
                    const form = this.closest('form');
                    if (form && form.dataset.autoSubmit !== 'false') {
                        // Small delay to allow user to see the complete input
                        setTimeout(function() {
                            form.submit();
                        }, 200);
                    }
                }
            });
        });
    }

    /**
     * Initialize QR code generation
     */
    function initQRCode() {
        const qrcodeContainer = document.getElementById('qrcode');
        const provisioningUri = qrcodeContainer ? qrcodeContainer.dataset.uri : null;

        if (qrcodeContainer && provisioningUri && typeof QRCode !== 'undefined') {
            QRCode.toCanvas(document.createElement('canvas'), provisioningUri, {
                width: 200,
                margin: 2,
                color: {
                    dark: '#000000',
                    light: '#ffffff'
                }
            }, function(error, canvas) {
                if (error) {
                    console.error('QR Code generation error:', error);
                    qrcodeContainer.innerHTML = '<p class="text-danger">Failed to generate QR code</p>';
                } else {
                    qrcodeContainer.innerHTML = '';
                    qrcodeContainer.appendChild(canvas);
                }
            });
        }
    }

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
     * Verify OTP via AJAX
     */
    function verifyOTPAjax(token, callback) {
        const formData = new FormData();
        formData.append('token', token);
        formData.append('nonce', window.init ? window.init.csrfNonce : '');

        fetch('/otp/check', {
            method: 'POST',
            body: formData,
            credentials: 'same-origin'
        })
        .then(function(response) {
            return response.json();
        })
        .then(function(data) {
            callback(null, data);
        })
        .catch(function(error) {
            callback(error, null);
        });
    }

    /**
     * Toggle setting visibility based on master switch
     */
    function initSettingsToggle() {
        const masterSwitch = document.getElementById('otp_enabled');
        const dependentSettings = document.querySelectorAll('.otp-dependent-setting');
        
        if (masterSwitch && dependentSettings.length > 0) {
            function updateDependentSettings() {
                dependentSettings.forEach(function(setting) {
                    setting.disabled = !masterSwitch.checked;
                    setting.closest('.form-check').classList.toggle('text-muted', !masterSwitch.checked);
                });
            }
            
            masterSwitch.addEventListener('change', updateDependentSettings);
            updateDependentSettings();
        }
    }

    /**
     * Initialize all OTP functionality
     */
    function init() {
        initOTPInput();
        initQRCode();
        initCopySecret();
        initSettingsToggle();
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Expose some functions globally if needed
    window.CTFdOTP = {
        verifyOTPAjax: verifyOTPAjax,
        showToast: showToast
    };
})();
