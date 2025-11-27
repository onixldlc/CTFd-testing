"""
CTFd OTP Plugin

This plugin adds two-factor authentication (OTP/TOTP) support to CTFd.
It provides:
- OTP setup page for users/admins to configure their authenticator apps
- OTP verification page for login and sensitive actions
- Admin settings page to configure OTP requirements for various admin actions
- Backup codes for account recovery
"""

import base64
import hashlib
import io
import json
import secrets
import time

import pyotp
import qrcode
from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from CTFd.cache import clear_config
from CTFd.models import Users, db
from CTFd.plugins import (
    register_admin_plugin_menu_bar,
    register_plugin_assets_directory,
)
from CTFd.plugins.migrations import upgrade
from CTFd.utils import get_config, set_config
from CTFd.utils.decorators import admins_only, authed_only
from CTFd.utils.security.auth import login_user
from CTFd.utils.user import get_current_user, is_admin

# Rate limiting constants
BACKUP_CODE_RATE_LIMIT_SECONDS = 300  # 5 minutes
BACKUP_CODE_MAX_ATTEMPTS = 5  # Max attempts before lockout


class OTPSecrets(db.Model):
    """Model to store OTP secrets for users."""

    __tablename__ = "otp_secrets"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), unique=True
    )
    secret = db.Column(db.String(32), nullable=False)
    enabled = db.Column(db.Boolean, default=False)
    backup_codes = db.Column(db.Text, nullable=True)
    backup_code_attempts = db.Column(db.Integer, default=0)
    backup_code_lockout_until = db.Column(db.Float, nullable=True)

    user = db.relationship("Users", foreign_keys=[user_id], lazy="select")

    def __init__(self, *args, **kwargs):
        super(OTPSecrets, self).__init__(**kwargs)


# Create Blueprint for OTP routes
otp_bp = Blueprint(
    "otp",
    __name__,
    template_folder="templates",
    static_folder="assets",
    url_prefix="/otp",
)


def generate_otp_secret():
    """Generate a new OTP secret."""
    return pyotp.random_base32()


def verify_otp(secret, token):
    """Verify an OTP token against a secret."""
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=1)


def get_provisioning_uri(secret, email, issuer="CTFd"):
    """Generate a provisioning URI for QR codes."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)


def generate_qr_code_base64(data):
    """Generate a QR code and return it as a base64-encoded PNG image."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{img_base64}"


def generate_backup_codes(count=10):
    """Generate a set of backup codes."""
    codes = []
    for _ in range(count):
        # Generate an 8-character alphanumeric code
        code = secrets.token_hex(4).upper()
        codes.append(code)
    return codes


def hash_backup_code(code):
    """Hash a backup code for secure storage."""
    return hashlib.sha256(code.encode()).hexdigest()


def store_backup_codes(otp_record, codes):
    """Store hashed backup codes in the database."""
    hashed_codes = [hash_backup_code(code) for code in codes]
    otp_record.backup_codes = json.dumps(hashed_codes)
    db.session.commit()


def verify_backup_code(otp_record, code):
    """
    Verify a backup code against stored hashed codes.
    Returns True if valid and removes the used code.
    """
    if not otp_record.backup_codes:
        return False

    try:
        stored_codes = json.loads(otp_record.backup_codes)
    except (json.JSONDecodeError, TypeError):
        return False

    hashed_input = hash_backup_code(code.upper().strip())

    if hashed_input in stored_codes:
        # Remove the used code
        stored_codes.remove(hashed_input)
        otp_record.backup_codes = json.dumps(stored_codes)
        db.session.commit()
        return True

    return False


def check_backup_code_rate_limit(otp_record):
    """
    Check if the user is rate-limited for backup code attempts.
    Returns (is_allowed, time_remaining) tuple.
    """
    current_time = time.time()

    # Check if user is locked out
    if otp_record.backup_code_lockout_until:
        if current_time < otp_record.backup_code_lockout_until:
            time_remaining = int(otp_record.backup_code_lockout_until - current_time)
            return False, time_remaining
        else:
            # Lockout expired, reset attempts
            otp_record.backup_code_attempts = 0
            otp_record.backup_code_lockout_until = None
            db.session.commit()

    return True, 0


def record_backup_code_attempt(otp_record, success):
    """Record a backup code attempt and apply rate limiting if needed."""
    if success:
        # Reset attempts on success
        otp_record.backup_code_attempts = 0
        otp_record.backup_code_lockout_until = None
    else:
        # Increment failed attempts
        otp_record.backup_code_attempts = (otp_record.backup_code_attempts or 0) + 1

        # Apply lockout if max attempts exceeded
        if otp_record.backup_code_attempts >= BACKUP_CODE_MAX_ATTEMPTS:
            otp_record.backup_code_lockout_until = (
                time.time() + BACKUP_CODE_RATE_LIMIT_SECONDS
            )

    db.session.commit()


def get_remaining_backup_codes_count(otp_record):
    """Get the count of remaining backup codes."""
    if not otp_record.backup_codes:
        return 0
    try:
        codes = json.loads(otp_record.backup_codes)
        return len(codes)
    except (json.JSONDecodeError, TypeError):
        return 0


def is_otp_enabled_for_user(user_id):
    """Check if OTP is enabled for a specific user."""
    otp_record = OTPSecrets.query.filter_by(user_id=user_id).first()
    return otp_record and otp_record.enabled


def get_otp_settings():
    """Get all OTP-related settings."""
    return {
        "otp_enabled": get_config("otp_enabled"),
        "otp_required_for_admins": get_config("otp_required_for_admins"),
        "otp_required_for_clear_db": get_config("otp_required_for_clear_db"),
        "otp_required_for_reset": get_config("otp_required_for_reset"),
        "otp_required_for_export": get_config("otp_required_for_export"),
        "otp_required_for_import": get_config("otp_required_for_import"),
        "otp_required_for_user_delete": get_config("otp_required_for_user_delete"),
        "otp_required_for_config_change": get_config("otp_required_for_config_change"),
    }


# ==================== Routes ====================


@otp_bp.route("/setup", methods=["GET", "POST"])
@authed_only
def setup():
    """OTP setup page for users to configure their authenticator app."""
    user = get_current_user()

    if request.method == "GET":
        # Check if user already has OTP configured
        otp_record = OTPSecrets.query.filter_by(user_id=user.id).first()

        if otp_record and otp_record.enabled:
            # Already configured, show status with remaining backup codes count
            remaining_codes = get_remaining_backup_codes_count(otp_record)
            return render_template(
                "otp/setup.html",
                otp_configured=True,
                user=user,
                remaining_backup_codes=remaining_codes,
            )

        # Generate new secret for setup
        if otp_record:
            secret = otp_record.secret
        else:
            secret = generate_otp_secret()
            # Store the secret temporarily (not enabled yet)
            otp_record = OTPSecrets(user_id=user.id, secret=secret, enabled=False)
            db.session.add(otp_record)
            db.session.commit()

        # Generate provisioning URI for QR code
        provisioning_uri = get_provisioning_uri(
            secret, user.email, issuer=get_config("ctf_name") or "CTFd"
        )

        # Generate QR code as base64 image (server-side)
        qr_code_image = generate_qr_code_base64(provisioning_uri)

        return render_template(
            "otp/setup.html",
            otp_configured=False,
            secret=secret,
            provisioning_uri=provisioning_uri,
            qr_code_image=qr_code_image,
            user=user,
        )

    elif request.method == "POST":
        action = request.form.get("action")

        if action == "enable":
            # Verify the OTP token provided by user
            token = request.form.get("token", "").strip()

            # Server-side validation of token format
            if not token or len(token) != 6 or not token.isdigit():
                flash("Invalid OTP format. Please enter a 6-digit code.", "danger")
                return redirect(url_for("otp.setup"))

            otp_record = OTPSecrets.query.filter_by(user_id=user.id).first()

            if not otp_record:
                flash("OTP setup not initialized. Please try again.", "danger")
                return redirect(url_for("otp.setup"))

            if verify_otp(otp_record.secret, token):
                # Generate backup codes
                backup_codes = generate_backup_codes(10)
                store_backup_codes(otp_record, backup_codes)

                otp_record.enabled = True
                db.session.commit()

                # Show backup codes to user (only shown once)
                return render_template(
                    "otp/setup.html",
                    otp_configured=True,
                    otp_just_enabled=True,
                    backup_codes=backup_codes,
                    user=user,
                )
            else:
                flash("Invalid OTP token. Please try again.", "danger")
                provisioning_uri = get_provisioning_uri(
                    otp_record.secret,
                    user.email,
                    issuer=get_config("ctf_name") or "CTFd",
                )
                qr_code_image = generate_qr_code_base64(provisioning_uri)
                return render_template(
                    "otp/setup.html",
                    otp_configured=False,
                    secret=otp_record.secret,
                    provisioning_uri=provisioning_uri,
                    qr_code_image=qr_code_image,
                    user=user,
                    error="Invalid OTP token",
                )

        elif action == "disable":
            # Verify current OTP before disabling
            token = request.form.get("token", "").strip()

            # Server-side validation of token format
            if not token or len(token) != 6 or not token.isdigit():
                flash("Invalid OTP format. Please enter a 6-digit code.", "danger")
                return redirect(url_for("otp.setup"))

            otp_record = OTPSecrets.query.filter_by(user_id=user.id).first()

            if otp_record and verify_otp(otp_record.secret, token):
                db.session.delete(otp_record)
                db.session.commit()
                flash(
                    "OTP has been disabled. You can set it up again anytime.",
                    "info",
                )
                # Render the disabled confirmation to prevent auto-regeneration
                return render_template(
                    "otp/setup.html",
                    otp_configured=False,
                    otp_just_disabled=True,
                    user=user,
                )
            else:
                flash("Invalid OTP token. Cannot disable OTP.", "danger")
                return redirect(url_for("otp.setup"))

        elif action == "regenerate":
            # Verify current OTP before regenerating
            token = request.form.get("token", "").strip()
            otp_record = OTPSecrets.query.filter_by(user_id=user.id).first()

            if (
                otp_record
                and otp_record.enabled
                and verify_otp(otp_record.secret, token)
            ):
                new_secret = generate_otp_secret()
                otp_record.secret = new_secret
                otp_record.enabled = False
                otp_record.backup_codes = None  # Clear backup codes
                db.session.commit()
                flash(
                    "New OTP secret generated. Please set up your authenticator app again.",
                    "info",
                )
            elif not otp_record or not otp_record.enabled:
                # Not enabled yet, just regenerate
                if otp_record:
                    otp_record.secret = generate_otp_secret()
                else:
                    otp_record = OTPSecrets(
                        user_id=user.id, secret=generate_otp_secret(), enabled=False
                    )
                    db.session.add(otp_record)
                db.session.commit()
                flash("New OTP secret generated.", "info")
            else:
                flash("Invalid OTP token. Cannot regenerate secret.", "danger")

            return redirect(url_for("otp.setup"))

        elif action == "regenerate_backup_codes":
            # Verify current OTP before regenerating backup codes
            token = request.form.get("token", "").strip()

            # Server-side validation of token format
            if not token or len(token) != 6 or not token.isdigit():
                flash("Invalid OTP format. Please enter a 6-digit code.", "danger")
                return redirect(url_for("otp.setup"))

            otp_record = OTPSecrets.query.filter_by(user_id=user.id).first()

            if (
                otp_record
                and otp_record.enabled
                and verify_otp(otp_record.secret, token)
            ):
                # Generate new backup codes
                backup_codes = generate_backup_codes(10)
                store_backup_codes(otp_record, backup_codes)

                # Reset rate limiting
                otp_record.backup_code_attempts = 0
                otp_record.backup_code_lockout_until = None
                db.session.commit()

                # Show new backup codes to user
                return render_template(
                    "otp/setup.html",
                    otp_configured=True,
                    otp_just_enabled=True,
                    backup_codes=backup_codes,
                    user=user,
                    backup_codes_regenerated=True,
                )
            else:
                flash("Invalid OTP token. Cannot regenerate backup codes.", "danger")
                return redirect(url_for("otp.setup"))

    return redirect(url_for("otp.setup"))


@otp_bp.route("/verify", methods=["GET", "POST"])
def verify():
    """OTP verification page."""
    # Check if user needs to verify OTP
    pending_user_id = session.get("otp_pending_user_id")
    next_url = session.get("otp_next_url", url_for("challenges.listing"))
    action = session.get("otp_action")

    if not pending_user_id and not action:
        return redirect(url_for("auth.login"))

    if request.method == "GET":
        return render_template(
            "otp/verify.html",
            action=action,
            next_url=next_url,
        )

    elif request.method == "POST":
        token = request.form.get("token", "").strip()
        use_backup_code = request.form.get("use_backup_code") == "1"

        # Determine user_id for rate limiting check
        check_user_id = pending_user_id if pending_user_id else None
        if not check_user_id and action:
            current_user = get_current_user()
            if current_user:
                check_user_id = current_user.id

        if use_backup_code:
            # Backup code verification
            backup_code = request.form.get("backup_code", "").strip()

            if not backup_code:
                flash("Please enter a backup code.", "danger")
                return render_template(
                    "otp/verify.html",
                    action=action,
                    next_url=next_url,
                    show_backup_code=True,
                )

            # Get the OTP record for rate limiting
            if check_user_id:
                otp_record = OTPSecrets.query.filter_by(user_id=check_user_id).first()

                if otp_record:
                    # Check rate limiting
                    is_allowed, time_remaining = check_backup_code_rate_limit(
                        otp_record
                    )
                    if not is_allowed:
                        flash(
                            f"Too many failed attempts. Please wait {time_remaining // 60} minutes and {time_remaining % 60} seconds.",
                            "danger",
                        )
                        return render_template(
                            "otp/verify.html",
                            action=action,
                            next_url=next_url,
                            show_backup_code=True,
                            rate_limited=True,
                            rate_limit_remaining=time_remaining,
                        )

                    # Verify backup code
                    if verify_backup_code(otp_record, backup_code):
                        record_backup_code_attempt(otp_record, success=True)

                        if pending_user_id:
                            # Complete login
                            user = Users.query.filter_by(id=pending_user_id).first()
                            if user:
                                session.pop("otp_pending_user_id", None)
                                session.pop("otp_next_url", None)
                                session.pop("otp_action", None)
                                login_user(user)
                                flash(
                                    "Login successful using backup code! Consider regenerating backup codes.",
                                    "success",
                                )
                                return redirect(next_url)
                        elif action:
                            # Admin action verification
                            session["otp_verified_action"] = action
                            session["otp_verified_timestamp"] = time.time()
                            session.pop("otp_action", None)
                            flash(
                                "Backup code verified. You may proceed with the action.",
                                "success",
                            )
                            return redirect(next_url)
                    else:
                        record_backup_code_attempt(otp_record, success=False)
                        flash("Invalid backup code. Please try again.", "danger")
                        return render_template(
                            "otp/verify.html",
                            action=action,
                            next_url=next_url,
                            show_backup_code=True,
                        )

            flash("Could not verify backup code.", "danger")
            return render_template(
                "otp/verify.html",
                action=action,
                next_url=next_url,
                show_backup_code=True,
            )

        else:
            # Regular OTP verification
            # Server-side validation of token format
            if not token or len(token) != 6 or not token.isdigit():
                flash("Invalid OTP format. Please enter a 6-digit code.", "danger")
                return render_template(
                    "otp/verify.html", action=action, next_url=next_url
                )

            if pending_user_id:
                # Login OTP verification
                otp_record = OTPSecrets.query.filter_by(user_id=pending_user_id).first()

                if otp_record and verify_otp(otp_record.secret, token):
                    # OTP verified, complete login
                    user = Users.query.filter_by(id=pending_user_id).first()
                    if user:
                        session.pop("otp_pending_user_id", None)
                        session.pop("otp_next_url", None)
                        session.pop("otp_action", None)
                        login_user(user)
                        flash("Login successful!", "success")
                        return redirect(next_url)
                else:
                    flash("Invalid OTP token. Please try again.", "danger")
                    return render_template(
                        "otp/verify.html", action=action, next_url=next_url
                    )

            elif action:
                # Admin action OTP verification
                user = get_current_user()
                if user:
                    otp_record = OTPSecrets.query.filter_by(user_id=user.id).first()

                    if otp_record and verify_otp(otp_record.secret, token):
                        # OTP verified for action
                        session["otp_verified_action"] = action
                        session["otp_verified_timestamp"] = time.time()
                        session.pop("otp_action", None)
                        flash(
                            "OTP verified. You may proceed with the action.", "success"
                        )
                        return redirect(next_url)
                    else:
                        flash("Invalid OTP token. Please try again.", "danger")
                        return render_template(
                            "otp/verify.html", action=action, next_url=next_url
                        )

    return redirect(url_for("auth.login"))


@otp_bp.route("/admin/settings", methods=["GET", "POST"])
@admins_only
def admin_settings():
    """Admin settings page for OTP configuration."""
    if request.method == "GET":
        settings = get_otp_settings()
        return render_template("otp/admin_settings.html", **settings)

    elif request.method == "POST":
        # Update OTP settings
        set_config("otp_enabled", request.form.get("otp_enabled") == "on")
        set_config(
            "otp_required_for_admins",
            request.form.get("otp_required_for_admins") == "on",
        )
        set_config(
            "otp_required_for_clear_db",
            request.form.get("otp_required_for_clear_db") == "on",
        )
        set_config(
            "otp_required_for_reset", request.form.get("otp_required_for_reset") == "on"
        )
        set_config(
            "otp_required_for_export",
            request.form.get("otp_required_for_export") == "on",
        )
        set_config(
            "otp_required_for_import",
            request.form.get("otp_required_for_import") == "on",
        )
        set_config(
            "otp_required_for_user_delete",
            request.form.get("otp_required_for_user_delete") == "on",
        )
        set_config(
            "otp_required_for_config_change",
            request.form.get("otp_required_for_config_change") == "on",
        )

        clear_config()
        flash("OTP settings have been updated.", "success")
        return redirect(url_for("otp.admin_settings"))


def require_otp_for_action(action):
    """
    Decorator to require OTP verification for sensitive admin actions.
    Usage: @require_otp_for_action("clear_db")
    """
    import functools

    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not is_admin():
                return f(*args, **kwargs)

            # Check if OTP is required for this action
            settings = get_otp_settings()
            config_key = f"otp_required_for_{action}"

            if not settings.get("otp_enabled") or not settings.get(config_key):
                return f(*args, **kwargs)

            user = get_current_user()
            if not user:
                return f(*args, **kwargs)

            # Check if user has OTP enabled
            if not is_otp_enabled_for_user(user.id):
                flash(
                    "OTP is required for this action but not configured. Please set up OTP first.",
                    "warning",
                )
                return redirect(url_for("otp.setup"))

            # Check if OTP was recently verified for this action
            verified_action = session.get("otp_verified_action")
            verified_timestamp = session.get("otp_verified_timestamp", 0)
            current_time = time.time()

            # OTP verification is valid for 5 minutes
            if verified_action == action and (current_time - verified_timestamp) < 300:
                # Clear the verification after use
                session.pop("otp_verified_action", None)
                session.pop("otp_verified_timestamp", None)
                return f(*args, **kwargs)

            # Redirect to OTP verification
            session["otp_action"] = action
            session["otp_next_url"] = request.url
            return redirect(url_for("otp.verify"))

        return decorated_function

    return decorator


def load(app):
    """Load the OTP plugin."""
    # Run database migrations (Alembic handles schema changes)
    upgrade(plugin_name="ctfd-otp-plugin")

    # Register blueprint
    app.register_blueprint(otp_bp)

    # Register plugin assets
    register_plugin_assets_directory(app, base_path="/plugins/ctfd-otp-plugin/assets/")

    # Register admin menu item
    register_admin_plugin_menu_bar("OTP Settings", "/otp/admin/settings")

    # Initialize default config values if not set
    with app.app_context():
        if get_config("otp_enabled") is None:
            set_config("otp_enabled", False)
        if get_config("otp_required_for_admins") is None:
            set_config("otp_required_for_admins", False)
        if get_config("otp_required_for_clear_db") is None:
            set_config("otp_required_for_clear_db", False)
        if get_config("otp_required_for_reset") is None:
            set_config("otp_required_for_reset", False)
        if get_config("otp_required_for_export") is None:
            set_config("otp_required_for_export", False)
        if get_config("otp_required_for_import") is None:
            set_config("otp_required_for_import", False)
        if get_config("otp_required_for_user_delete") is None:
            set_config("otp_required_for_user_delete", False)
        if get_config("otp_required_for_config_change") is None:
            set_config("otp_required_for_config_change", False)
