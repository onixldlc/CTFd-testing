#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Tests for CTFd OTP Plugin

Tests cover:
- OTP rate limiting (5 attempts per minute)
- Backup code rate limiting (5 attempts per 5 minutes)
- OTP setup actions
- OTP verification flows
"""

import importlib
import time

import pyotp

from tests.helpers import (
    create_ctfd,
    destroy_ctfd,
    gen_user,
)


def get_otp_plugin(app):
    """Get OTP plugin module."""
    return importlib.import_module("CTFd.plugins.ctfd-otp-plugin")


def create_ctfd_with_otp():
    """Create a CTFd app with OTP plugin enabled."""
    return create_ctfd(enable_plugins=True)


class TestOTPRateLimiting:
    """Tests for OTP rate limiting (5 attempts per 1 minute)."""

    def test_otp_rate_limit_allows_5_attempts(self):
        """Test that 5 OTP attempts are allowed before lockout."""
        app = create_ctfd_with_otp()
        with app.app_context():
            otp_plugin = get_otp_plugin(app)
            db = app.db

            # Create a user
            user = gen_user(db, name="testuser", email="test@test.com")

            # Create OTP record with a known secret
            secret = pyotp.random_base32()
            otp_record = otp_plugin.OTPSecrets(
                user_id=user.id, secret=secret, enabled=True
            )
            db.session.add(otp_record)
            db.session.commit()

            # Simulate 4 failed attempts - should all be allowed
            for i in range(4):
                is_allowed, _ = otp_plugin.check_otp_rate_limit(otp_record)
                assert is_allowed, f"Attempt {i+1} should be allowed"
                otp_plugin.record_otp_attempt(otp_record, success=False)

            # 5th attempt should still be allowed (lockout happens at attempt 5)
            is_allowed, _ = otp_plugin.check_otp_rate_limit(otp_record)
            assert is_allowed, "5th attempt should be allowed"
            otp_plugin.record_otp_attempt(otp_record, success=False)

            # Now user should be locked out
            is_allowed, time_remaining = otp_plugin.check_otp_rate_limit(otp_record)
            assert not is_allowed, "6th attempt should be blocked"
            assert time_remaining > 0, "Should have time remaining on lockout"

        destroy_ctfd(app)

    def test_otp_rate_limit_1_minute_lockout(self):
        """Test that OTP lockout lasts for 1 minute (60 seconds)."""
        app = create_ctfd_with_otp()
        with app.app_context():
            otp_plugin = get_otp_plugin(app)
            db = app.db

            user = gen_user(db, name="testuser", email="test@test.com")
            secret = pyotp.random_base32()
            otp_record = otp_plugin.OTPSecrets(
                user_id=user.id, secret=secret, enabled=True
            )
            db.session.add(otp_record)
            db.session.commit()

            # Trigger lockout with 5 failed attempts
            for _ in range(5):
                otp_plugin.record_otp_attempt(otp_record, success=False)

            # Verify lockout is active
            is_allowed, time_remaining = otp_plugin.check_otp_rate_limit(otp_record)
            assert not is_allowed
            # Lockout should be around 60 seconds (1 minute)
            assert 55 <= time_remaining <= 60

        destroy_ctfd(app)

    def test_otp_rate_limit_resets_after_success(self):
        """Test that OTP attempts reset after successful verification."""
        app = create_ctfd_with_otp()
        with app.app_context():
            otp_plugin = get_otp_plugin(app)
            db = app.db

            user = gen_user(db, name="testuser", email="test@test.com")
            secret = pyotp.random_base32()
            otp_record = otp_plugin.OTPSecrets(
                user_id=user.id, secret=secret, enabled=True
            )
            db.session.add(otp_record)
            db.session.commit()

            # Make 4 failed attempts
            for _ in range(4):
                otp_plugin.record_otp_attempt(otp_record, success=False)

            assert otp_record.otp_attempts == 4

            # Successful attempt should reset
            otp_plugin.record_otp_attempt(otp_record, success=True)

            assert otp_record.otp_attempts == 0
            assert otp_record.otp_lockout_until is None

        destroy_ctfd(app)

    def test_otp_rate_limit_resets_after_lockout_expires(self):
        """Test that OTP rate limit resets after the lockout period expires."""
        app = create_ctfd_with_otp()
        with app.app_context():
            otp_plugin = get_otp_plugin(app)
            db = app.db

            user = gen_user(db, name="testuser", email="test@test.com")
            secret = pyotp.random_base32()
            otp_record = otp_plugin.OTPSecrets(
                user_id=user.id, secret=secret, enabled=True
            )
            db.session.add(otp_record)
            db.session.commit()

            # Trigger lockout
            for _ in range(5):
                otp_plugin.record_otp_attempt(otp_record, success=False)

            # Verify locked out
            is_allowed, _ = otp_plugin.check_otp_rate_limit(otp_record)
            assert not is_allowed

            # Simulate time passing (set lockout to past)
            otp_record.otp_lockout_until = time.time() - 1
            db.session.commit()

            # Should be allowed again
            is_allowed, _ = otp_plugin.check_otp_rate_limit(otp_record)
            assert is_allowed

            # Attempts should be reset
            assert otp_record.otp_attempts == 0
            assert otp_record.otp_lockout_until is None

        destroy_ctfd(app)


class TestBackupCodeRateLimiting:
    """Tests for backup code rate limiting (5 attempts per 5 minutes)."""

    def test_backup_code_rate_limit_allows_5_attempts(self):
        """Test that 5 backup code attempts are allowed before lockout."""
        app = create_ctfd_with_otp()
        with app.app_context():
            otp_plugin = get_otp_plugin(app)
            db = app.db

            user = gen_user(db, name="testuser", email="test@test.com")
            secret = pyotp.random_base32()
            otp_record = otp_plugin.OTPSecrets(
                user_id=user.id, secret=secret, enabled=True
            )
            db.session.add(otp_record)
            db.session.commit()

            # 4 failed attempts should be allowed
            for i in range(4):
                is_allowed, _ = otp_plugin.check_backup_code_rate_limit(otp_record)
                assert is_allowed, f"Attempt {i+1} should be allowed"
                otp_plugin.record_backup_code_attempt(otp_record, success=False)

            # 5th attempt should be allowed (lockout triggers after recording it)
            is_allowed, _ = otp_plugin.check_backup_code_rate_limit(otp_record)
            assert is_allowed, "5th attempt should be allowed"
            otp_plugin.record_backup_code_attempt(otp_record, success=False)

            # Now locked out
            is_allowed, time_remaining = otp_plugin.check_backup_code_rate_limit(
                otp_record
            )
            assert not is_allowed
            assert time_remaining > 0

        destroy_ctfd(app)

    def test_backup_code_rate_limit_5_minute_lockout(self):
        """Test that backup code lockout lasts for 5 minutes (300 seconds)."""
        app = create_ctfd_with_otp()
        with app.app_context():
            otp_plugin = get_otp_plugin(app)
            db = app.db

            user = gen_user(db, name="testuser", email="test@test.com")
            secret = pyotp.random_base32()
            otp_record = otp_plugin.OTPSecrets(
                user_id=user.id, secret=secret, enabled=True
            )
            db.session.add(otp_record)
            db.session.commit()

            # Trigger lockout
            for _ in range(5):
                otp_plugin.record_backup_code_attempt(otp_record, success=False)

            is_allowed, time_remaining = otp_plugin.check_backup_code_rate_limit(
                otp_record
            )
            assert not is_allowed
            # Should be around 300 seconds (5 minutes)
            assert 295 <= time_remaining <= 300

        destroy_ctfd(app)


class TestOTPVerify:
    """Tests for OTP verification endpoint rate limiting."""

    def test_verify_rate_limits_otp_after_5_failed_attempts(self):
        """Test that OTP verification enforces rate limiting after 5 failed attempts."""
        app = create_ctfd_with_otp()
        with app.app_context():
            otp_plugin = get_otp_plugin(app)
            db = app.db

            # Create a user with OTP enabled
            user = gen_user(db, name="testuser", email="test@test.com")
            secret = pyotp.random_base32()
            otp_record = otp_plugin.OTPSecrets(
                user_id=user.id, secret=secret, enabled=True
            )
            db.session.add(otp_record)
            db.session.commit()

            # Simulate 5 failed OTP verification attempts
            for i in range(5):
                is_allowed, _ = otp_plugin.check_otp_rate_limit(otp_record)
                assert is_allowed, f"Attempt {i+1} should be allowed"
                
                # Verify with wrong token
                result = otp_plugin.verify_otp(secret, "000000")
                assert not result, "Wrong token should not verify"
                
                otp_plugin.record_otp_attempt(otp_record, success=False)

            # Now should be rate limited
            is_allowed, time_remaining = otp_plugin.check_otp_rate_limit(otp_record)
            assert not is_allowed, "Should be rate limited after 5 failed attempts"
            assert time_remaining > 0, "Should have time remaining on lockout"

        destroy_ctfd(app)


class TestOTPSetupRateLimiting:
    """Tests for OTP setup actions rate limiting.
    
    Note: These tests verify the rate limiting functions work correctly.
    The setup endpoint should apply rate limiting to OTP verification attempts.
    """

    def test_setup_action_should_use_rate_limiting_functions(self):
        """Test that OTP setup actions have rate limiting applied.
        
        This verifies the rate limiting functions work when called from setup.
        """
        app = create_ctfd_with_otp()
        with app.app_context():
            otp_plugin = get_otp_plugin(app)
            db = app.db

            user = gen_user(db, name="testuser", email="test@test.com")
            secret = pyotp.random_base32()
            otp_record = otp_plugin.OTPSecrets(
                user_id=user.id, secret=secret, enabled=True
            )
            db.session.add(otp_record)
            db.session.commit()

            # Simulate 5 failed attempts using the rate limiting functions
            for i in range(5):
                is_allowed, _ = otp_plugin.check_otp_rate_limit(otp_record)
                assert is_allowed, f"Attempt {i+1} should be allowed"
                otp_plugin.record_otp_attempt(otp_record, success=False)

            # Now should be rate limited
            is_allowed, time_remaining = otp_plugin.check_otp_rate_limit(otp_record)
            assert not is_allowed, "Should be rate limited after 5 failed attempts"
            assert time_remaining > 0, "Should have time remaining"

        destroy_ctfd(app)

    def test_rate_limit_applies_to_all_otp_actions(self):
        """Test that rate limiting would block attempts across actions.
        
        If rate limiting is applied to enable/disable/regenerate actions,
        attempts from one action count towards the limit for all actions.
        """
        app = create_ctfd_with_otp()
        with app.app_context():
            otp_plugin = get_otp_plugin(app)
            db = app.db

            user = gen_user(db, name="testuser", email="test@test.com")
            secret = pyotp.random_base32()
            otp_record = otp_plugin.OTPSecrets(
                user_id=user.id, secret=secret, enabled=True
            )
            db.session.add(otp_record)
            db.session.commit()

            # Simulate mixed failed attempts (would come from different actions)
            otp_plugin.record_otp_attempt(otp_record, success=False)  # enable
            otp_plugin.record_otp_attempt(otp_record, success=False)  # disable
            otp_plugin.record_otp_attempt(otp_record, success=False)  # regenerate
            otp_plugin.record_otp_attempt(otp_record, success=False)  # backup
            otp_plugin.record_otp_attempt(otp_record, success=False)  # any

            # Now all actions should be blocked
            is_allowed, _ = otp_plugin.check_otp_rate_limit(otp_record)
            assert not is_allowed, "Should be rate limited after 5 total failed attempts"

        destroy_ctfd(app)


class TestOTPFunctions:
    """Tests for OTP utility functions."""

    def test_verify_otp_with_valid_token(self):
        """Test OTP verification with valid token."""
        app = create_ctfd_with_otp()
        with app.app_context():
            otp_plugin = get_otp_plugin(app)

            secret = pyotp.random_base32()
            totp = pyotp.TOTP(secret)
            valid_token = totp.now()

            assert otp_plugin.verify_otp(secret, valid_token)

        destroy_ctfd(app)

    def test_verify_otp_with_invalid_token(self):
        """Test OTP verification with invalid token."""
        app = create_ctfd_with_otp()
        with app.app_context():
            otp_plugin = get_otp_plugin(app)

            secret = pyotp.random_base32()

            assert not otp_plugin.verify_otp(secret, "000000")

        destroy_ctfd(app)

    def test_generate_backup_codes(self):
        """Test backup code generation."""
        app = create_ctfd_with_otp()
        with app.app_context():
            otp_plugin = get_otp_plugin(app)

            codes = otp_plugin.generate_backup_codes(10)

            assert len(codes) == 10
            for code in codes:
                assert len(code) == 8
                assert code.isupper()

        destroy_ctfd(app)

    def test_verify_backup_code(self):
        """Test backup code verification."""
        app = create_ctfd_with_otp()
        with app.app_context():
            otp_plugin = get_otp_plugin(app)
            db = app.db

            user = gen_user(db, name="testuser", email="test@test.com")
            secret = pyotp.random_base32()
            otp_record = otp_plugin.OTPSecrets(
                user_id=user.id, secret=secret, enabled=True
            )
            db.session.add(otp_record)
            db.session.commit()

            # Generate and store backup codes
            codes = otp_plugin.generate_backup_codes(10)
            otp_plugin.store_backup_codes(otp_record, codes)

            # Verify a backup code works
            assert otp_plugin.verify_backup_code(otp_record, codes[0])

            # Same code should not work again (one-time use)
            assert not otp_plugin.verify_backup_code(otp_record, codes[0])

            # Different code should still work
            assert otp_plugin.verify_backup_code(otp_record, codes[1])

        destroy_ctfd(app)

    def test_remaining_backup_codes_count(self):
        """Test counting remaining backup codes."""
        app = create_ctfd_with_otp()
        with app.app_context():
            otp_plugin = get_otp_plugin(app)
            db = app.db

            user = gen_user(db, name="testuser", email="test@test.com")
            secret = pyotp.random_base32()
            otp_record = otp_plugin.OTPSecrets(
                user_id=user.id, secret=secret, enabled=True
            )
            db.session.add(otp_record)
            db.session.commit()

            codes = otp_plugin.generate_backup_codes(10)
            otp_plugin.store_backup_codes(otp_record, codes)

            assert otp_plugin.get_remaining_backup_codes_count(otp_record) == 10

            # Use one code
            otp_plugin.verify_backup_code(otp_record, codes[0])

            assert otp_plugin.get_remaining_backup_codes_count(otp_record) == 9

        destroy_ctfd(app)
