# CTFd OTP Plugin

A two-factor authentication (OTP/TOTP) plugin for CTFd that adds an extra layer of security to your CTF platform.

## Features

- **OTP Setup Page**: Users can configure their authenticator apps by scanning a QR code or manually entering a secret key
- **OTP Verification Page**: Verify OTP codes during login or for sensitive admin actions
- **Backup Codes**: 10 one-time backup codes for account recovery if authenticator is lost
- **Admin Settings Page**: Configure OTP requirements for various admin actions with granular control
- **Rate Limiting**: Protection against brute force attacks on backup codes (5 attempts, then 5-minute lockout)
- **Action-based OTP Protection**: Require OTP verification for sensitive operations like:
  - Clearing the database
  - Resetting the CTF
  - Deleting users
  - Exporting/Importing data
  - Changing configuration

## Installation

1. Copy the `ctfd-otp-plugin` folder to your CTFd plugins directory:

   ```
   CTFd/plugins/ctfd-otp-plugin/
   ```

2. Install the required Python dependencies:

   ```bash
   pip install pyotp qrcode[pil]
   ```

3. Restart CTFd

## Usage

### Setting Up OTP

1. Navigate to `/otp/setup` as an authenticated user
2. Scan the QR code with your authenticator app (Google Authenticator, Authy, Microsoft Authenticator, etc.)
3. Enter the 6-digit code from your app to verify and enable OTP
4. **Important**: Save the 10 backup codes shown after setup - these are one-time use codes for account recovery

### Using Backup Codes

If you lose access to your authenticator app:

1. On the OTP verification page, click "Use a Backup Code"
2. Enter one of your 8-character backup codes
3. Each backup code can only be used once
4. After logging in, regenerate new backup codes from the OTP setup page

### Admin Configuration

1. Navigate to `/otp/admin/settings` as an administrator
2. Enable/disable the OTP plugin globally
3. Configure which admin actions require OTP verification
4. Toggle individual action protection settings

## Settings

| Setting                     | Description                                       |
| --------------------------- | ------------------------------------------------- |
| Enable OTP Plugin           | Master switch to enable/disable OTP functionality |
| Require OTP for Admin Login | Require admins to verify OTP during login         |
| Clear Database              | Require OTP to clear database tables              |
| Reset CTF                   | Require OTP to reset CTF data                     |
| Delete Users                | Require OTP to delete user accounts               |
| Export Data                 | Require OTP to export CTF data                    |
| Import Data                 | Require OTP to import CTF data                    |
| Change Configuration        | Require OTP to modify CTF settings                |

## Compatible Authenticator Apps

- [Google Authenticator](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2)
- [Authy](https://authy.com/)
- [Microsoft Authenticator](https://www.microsoft.com/en-us/security/mobile-authenticator-app)
- Any TOTP-compatible authenticator app

## Technical Details

- Uses TOTP (Time-based One-Time Password) algorithm
- 6-digit codes that refresh every 30 seconds
- OTP verification for admin actions is valid for 5 minutes
- 10 backup codes generated on OTP setup (8 characters each, one-time use)
- Backup code rate limiting: 5 failed attempts triggers a 5-minute lockout
- Secrets are stored in plain text in the database. Consider enabling database encryption or application-level encryption for enhanced security in high-security environments.
- Backup codes are stored as SHA-256 hashes for security

## API Endpoints

| Endpoint              | Method   | Description                   |
| --------------------- | -------- | ----------------------------- |
| `/otp/setup`          | GET/POST | OTP setup and management page |
| `/otp/verify`         | GET/POST | OTP verification page         |
| `/otp/admin/settings` | GET/POST | Admin settings page           |

## Development

### Decorator for Custom Actions

You can protect your own admin actions using the `require_otp_for_action` decorator. Since the plugin directory uses hyphens (`ctfd-otp-plugin`), Python cannot import it directly. Use the plugin module access pattern:

```python
# Access the decorator through CTFd's plugin system
import importlib
otp_plugin = importlib.import_module("CTFd.plugins.ctfd-otp-plugin")
require_otp_for_action = otp_plugin.require_otp_for_action

@app.route('/admin/my-action', methods=['POST'])
@admins_only
@require_otp_for_action('my_action')
def my_protected_action():
    # This action will require OTP verification
    pass
```

**Note:** Make sure to add a corresponding OTP setting (e.g., `otp_required_for_my_action`) in the admin settings if you want to make it configurable.

## Integration Notes

### Important: Login Flow Integration

**This plugin does NOT automatically enforce OTP during user login.** The plugin provides the infrastructure for OTP (setup pages, verification pages, admin settings) and protects admin actions, but it does not hook into CTFd's authentication flow out of the box.

#### Current Functionality (Works Without Modification)

- ✅ OTP setup and management for users
- ✅ Admin settings to configure OTP requirements
- ✅ Protection for admin actions (clear DB, reset, delete users, etc.) via the `@require_otp_for_action` decorator
- ✅ OTP verification page infrastructure

#### Requires CTFd Core Modifications

To enforce OTP during login, you need to modify CTFd's authentication routes. Here's how:

1. **Modify the login route** in `CTFd/auth.py`:

   ```python
   # After successful password validation but before login_user():
   from CTFd.plugins import get_plugin

   # Check if OTP is required for this user
   otp_plugin = get_plugin("ctfd-otp-plugin")
   if otp_plugin and otp_plugin.is_otp_enabled_for_user(user.id):
       session["otp_pending_user_id"] = user.id
       session["otp_next_url"] = request.args.get("next", url_for("challenges.listing"))
       return redirect(url_for("otp.verify"))

   # Otherwise, proceed with normal login
   login_user(user)
   ```

2. **Set the session variable** `otp_pending_user_id` to the user's ID after password validation

3. **Redirect to `/otp/verify`** instead of completing the login immediately

4. The plugin's verify route will handle OTP verification and complete the login

#### Alternative: Middleware Approach

You can also create a middleware or use Flask's `before_request` hook to check if authenticated users need OTP verification, though this is more complex and may affect performance.

### Admin Action Protection

The `@require_otp_for_action` decorator works without any core modifications. To protect a custom admin action:

```python
import importlib
otp_plugin = importlib.import_module("CTFd.plugins.ctfd-otp-plugin")

@app.route('/admin/dangerous-action', methods=['POST'])
@admins_only
@otp_plugin.require_otp_for_action('dangerous_action')
def dangerous_action():
    # This action requires OTP verification
    pass
```

## Requirements

- CTFd 3.x+
- Python 3.7+
- pyotp library
- qrcode library (with pillow for image generation)

## License

This plugin is released under the same license as CTFd.

## Support

For issues and feature requests, please create an issue in the repository.
