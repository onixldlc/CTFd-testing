# CTFd OTP Plugin

A two-factor authentication (OTP/TOTP) plugin for CTFd that adds an extra layer of security to your CTF platform.

## Features

- **OTP Setup Page**: Users can configure their authenticator apps by scanning a QR code or manually entering a secret key
- **OTP Verification Page**: Verify OTP codes during login or for sensitive admin actions
- **Admin Settings Page**: Configure OTP requirements for various admin actions with granular control
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
- Secrets are stored in plain text in the database. Consider enabling database encryption or application-level encryption for enhanced security in high-security environments.

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

This plugin provides OTP infrastructure and admin action protection. To enforce OTP on user login, you would need to integrate with CTFd's authentication flow by:

1. Modifying the login route to check for OTP requirement
2. Setting `otp_pending_user_id` in session after password validation
3. Redirecting to `/otp/verify` before completing login

## Requirements

- CTFd 3.x+
- Python 3.7+
- pyotp library
- qrcode library (with pillow for image generation)

## License

This plugin is released under the same license as CTFd.

## Support

For issues and feature requests, please create an issue in the repository.
