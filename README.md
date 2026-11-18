# Login Armor

Login Armor is a free WordPress plugin that protects login, accounts and administration. It has thirteen independent security modules, no premium tier and no remote dashboard.

- **Install it** from your WordPress dashboard (Plugins > Add New, search for "Login Armor") or from [wordpress.org/plugins/login-armor](https://wordpress.org/plugins/login-armor/).
- **Get support** on the [WordPress.org support forum](https://wordpress.org/support/plugin/login-armor/).
- **License:** GPL-2.0-or-later, see [LICENSE](LICENSE).
- **Author:** Fabrice Ducarme, [wpformation.com](https://wpformation.com).

## What it does

1. **Hide Login:** replaces `wp-login.php` with a private slug.
2. **Brute Force Protection:** escalating lockouts and subnet blocking for login, password recovery, registration, XML-RPC and REST.
3. **Hardening:** sixteen opt-in controls (XML-RPC, file editing, author enumeration, application passwords, forcing HTTPS and more).
4. **Two-Factor Authentication:** TOTP, email codes, backup codes, trusted devices and per-role enforcement.
5. **Detection and Incidents:** groups raw events into attack patterns with severity and timelines.
6. **Activity Log:** tamper-evident admin audit trail, CSV export and optional signed SIEM forwarding.
7. **Security Headers** for the login and lockout pages.
8. **Breach Check:** privacy-preserving Have I Been Pwned password checks.
9. **Password Policy:** length and character rules, breached-password rejection.
10. **Session Management:** idle timeout, maximum lifetime and revocation of other sessions.
11. **IP Geolocation:** cached country lookup for the addresses shown in incidents.
12. **Request Firewall:** monitor-first filtering of malicious paths, query strings and methods.
13. **Bot Challenge:** an invisible proof-of-work, an alternative to CAPTCHAs with no external service.

It also ships a 0-100 security score, notifications (email, Slack, Discord, webhooks), Site Health tests, a full WP-CLI suite, multisite support and a safe mode constant that stands down every protection able to lock an administrator out.

Requirements: WordPress 6.8 or later, PHP 8.1 or later. The plugin has no external dependency and no build step.

## About this repository

Development happens in a private repository. Each version published on WordPress.org is copied here unchanged on the day it is released, and tagged `vX.Y.Z`. The files of a tag are the files of the ZIP that WordPress.org serves for that version.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private vulnerability reporting instead: **Security** tab, then **Report a vulnerability**.
