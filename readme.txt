=== Login Armor ===
Contributors: wpformation
Donate link: https://wpformation.com
Tags: login security, hide login, brute force, limit login, activity log
Requires at least: 6.8
Tested up to: 7.1
Stable tag: 2.10.1
Requires PHP: 8.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Thirteen security modules + AI briefing: hide login, request firewall, brute force, 2FA, password policy, sessions, hardening, audit log. No upsells.

== Description ==

🇫🇷 **Fully translated into French. Interface et documentation intégralement disponibles en français.**

**Thirteen security modules. One lightweight plugin. No premium tier.**

https://www.youtube.com/watch?v=sSNeqpQxtf8

Login Armor protects WordPress login, accounts and administration with thirteen independent modules. It is built for agencies, freelancers and site owners who want practical security, clear evidence and safe defaults without a remote dashboard, bundled telemetry or upsells.

= Why Login Armor =

* **Complete and free:** every module is included under the GPL.
* **Lightweight:** modules load only when needed and normal login checks add less than 2 ms on a typical setup.
* **Private by default:** data stays on your site. Optional external calls are disabled until you enable the related feature.
* **Ready for real sites:** multisite support, reverse-proxy controls, WP-CLI commands and production-safe defaults.

= Thirteen security modules =

1. **Hide Login:** replace `wp-login.php` with a private slug and return a 404 or redirect blocked visitors to a chosen URL.
2. **Brute Force Protection:** escalating lockouts, subnet blocking, trusted proxy headers and coverage for login, password recovery, registration, XML-RPC and REST users.
3. **Hardening:** sixteen controls for XML-RPC, pingbacks, file editing, version exposure, application passwords, author enumeration, reserved usernames, honeypots, new-admin alerts and forcing HTTPS.
4. **Two-Factor Authentication:** TOTP, email codes, backup codes, trusted devices, per-role enforcement, grace periods and recovery.
5. **Detection and Incidents:** group raw events into attack patterns with severity, timelines, source IPs, targeted users and one-click actions.
6. **Activity Log:** tamper-evident admin audit trail with filters, CSV export, retention controls and optional signed SIEM forwarding.
7. **Security Headers:** CSP, X-Frame-Options, Permissions-Policy, Referrer-Policy and X-Content-Type-Options for login and lockout pages, with optional site-wide baseline headers.
8. **Breach Check:** privacy-preserving Have I Been Pwned password checks and an optional XposedOrNot email check.
9. **Password Policy:** length and character rules, username exclusion, breached-password rejection and optional non-locking expiration reminders.
10. **Session Management:** idle timeout, maximum lifetime, optional single-device access and one-click revocation of other sessions.
11. **IP Geolocation:** cached country lookup for IPs shown in Incidents and Events, with private ranges excluded.
12. **Request Firewall:** optional, monitor-first filtering of malicious paths, query strings and HTTP methods, with administrator exclusions and IP/path allowlists.
13. **Bot Challenge:** an invisible proof-of-work the browser solves before the login form is accepted, an alternative to CAPTCHAs with no external service; monitor-first, then enforce.

= Additional tools =

Login Armor also includes guided onboarding, a 0-100 security score, conflict detection, email/Slack/Discord/webhook notifications, an optional weekly or monthly security digest, nine Tools > Site Health tests with a support panel, a dashboard widget and a complete WP-CLI suite. A safe mode constant in wp-config.php stands down every protection that could lock an administrator out, without changing a single setting.

The guided safe baseline turns on brute-force protection, attack detection, login-page security headers, the activity log, the seven safest hardening toggles, and the request firewall and bot challenge in monitor mode, where they record without blocking anything. Hide Login and two-factor stay off so you enable them deliberately. After seven days of monitoring, Login Armor reads your own traffic and tells you whether the firewall and the bot challenge can safely start blocking.

The optional AI Security Briefing uses your own WordPress AI connector to explain a thirty-day security snapshot or a single incident. It always starts with deterministic facts, works without AI and sends nothing until an administrator explicitly requests an analysis.

GPL forever. PHP 8.1+. WordPress 6.8+. Zero dependencies.

---

**Treize modules de sécurité. Une seule extension légère. Aucune version premium.**

Login Armor protège la connexion, les comptes et l'administration de WordPress grâce à treize modules indépendants. L'extension s'adresse aux agences, freelances et propriétaires de sites qui veulent une sécurité concrète, des preuves lisibles et des réglages sûrs, sans tableau de bord distant, télémétrie imposée ni upsell.

= Pourquoi Login Armor =

* **Complet et gratuit :** tous les modules sont inclus sous licence GPL.
* **Léger :** les modules se chargent uniquement lorsque nécessaire et les contrôles ajoutent moins de 2 ms sur une connexion normale.
* **Privé par défaut :** les données restent sur votre site. Les appels externes optionnels sont désactivés tant que vous n'activez pas la fonction concernée.
* **Prêt pour la production :** multisite, reverse proxies, commandes WP-CLI et réglages par défaut sécurisés.

= Treize modules de sécurité =

1. **Masquer la connexion :** remplace `wp-login.php` par un slug privé et renvoie une 404 ou redirige les visiteurs bloqués vers l'URL choisie.
2. **Protection contre la force brute :** verrouillages progressifs, blocage de sous-réseaux, proxies de confiance et protection de la connexion, récupération, inscription, XML-RPC et REST users.
3. **Renforcement :** seize contrôles pour XML-RPC, les pingbacks, l'éditeur de fichiers, la version, les mots de passe applicatifs, l'énumération d'auteurs, les identifiants réservés, le pot de miel, les alertes nouvel administrateur et le passage forcé en HTTPS.
4. **Authentification à deux facteurs :** TOTP, codes par e-mail, codes de secours, appareils de confiance, application par rôle, période de grâce et récupération.
5. **Détection et incidents :** regroupe les événements en scénarios d'attaque avec sévérité, chronologie, IP sources, comptes ciblés et actions immédiates.
6. **Journal d'activité :** piste d'audit admin infalsifiable avec filtres, export CSV, rétention et transfert SIEM signé optionnel.
7. **En-têtes de sécurité :** CSP, X-Frame-Options, Permissions-Policy, Referrer-Policy et X-Content-Type-Options pour les pages de connexion et de verrouillage, avec en-têtes de base optionnels sur tout le site.
8. **Détection de fuites :** vérification confidentielle des mots de passe via Have I Been Pwned et contrôle optionnel des e-mails via XposedOrNot.
9. **Politique de mot de passe :** longueur, classes de caractères, exclusion de l'identifiant, rejet des mots de passe compromis et rappels d'expiration non bloquants.
10. **Gestion des sessions :** délai d'inactivité, durée maximale, accès limité à un appareil et révocation des autres sessions.
11. **Géolocalisation IP :** pays des IP affichées dans Incidents et Événements, avec cache et exclusion des plages privées.
12. **Pare-feu de requêtes :** filtrage optionnel, d'abord en surveillance, des chemins, requêtes et méthodes HTTP malveillants, avec exclusion des administrateurs et listes d'autorisation IP/chemins.
13. **Défi anti-bot :** une preuve de calcul invisible résolue par le navigateur avant validation du formulaire de connexion, alternative aux CAPTCHA sans service externe ; d'abord en surveillance, puis en blocage.

= Outils complémentaires =

Login Armor inclut aussi un assistant de configuration, un score de sécurité de 0 à 100, la détection de conflits, les notifications par e-mail, Slack, Discord ou webhook, un widget de tableau de bord et une suite WP-CLI complète.

La base sûre guidée active la protection contre la force brute, la détection d'attaques, les en-têtes de sécurité de la page de connexion, le journal d'activité, les sept réglages de renforcement les plus sûrs, ainsi que le pare-feu de requêtes et le défi anti-bot en mode surveillance, où ils enregistrent sans rien bloquer. Hide Login et la double authentification restent désactivés pour que vous les activiez délibérément. Au bout de sept jours de surveillance, Login Armor lit votre trafic réel et vous dit si le pare-feu et le défi anti-bot peuvent passer au blocage sans risque.

Le briefing de sécurité IA optionnel utilise votre propre connecteur IA WordPress pour expliquer les trente derniers jours ou un incident précis. Il commence toujours par des faits déterministes, fonctionne sans IA et n'envoie rien tant qu'un administrateur ne demande pas explicitement une analyse.

= Conçu par =

Login Armor est conçu et maintenu par Fabrice Ducarme de [WPFormation](https://wpformation.com/login-armor/). Nous l'utilisons sur chaque site que nous livrons.

* [Présentation et fonctionnement de Login Armor](https://wpformation.com/login-armor/)
* [Guides de sécurité WordPress](https://wpformation.com/securite-wordpress/) sur WPFormation
* [Veille des vulnérabilités WordPress](https://wpformation.com/outils/veille-securite/) sur WPFormation

GPL pour toujours. PHP 8.1+. WordPress 6.8+. Zéro dépendance.

== Installation ==

1. Upload the `login-armor` directory to `/wp-content/plugins/`
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to LoginArmor in the admin menu to configure

For multisite: Network Activate the plugin to apply it across all sites.

= Setting up Hide Login =

1. Go to LoginArmor > Settings > Hide Login section
2. Enter your desired login slug (e.g., `my-login`)
3. Save settings
4. **Bookmark your new login URL**: you will need it to access your admin

= Recovering access =

If you forget your custom login URL:

* Use WP-CLI: `wp login-armor status` prints your login URL and changes nothing
* Or read it in your database: the `login_armor_hide_slug` row of the `wp_options` table holds the slug, and your login URL is your site address followed by `/slug/` (or by `/?slug` when your permalinks are set to Plain)
* Check your inbox: if you ticked the box when you switched Hide Login on, the URL was emailed to you
* Turn Hide Login off: `wp option update login_armor_hide_enabled 0`. Deleting the `login_armor_hide_slug` row (or `wp option delete login_armor_hide_slug`), the method older versions gave, now has the same effect: `wp-login.php` answers again, and you choose a new URL from the settings once you are back in
* Run `wp login-armor rescue` from your server shell: it lists every way back in, and changes nothing until you add `--yes`
* Last resort, safe mode: add `define( 'LOGIN_ARMOR_SAFE_MODE', true );` to `wp-config.php`. `wp-login.php` is served again, two-factor is not required, the request firewall and the bot challenge only log, single-session enforcement pauses, and Force HTTPS enforces nothing. Your settings are untouched, brute-force lockouts stay active, and everything comes back the moment you delete the line.

If Force HTTPS was switched on by mistake and the site cannot answer over TLS:

* Use WP-CLI: `wp option patch update login_armor_hardening force_https false` (write `false` or `0`, nothing else: WordPress reads `off` and `no` as ON)
* Or, if you cannot reach a shell, stand it down without changing the setting: add `define( 'LOGIN_ARMOR_SAFE_MODE', true );` to `wp-config.php`. All four effects stop at once, the toggle keeps saying what you chose, and enforcement comes back on the first request after you delete the line.

= Turning Force HTTPS off: what changes =

If the proxy in front of your site starts reporting HTTPS from an address that is not in your Trusted proxy IPs, Force HTTPS **stands down entirely**: no redirect, no admin over SSL, no Secure cookies, nothing enforced at all, until you declare that proxy. That is deliberate. On a site whose proxy cannot be verified, each one of those three is a way to lock you out: the redirect loops, WordPress's own admin redirect loops, and the authentication cookie gets written under a name WordPress will not read back, so nobody can stay signed in. The plugin says so in the admin while it lasts, and everything comes back by itself on the first request after you declare the proxy.

That notice shows you the address it saw, and it is an observation, not an instruction. Any visitor can make it appear by sending one header, so never add an address to Trusted proxy IPs because it appeared there: ask your host or your CDN which address their terminator uses, and add only that one. An address on that list is believed when it tells Login Armor who your visitors are, which is what every lockout and ban depends on. If the notice says several different addresses have sent that header, that is forgery rather than a proxy you forgot to declare.

Switching Force HTTPS on or off changes whether WordPress reads your session from its secure cookie or its ordinary one, so you may be asked to sign in again right after the change. That is normal, and it is the same thing WordPress does on its own when you move your site address to https.

Turning the toggle off removes exactly what Login Armor added: its HTTP to HTTPS redirect, its call to `force_ssl_admin()`, the Secure flag it put on the two authentication cookies, and the fact that a request forwarded by one of your declared proxies counted as HTTPS for the length of that request. It changes nothing else.

Two things it cannot take back, because they were never a setting of this plugin. If your site sends a `Strict-Transport-Security` header, this option is what made that header effective behind a proxy, and every browser that already received it keeps the pin for the header's own duration, with the option on or off. And the redirect itself is sent with no-cache headers so that a CDN or a page cache does not keep serving it, but a cache that ignores those headers may still need to be purged. Your site address, your `.htaccess`, the `FORCE_SSL_ADMIN` constant in `wp-config.php` and any `Strict-Transport-Security` header stay exactly as they were. So if WordPress still sends the admin to https after you switch the toggle off, it is because the site address is already an `https://` one or because `FORCE_SSL_ADMIN` is defined in `wp-config.php`, and neither of those belongs to this plugin.

== Frequently Asked Questions ==

= Will it lock me out of my own site? =

Hide Login should not: when you switch it on, it offers to email the new URL to the site address, and `wp login-armor status` prints it at any time from SSH. Deleting the slug from the database turns Hide Login off and gives you `wp-login.php` back, and `wp login-armor rescue` prints every way back in without changing anything.

One option can, and it says so on its own row: Force HTTPS. It is off by default, it is never switched on by the safe baseline, and the plugin refuses to switch it on from a connection that is not already HTTPS. It also stands down by itself, and tells you so in the admin, if the proxy in front of your site starts reporting HTTPS from an address you have not listed in Trusted proxy IPs, which is what happens when a CDN or a load balancer changes address. If you still end up locked out, one command puts it back: `wp option patch update login_armor_hardening force_https false`.

If you cannot reach a shell either, there is a break-glass switch: add `define( 'LOGIN_ARMOR_SAFE_MODE', true );` to `wp-config.php`. `wp-login.php` answers again, the second factor is not demanded, the request firewall and the bot challenge drop back to logging only, and Force HTTPS stops enforcing all four of its effects, without any setting being rewritten. It is a constant and not an option, so it cannot be flipped from the database, and it is read once, while the plugin file loads: only code that runs before that can arm it, which means `wp-config.php`, a must-use plugin, or a plugin that loads earlier. A theme, or anything running on a WordPress hook, cannot, because by then the answer is already fixed. Brute-force lockouts are deliberately left running: clear your own address from the admin notice, or with `wp login-armor rescue --ip=<your ip> --yes`, which also lifts a blocked network that contains it. Delete the line to restore full protection. The "Block subnet" button refuses the network your own address belongs to.

= Does it slow my site down? =

No. Everything is lazy-loaded and indexed. On a normal login flow the extra SQL cost is under 2 ms.

= Is it compatible with Cloudflare / reverse proxies? =

Yes. Choose the proxy header in Settings and list the exact IP addresses or CIDR ranges of the proxies that are allowed to supply it. Forwarding headers are ignored when the immediate network peer is not explicitly trusted.

= Does it work with multisite? =

Yes, subdomain and subfolder. Each site has its own modules, logs, and thresholds.

= Does it work with Roots Bedrock, or with WordPress in its own directory? =

Yes. Since 2.8.3 the root .htaccess rules go where the server applies them: the directory the site is served from (`web/` under Bedrock), next to WordPress's own rewrite rules, rather than WordPress's directory (`web/wp/`). Under Bedrock, the safe-mode constant is set with `Config::define( 'LOGIN_ARMOR_SAFE_MODE', true );` in `config/application.php`.

Login Armor does not rotate your security keys: under Bedrock they live in `.env` and belong to your deployment. Know before you rotate them that it signs everyone out, and that the authenticator-app secrets are encrypted with `AUTH_KEY`: after a new `AUTH_KEY`, users sign in with a backup code, or an administrator runs `wp login-armor 2fa reset <user> --yes` and they enrol again. The Activity Log notices the change of keys; `wp login-armor activity reset-chain` starts a new baseline.

= Does it work with a headless WordPress (Next.js, Nuxt or Astro front end)? =

Yes. It was checked on a clone of a real headless back end (Nginx, Redis object cache, a Next.js front end reading the REST API). The hidden login URL, two-factor and brute-force lockouts protect the back office, while the public REST API, application passwords (previews, publishing scripts, MCP connectors) and revalidation webhooks keep working, even from an address that is locked out of the login form.

Turn on headless mode (Settings > Headless back end). It keeps "Restrict REST API" and "Disable application passwords" off, the two settings that close what your front end reads and refuse what your scripts write with, whether the change comes from the screen, an import or WP-CLI. The Request Firewall never inspects REST requests, so it leaves your API alone, even in blocking mode, and it does not protect it either. Only its "Bad user agents" family blocks pages outside the REST API (feeds, the sitemap) when curl or python request them.

Failed application passwords are logged and shown as their own incident, "Application password refused". Only unknown accounts count toward the lockout: an application password cannot be guessed, while a script holding a revoked one would otherwise lock your own address. Login Armor also records which networks each application password is used from, and alerts you the first time one is used from a hosting provider it has never been used from; you approve the network from the user's profile if it is one of your services. On a multisite network, a site administrator cannot approve the network of a password that belongs to another account, because WordPress requires the "manage_network_users" capability to edit another profile: a super administrator can, and everyone can on their own profile.

If fail2ban watches the hidden login URL, count HTTP 429 too: it is what Login Armor answers once it locks an address. Do not add a fail2ban jail on the 401 answers of the REST API: it would ban the cloud addresses your front end reads from, for the whole site.

= Can the logs be sent off the server? =

Yes. The Activity Log can forward every entry to an HTTPS endpoint you own (Settings > Activity Log): signed JSON (HMAC-SHA256), queued and retried, with the integrity-chain hashes so that your collector can verify the journal even if the local database is wiped. Alerts (incidents, lockouts, administrator accounts) go by email, Slack, Discord or webhook. The Events and Activity lists export to CSV, and every login attempt fires the `login_armor_log_recorded` action, which a must-use plugin can send to syslog or a SIEM.

= Can fail2ban ban the addresses LoginArmor counts? =

Yes. Turn on "Write failures and lockouts to the system log" (Settings > Brute force). Each failed login that counts toward the lockout, and each lockout, then writes one line under the identity `login-armor`, facility auth: `auth_failure ip=<address> vector=<form|xmlrpc|rest|other> reason=<code>` and `lockout ip=<address> level=<1|2>`. Never the login typed. A wrong application password of an existing account is not counted, so fail2ban never bans your own scripts. Filter (`/etc/fail2ban/filter.d/login-armor.conf`): `[Definition]` then `failregex = login-armor\[\d+\]: (?:auth_failure|lockout) ip=<HOST>`. Jail, with the systemd journal: `[login-armor]`, `enabled = true`, `backend = systemd`, `journalmatch = SYSLOG_IDENTIFIER=login-armor`, `maxretry = 5`, `findtime = 600`, `bantime = 3600`; with a log file instead of the journal, `logpath = /var/log/auth.log`. Setting up fail2ban is done as root on the server, and LoginArmor's allow list does not stop fail2ban: add your own addresses to `ignoreip`.

= Can I use LoginArmor alongside Wordfence / iThemes Security / Solid Security? =

Yes, but disable overlapping modules on one side to avoid double lockouts. With WPS Hide Login or Rename wp-login.php, whose only job is hiding the login page, LoginArmor refuses to switch its own hidden login address on, and stands down with a notice if both end up active: never two hidden addresses at once.

= Where is the data stored? =

Up to five custom tables in your own database: login events, brute-force attempts, incidents, and, when you switch the Activity Log on, its journal and its forwarding queue. Nothing leaves your server unless you enable a feature that says it does.

= How do I copy my configuration to another site? =

Settings > Export downloads every setting as a JSON file (webhook URLs only if you tick the box; the SIEM signing secret and users' two-factor enrolments never leave the site). On the other site, Settings > Import shows you every change first and applies nothing until you confirm. From the command line: `wp login-armor settings export --file=model.json`, then `wp login-armor settings import model.json --dry-run` and `--yes`. One invalid value refuses the whole file, and a firewall or bot challenge switched on by import always starts in monitor mode.

= What are the .htaccess.login-armor.bak and .htaccess.login-armor.lock files? =

They sit next to a `.htaccess` file that Login Armor writes into, in `wp-content/uploads` or at the root of the site. The `.bak` file is your restore point: a copy of the file as it was, taken once before the very first change and never overwritten afterwards. The `.lock` file is empty; it exists only to stop two requests writing the same file at the same moment. Both names start with `.ht`, so a web server configured for WordPress never serves them to a visitor. Both are deliberately left in place when you uninstall the plugin: a backup that disappears with the plugin is not a backup. The rules themselves are not: deactivating Login Armor takes its blocks out of the `.htaccess` files (and puts them back when you reactivate it), and deleting the plugin removes them for good. Your own rules around them are never touched.

= Is there a pro version? =

Not currently. LoginArmor is fully free and open source. GPL forever.

= Where can I report bugs or request features? =

Support forum: [wordpress.org/support/plugin/login-armor/](https://wordpress.org/support/plugin/login-armor/).

== Screenshots ==

1. Quick tour of the main modules - Hide Login, Hardening, 2FA setup with QR code, Incidents drill-down, Activity Log, Events, and Overview dashboard.
2. Overview dashboard - health cards, security pulse, live event tail, threat banner that surfaces active attacks.
3. Incidents - real-time pattern detection grouped by attack class with severity and one-click resolution.
4. Incident drill-down - full timeline, user-agent fingerprint, suggested actions, escalation flag.
5. Events - complete login attempts log with filters and CSV export.
6. Activity Log - admin action audit trail across seven domains, filterable and exportable.
7. Settings - modular configuration with live security score and a sticky save bar.
8. Hide Login pre-activation modal - pick or generate the secret URL and email it to yourself before flipping the switch.
9. Hardening - sixteen one-click toggles grouped by surface reduction, credential hardening, and request filtering.
10. Two-factor authentication setup - QR code for any authenticator app, copy-paste fallback, and live verification.
11. Breach Check - fully transparent k-anonymity lookups, separate password and email toggles, opt-in email check disabled by default.
12. Product demo - a distributed brute-force attack detected, grouped into one incident and locked out, then the hidden login URL, two-factor authentication, the request firewall, the bot challenge, the one-click safe baseline and the signed activity log.

== External Services ==

Login Armor has no telemetry and requires no Login Armor account. The following services are contacted only when WordPress itself or an administrator enables the related feature.

= WordPress AI connector (optional) =

The AI Security Briefing sends a security prompt through the administrator's own WordPress AI connector only after they click an analysis button. Minimised mode sends counts, categories, severities and role buckets without clear IP addresses or usernames. Explicit deep mode also sends IP addresses and event details. Login Armor stores no provider API key. The selected AI provider's terms and privacy policy apply.

= Slack, Discord or custom webhook (optional) =

When an administrator enables an incident notification channel, Login Armor sends the incident type, severity, IP address, target username, event count and site URL to the configured endpoint. The separate signed Activity Log forwarding option sends the event, object, user ID/login/role, IP address, description, integrity hashes, site URL and plugin version to the administrator's SIEM or custom webhook.

* **Slack:** [Terms](https://slack.com/terms-of-service) | [Privacy](https://slack.com/privacy-policy)
* **Discord:** [Terms](https://discord.com/terms) | [Privacy](https://discord.com/privacy)
* **Custom webhook:** terms and privacy are controlled by the administrator's chosen endpoint.

= Gravatar =

The Activity Log uses WordPress core's `get_avatar()`. If avatars are enabled in WordPress, a hashed email address may be sent to Gravatar to retrieve the image.

* **Gravatar:** [Terms](https://automattic.com/tos/) | [Privacy](https://automattic.com/privacy/)

= Have I Been Pwned (optional) =

Breach Check and the optional compromised-password policy send only the first 5 characters of a password's SHA-1 hash to the Pwned Passwords API. The password and full hash never leave the site. Checks fail soft if the service is unavailable. Public registration and password-reset validation do not call the service; authenticated checks remain active.

* **Have I Been Pwned:** [Privacy](https://haveibeenpwned.com/Privacy) | [Acceptable Use](https://haveibeenpwned.com/AcceptableUse)

= XposedOrNot (optional) =

The separate Email check, disabled by default, sends the user's email address and a plugin-identifying User-Agent to XposedOrNot when a user is created or changes email.

* **XposedOrNot:** [Service](https://xposedornot.com/) | [Privacy](https://xposedornot.com/privacy.html)

= ipwho.is (optional) =

IP Geolocation sends public IP addresses recorded in the login log or in an incident to ipwho.is, in a background task: at most 20 addresses every five minutes, and no request is made while an admin page is being rendered. There is no request at all for five minutes after an API failure, and the free tier of the API allows 1000 requests a day per site, after which it asks for a pause that the plugin honours. Results are cached for 30 days, and so is an answer that carries no country. The cache also keeps the AS number and the operator name, and the lookup identifies the network behind the use of an application password. Private and reserved ranges are never sent, and developers can replace the lookup through the `login_armor_geoip_lookup` filter. The compromise: the background task is a WordPress scheduled event, so on a site where WP-Cron is disabled and no system cron calls wp-cron.php, the country badges stay empty.

* **ipwho.is:** [Service](https://ipwho.is/) | [Documentation](https://ipwhois.io/documentation)

== Changelog ==

The three most recent releases are summarised here, because wordpress.org shows at most 5000 characters and silently truncates the rest. The complete history, with the reasoning behind each fix, is in CHANGELOG.md in the plugin's repository.

= 2.10.1 =
Security release: ten fixes from a security audit of 2.10.0. Updating is recommended for every site. No setting changes.

* Security - Multisite: an account enrolled in two-factor authentication is now asked for its code on every site of the network, including sites where the module is off. Signing in on such a site skipped the second factor.
* Security - Hidden login URL: a crafted request could still sign in through wp-login.php. It now gets the same 404 as any other.
* Security - Brute force: a successful login cleared the failures of every account from that address. Only the account that signed in is reset now.
* Security - The honeypot now refuses a login even when the password is right.
* Security - Behind a declared proxy, an invalid byte in the forwarding header left the attempt uncounted.
* Security - Request firewall: the REST API exemption and the allow list no longer cover paths that only look like them.
* Security - Bot challenge: the request limit counts IPv6 addresses per /64 network.
* Security - Two-factor: an account that uses an authenticator app is no longer offered the e-mail code, unless its app secret can no longer be read. Confirming a reset requires the right to edit that account, and the confirmation never goes to the account being reset.

= 2.10.0 =
Fixes from an audit of 2.9.0, and what a real headless back end asked for. Works the same on any site.

* Fixed - A lockout reached through the hidden login form now logs the attempt that triggered it, opens the brute-force incident and sends the lockout alert. The lockout page used to end the request before any of them ran.
* Fixed - The REST gate of a locked address also refuses /wp/v2/users when the route comes in a POST body, with a method override, or as an embedded author (_embed, batch).
* Fixed - Application passwords: concurrent refusals could go past the 20 log rows per hour, two passwords used at once could lose a day of learning, switching monitoring back on did not resume the pending review, and a missing table lost uses without repairing itself.
* Fixed - `wp option update` with the string "false" switched a module ON. Boolean settings are now stored as 1 or 0; on update, a stored "false" is kept as what the site was doing (logged in the Activity Log), and "false" switches off from then on.
* New - With WPS Hide Login or Rename wp-login.php active, the hidden login address is refused, or stands down with a notice: never two at once.
* New - Optional system-log lines for fail2ban (Settings > Brute force), documented in the FAQ.
* New - The scheduled digest can go to its own e-mail address, without incident mail.
* New - `define( 'LOGIN_ARMOR_CLI_HIDE_SLUG', true );` keeps the hidden address out of `wp login-armor status` (shown with `--show-slug`).

= 2.9.0 =
Headless back ends and application passwords.

* New - Headless mode (Settings > Headless back end) keeps "Restrict REST API" and "Disable application passwords" off, from the screen, an import or WP-CLI, and says what it turned off. Two Site Health checks in that mode: back end indexed, accounts listed to anonymous visitors.
* New - Failed application passwords are logged, with a Source filter on the Events tab and their own incident type. Only unknown accounts count toward the lockout, and the journal keeps at most 20 rows per address and hour.
* New - Application-password monitoring: which networks each password is used from, on the user's profile, and an alert the first time one is used from a new hosting provider. Networks are identified by confirmed reverse DNS; IP Geolocation, when you turn it on, adds the AS number and the operator.
* Changed - A signed-in administrator, or a valid application password, is no longer refused /wp/v2/users from a locked address.
* Fixed - The lockout gate of the REST API did not recognise the route in the ?rest_route= form, with encoded letters, in capitals or under a custom REST prefix.
* Fixed - Notifications on the plugin screens were drawn without background or border.
* Fixed - The FAQ said the Request Firewall must stay out of blocking mode on a headless back end. It never inspects REST requests.


== Upgrade Notice ==

= 2.10.1 =
Security release, recommended for every site: two-factor authentication on multisite networks, the hidden login URL, the brute-force counter, the honeypot, the request firewall and the bot challenge.

= 2.10.0 =
Fixes from an audit of 2.9.0: a form lockout is now logged and opens its incident, the REST gate of a locked address covers every route form, and "false" written by WP-CLI really switches a setting off. Optional fail2ban lines, a digest recipient of its own.

= 2.9.0 =
Headless mode, logged application-password failures that no longer lock their owner, and an alert when an application password is used from a new hosting provider.

= 2.8.3 =
On Roots Bedrock, or with WordPress in its own directory, the root .htaccess rules of the Hardening tab are now written where the server reads them. No change on a standard install.

= 2.8.2 =
The request firewall now inspects visitors that a proxy on the same server forwards, once that proxy is declared, and the Overview facts follow an attack as it happens. Recommended for sites behind a local proxy.

= 2.8.1 =
"Block PHP in uploads" now works on OpenLiteSpeed too, and Site Health says whether the firewall and the bot challenge block or only watch. Recommended for every site.

= 2.8.0 =
Two-factor recovery by the administrator now works, the login log can no longer go silent after a refused database upgrade, and deleting the hidden URL gives wp-login.php back. Recommended for every site.

= 2.7.10 =
The incident list opens on the open incidents; All, Resolved and Ignored stay in the status filter. Page links keep the observations toggle.

= 2.7.9 =
Filter bars on one height with their list arrows back, counts that agree with their numbers, and the two reset buttons: the integrity panel refreshed, the detection reset recorded in the activity log.

= 2.7.8 =
Fixes being signed out right after signing in when an idle timeout is set, the activity line that stopped before its end, IP addresses broken over two lines in the Events table, and import preview columns one letter wide.

= 2.7.7 =
Fixes text cut off or printed over its neighbour in the Events and Activity tables (on phones and in windows around 1100 to 1220 pixels), the guide panel hidden behind the sponsored block, and several cards cut on phones. Stylesheets only.

= 2.7.6 =
Fixes the end of the Settings tab staying hidden under the "Unsaved changes" bar, that bar's placement on narrow windows, keyboard focus landing under the bars, and sideways scrolling on phones. Stylesheet only.

= 2.7.5 =
Removes the dashed break near the right-hand edge of the activity chart. It was added in 2.7.3 to flag a partial final hour that does not in fact exist, and it read as a gap in the data. The curve is one continuous line again.

= 2.7.4 =
Fixes two things: the activity chart on the Overview showed what looked like a gap in the data while it loaded, and the Activity Log's nightly purge was never re-scheduled if it went missing, so a site could stop deleting old rows for good.

= 2.7.3 =
Fixes a false TAMPERED alarm on the Activity Log: the nightly retention purge broke the integrity chain it was verified against, on every site that kept the module on longer than its retention window. Also corrects the activity chart, which was stretched 1.63 times too tall.

= 2.7.2 =
Fixes three defects an independent review of 2.7.1 found. An AI analysis could be generated, billed and then silently lost on a site with an incomplete table; a malformed bulk request could resolve every incident; and the test guarding that endpoint's access check proved nothing.

= 2.7.1 =
First release to carry the 2.7.0 work. Fixes fourteen defects, three of them serious: an export could call a module off while it was running, a cache could freeze your login decoys so a changed setting did nothing, and saving a hardening rule could report success while the file went unwritten.

= 2.7.0 =
New safe mode: one line in wp-config.php gets you back in when a setting locks you out. Plus a scheduled security digest, eight Site Health tests, a search box in Settings and a Force HTTPS control. Two fixes reach every site: password reset links on apex+www, and a hardening toggle read as ON.

= 2.6.1 =
Reliability release. Your rules in the uploads .htaccess are preserved instead of erased. On multisite, every site is set up and gets its scheduled tasks. Two alerts in the same second no longer cancel one another; critical alerts keep a reserve. Country lookups moved off the admin screen.

= 2.6.0 =
Export your settings as JSON and replay them on your other sites, from the Settings tab or with wp login-armor settings import. Two-factor entries in authenticator apps now carry the site domain, so a long list stays searchable.

= 2.5.3 =
Fixes the "trust this device" checkbox, which could not be ticked because the code field submitted itself on the sixth digit. Incident timelines now show every event that raised the incident, instead of the last ten minutes only.

= 2.5.2 =
Fixes password reset links failing with "this key is no longer valid" when Hide Login is enabled and usernames are e-mail addresses. Recommended for every site using Hide Login.

= 2.5.1 =
Compatibility release. The firewall no longer blocks the requests your site makes to itself, which could break plugins such as SEOPress. Restrict REST API now has an exceptions field, so a plugin needing public REST access no longer requires custom PHP.

= 2.5.0 =
New optional Bot Challenge module: an invisible proof-of-work on the login form, a CAPTCHA alternative with no external service. Off by default; enabling starts in monitor mode. Existing sites unchanged.

= 2.4.8 =
Security follow-up: prevents a misconfigured trusted proxy from becoming a shared lockout identity and completes reliable webhook delivery for audit rows retained under contention.

= 2.4.7 =
Security update: closes proxy-header rate-limit bypass, unauthenticated 2FA recovery email amplification, and unauthenticated HIBP request amplification. Recommended for all installations.

= 2.4.6 =
Fixes the Hide Login custom redirect and restores FSE block styles on protected 404 responses.

= 2.4.5 =
The plugin's own blocks (2FA lockout, honeypot, reserved username) no longer count as failed passwords, so a legitimate user is not locked out while using the correct one. Failed logins now show their real reason. Also fixes the incidents table failing to create on MariaDB 11.7+/MySQL 9.

= 2.4.4 =
Hardening: accurate dashboard threat level, canonical wp_login cycle after 2FA, atomic lockout escalation, SSRF validation before every webhook delivery, and CSV formula-injection neutralisation. Recommended for all installations.

= 2.4.3 =
Security: mandatory 2FA is enforced after grace expiry, with an administrator recovery path. Also blocks TOTP replay, tightens webhook SSRF validation, and neutralises attacker input before AI incident analysis. Recommended for all installations.

= 2.4.2 =
Coherence release: cleaner deactivation and uninstall, a confirmation before disabling Two-Factor, faster brute-force lookups, and a heads-up when a front-end login plugin (e.g. Ultimate Member) is active. No behaviour change on standard installs. Recommended for all.

= 2.4.1 =
Fixes a "critical error" during password recovery when another plugin re-fires a WordPress hook with an off-contract argument type. Strict parameter hints relaxed, with internal guards, on every core-hook callback plugin-wide. Neutral on standard calls. Recommended for all installs.

= 2.4.0 =
New: an optional Request Firewall (8G-inspired PHP filter) that blocks malicious requests - off by default, starts in monitor mode (logs without blocking), admins never filtered. Plus a first-run onboarding wizard with a one-click safe baseline. All opt-in; existing sites unchanged.

= 2.3.0 =
Account-security release: Password Policy (length/complexity + reject breached passwords via privacy-preserving HIBP), Session Management (idle timeout, max lifetime, single session), and opt-in IP Geolocation. All off by default; nothing changes until you enable it.

= 2.2.0 =
New: the AI Security Briefing turns your last 30 days of activity into a plain-language verdict, an IP picture and prioritised actions, on top of a deterministic facts snapshot. Built on the WordPress 7 native AI Client - uses your own connector, no API key stored, runs on click.

= 2.1.26 =
Fixes email/backup 2FA bouncing to "session expired" on browsers that don't return the verification cookie on submit (some Chrome setups; Firefox worked). The form now also carries the session token, so login works regardless. Recommended if Email 2FA is enabled. Security unchanged.

= 2.1.25 =
Fixes email/backup two-factor verification being rejected ("session expired") in some browsers, notably Chrome, while Firefox worked. The form is now uncached and authenticated by the signed same-site cookie. Recommended if Email 2FA is enabled.

= 2.1.24 =
Fixes a fatal error (HTTP 500 / "network error") during authenticator-app (TOTP) setup on hosts whose wp-config.php does not define AUTH_KEY, such as some Infomaniak installs. Recommended if Two-Factor is enabled. Existing setups are unaffected.

= 2.1.23 =
Fixes the two-factor login screen: the "use a different method" links now work (and email a fresh code when switching to Email), expired/locked sessions explain themselves, and the authenticator-setup button reports errors. Recommended for 2FA users.

= 2.1.22 =
Fixes a Security Score that under-counted active modules: Brute Force and Detection (on by default) are now scored correctly, so the header, the score number and the module list agree. Display and scoring only: recommended for all installs.

= 2.1.21 =
Cosmetic patch: cleaner user-agent labels in the Events table: Jetpack/WordPress.com clients are recognised, and long agents are trimmed at a word boundary with an ellipsis instead of a chopped-off string with a dangling parenthesis.

= 2.1.20 =
Migration-friendly integrity: a security-key change now shows an amber "Keys changed" advisory with one-click chain re-baseline instead of a false "TAMPERED" alarm. Adds an XML-RPC blind-spot warning when Hide Login is on but XML-RPC stays open. Completes the French translation.

= 2.1.19 =
Clearer attack-type labels + descriptions on incidents, French translation of the visible admin tabs, translatable toast notifications, and a fix for the Activity Log integrity badge staying "UNVERIFIED" after a successful verify. Recommended for all installs.

= 2.1.18 =
Patch. Fixes "Select all" / bulk actions when incidents are all resolved (checkboxes now on every card) and only labels the attack vector for XML-RPC/REST (no more misleading "via login form"). Recommended for 2.1.17 users.

= 2.1.17 =
Feature release. Incidents now show the attack vector (XML-RPC / REST / login form), so you can spot which attempts bypass your hidden login URL, plus bulk mark-resolved/ignore. Adds a vector column to the incidents table (auto migration). Recommended for all installs.

= 2.1.16 =
Bug fix release from an external audit. Fixes plain-permalinks compat (Hide Login URL, REST API allowlist), restores activity-log coverage for 2FA, frontend registration and password reset, and extends Honeypot to WooCommerce + frontend login forms. Recommended for all installs.

= 2.1.15 =
Fixes a fatal TypeError when third-party plugins (e.g. WP Fastest Cache) call WordPress URL builders with off-contract argument types. Strict parameter hints relaxed on seven callbacks; return types unchanged. Neutral on canonical WP calls.

= 2.1.14 =
Bug fix. The prevent_author_enum hardening toggle no longer blocks the legitimate ?author=N filter in wp-admin Posts/Pages lists ("All / Mine / <author>" links). Public enumeration block unchanged. Three-line fix.

= 2.1.13 =
Bug fix. Silent 2FA failure on installs with permalink_structure without trailing slash (e.g. /%postname%): the verify cookie path mismatched the request path after handle_loaded's normalisation. Fixed cookie path to omit trailing slash. Neutral on trailing-slash installs.

= 2.1.12 =
Bug fix. Hide Login rendered without CSS when both apex and www routed to the same WP (shared hosting). Two fixes: canonical-host 301 in Hide Login + host-aware CSP in Login Page Security Headers. Neutral on single-host installs. New filter login_armor_canonical_host_redirect for opt-out.

= 2.1.11 =
Bug fix for multisite + domain mapping: the Hide Login URL is now host-aware (picks home_url or site_url from HTTP_HOST), fixing a 2.1.9 regression where mapped subsites redirected to /wp-admin/ (404). Standard and headless installs keep working.

= 2.1.10 =
Cosmetic fix. The 404 page served when an anonymous visitor hits `/wp-admin/` with Hide Login enabled now renders as a proper WordPress 404 (body class `error404`, SEO `noindex` meta, theme 404 template) instead of a half-bootstrapped page. No security or functional change.

= 2.1.9 =
Bug fix. Hide Login now builds the rewritten login URL from `site_url()` (matching `wp_login_url()` in WP core) instead of `home_url()`. Fixes silent breakage on multisite headless, WordPress in subdirectory, and reverse-proxy installs. Neutral on standard installs.

= 2.1.8 =
Hygiene release after a full 2.1.7 audit. Three LOW fixes: the webhook stats query no longer warns on fresh installs, the lockout_window option is cleaned on uninstall, and five missing French translations were added. No end-user-visible change.

= 2.1.7 =
Preventive: hardens the Email 2FA enrollment flow. Failed `wp_mail()` no longer leaves a half-committed 2FA state, and a new pre-activation modal forces a real test email + a safety-net check before the user can lock themselves out. Recommended for every install where Email-based 2FA is enabled.

= 2.1.6 =
Preventive release. Eliminates a latent V2.1.3-style fatal risk in the TwoFactor module. Finishes the uninstall.php cleanup (zero residual data). Surfaces Activity Log integrity coverage scope in admin UI. No new features, no DB migration.

= 2.1.4 =
Critical hotfix: 2.1.3 fatal-errored on every fresh install (Class "LoginArmor\ActivityLog\ActivityLog" not found). Sites with Activity Log already enabled were unaffected. Recommended for every install, urgent for new installs.

= 2.1.3 =
Critical hotfix: Hardening "Hide WP version" was stripping cache-buster from our own assets, so updates past 2.1.0 were invisible behind hosting CDNs (LiteSpeed LSADC, Cloudflare). Recommended for every install.

= 2.1.2 =
Critical hotfix: the Settings tab fatal-errored on every fresh install that had not yet enabled the Activity Log module (Class WebhookDispatcher not found). Recommended for every install.

= 2.1.1 =
Activity Log integrity: every row is HMAC-signed and chained, detects any tampering. Optional signed webhook forwarding (SIEM / Slack / Datadog / any HTTPS). New WP-CLI verify-chain. Bundles 6 hardening fixes. Migration automatic. Recommended for every install.

= 2.1.0 =
Security: 2FA pending token moved from URL query string to a signed HttpOnly + SameSite=Strict cookie. Closes URL-leak (browser history / Referer / access logs) and DB-leak (clear token no longer in wp_options). Recommended for every install with 2FA enabled.

= 2.0.5 =
Security audit pass: REST author-enum scope, optional HSTS, IPv6 subnet fix, 0.0.0.0 placeholder DoS skip, .htaccess admin-rules preservation. No regression. Recommended.

= 2.0.4 =
Real fix for the lockout 429 page on hosts with a public page cache (LiteSpeed Cache, WP Rocket, Cloudflare). Recommended after the 2.0.1-2.0.3 sequence.

= 2.0.3 =
Hotfix: HTTP/2 stream termination on LiteSpeed/LSAPI for the branded lockout page. Recommended.

= 2.0.2 =
Critical fix: 429 branded lockout page now reaches the browser. Recommended.

= 2.0.1 =
Branded 429 lockout page on the triggering attempt + Reset Stats UI + correct WP.org banner/icon. Recommended.

= 2.0.0 =
First WordPress.org release of the V2 line. Eight independent security modules. Recommended.
