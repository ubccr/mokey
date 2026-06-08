# FreeIPA self-service account management tool

## What is mokey?

mokey is web application that provides self-service user account management
tools for [FreeIPA](https://www.freeipa.org). The motivation for this project was
to implement the self-service account creation and password reset functionality
missing in FreeIPA.  This feature is not provided by default in FreeIPA, see
[here](https://www.freeipa.org/page/Self-Service_Password_Reset) for more info
and the rationale behind this decision. mokey is not a FreeIPA plugin but a
complete standalone application that uses the FreeIPA JSON API.  mokey requires
no changes to the underlying LDAP schema and uses a MariaDB database to store
access tokens. The user experience and web interface can be customized to fit
the requirements of an organization's look and feel. mokey is written in Go and
released under a modified BSD license.

## Project status

mokey should be considered alpha software and used at your own risk. There are
inherent security risks in providing features like self-service password resets
and can make your systems vulnerable to abuse.

## Features

- Account Signup
- Forgot/Change Password
- Add/Remove SSH Public Keys
- Add/Remove TOTP Tokens
- Enable/Disable Two-Factor Authentication
- Hydra Consent/Login Endpoint for OAuth/OpenID Connect
- Easy to install and configure (requires no FreeIPA/LDAP schema changes)

## Requirements

- FreeIPA v4.6.8 or greater
- Linux x86_64 
- Redis (optional)
- Hydra v1.0.0 (optional)

## Install

Note: mokey needs to be installed on a machine already enrolled in FreeIPA.
It's also recommended to have the ipa-admintools package installed. Enrolling a
host in FreeIPA is outside the scope of this document.

To install mokey download a copy of the pre-compiled binary [here](https://github.com/tubby1981/mokey/releases).

tar.gz archive:

```
$ tar xvzf mokey-VERSION-linux-x86_64.tar.gz 
```

deb, rpm packages:

```
$ sudo dpkg -i mokey_VERSION_amd64.deb

$ sudo rpm -ivh mokey-VERSION-amd64.rpm
```

## Setup and configuration

Create a dedicated service account in FreeIPA for mokey. All FreeIPA API calls
run as this account using a keytab (`site.ktuser` / `site.keytab` in
`mokey.toml`).

### Required FreeIPA privileges

The service account needs privileges to manage users and passwords. The
`User Administrators` privilege covers most day-to-day operations (user lookup,
password reset, MFA, SSH keys, and so on).

For password reset via email, mokey also needs to read password policies so it
can set `krbPasswordExpiration` correctly after an admin password change. Add
the **Password Policy Readers** privilege. Without it, `ipa pwpolicy-show`
fails for the service account and mokey falls back to
`accounts.password_max_life_days` in `mokey.toml`.

| Privilege | Purpose |
|-----------|---------|
| User Administrators | User management, password reset, MFA, SSH keys |
| Password Policy Readers | Read effective password policy (`maxlife`) per user |

The **System: Modify Users** permission must include the `ipauserauthtype`
attribute (required for MFA enable/disable).

### FreeIPA setup

Run the following on an IPA server (requires `ipa-admintools`):

```
$ mkdir /etc/mokey/private
$ kinit adminuser
$ ipa role-add 'Mokey User Manager' --desc='Mokey user management'
$ ipa role-add-privilege 'Mokey User Manager' --privileges='User Administrators'
$ ipa role-add-privilege 'Mokey User Manager' --privileges='Password Policy Readers'
$ ipa user-add mokeyapp --first Mokey --last App
$ ipa role-add-member 'Mokey User Manager' --users=mokeyapp
$ ipa permission-mod 'System: Modify Users' --includedattrs=ipauserauthtype
$ ipa-getkeytab -s [your.ipa-master.server] -p mokeyapp -k /etc/mokey/private/mokeyapp.keytab
$ chmod 640 /etc/mokey/private/mokeyapp.keytab
$ chgrp mokey /etc/mokey/private/mokeyapp.keytab
```

Verify the service account can read password policies:

```
$ kinit -kt /etc/mokey/private/mokeyapp.keytab mokeyapp
$ ipa pwpolicy-show --user=someuser
$ kdestroy
```

If `pwpolicy-show` returns *password policy not found*, the role is missing
**Password Policy Readers** or the user is not a member of the role. As a
fallback, set `password_max_life_days` in `mokey.toml` to match your IPA policy
(for example `183`).

### mokey configuration

Edit `/etc/mokey/mokey.toml`. Set the keytab path and service account name. The
values for `token_secret` and `csrf_secret` are generated automatically if left
blank. Set them explicitly if you want sessions and tokens to persist across
restarts. For all options see
[mokey.toml.sample](https://github.com/tubby1981/mokey/blob/main/mokey.toml.sample).

```
$ vim /etc/mokey/mokey.toml

[site]
# User account for the mokey service (must match keytab principal)
ktuser = "mokeyapp"
keytab = "/etc/mokey/private/mokeyapp.keytab"

# Secret key for branca tokens. Must be 32 bytes. To generate run:
#    openssl rand -hex 32
token_secret = ""

# CSRF token secret key. Should be a random string
csrf_secret = ""

[accounts]
# Fallback when pwpolicy_show is unavailable to the service account.
# Per-user IPA policy is used automatically when mokeyapp can read it.
password_max_life_days = 183

# Fallback password validation limits when IPA policy cannot be read.
# min_passwd_len and min_passwd_classes in mokey.toml are used only as fallback;
# effective Min length and Character classes come from each user's IPA policy.
```

It's highly recommended to run mokey using HTTPS. You'll need an SSL
cert/private_key either using FreeIPA's PKI, self-signed, or from a commercial
certificate authority. Creating SSL certs is outside the scope of this
document. You can also run mokey behind haproxy or Apache/Nginx.

Start mokey service:

```
$ systemctl restart mokey
$ systemctl enable mokey
```

## SSH Public Key Management

mokey allows users to add/remove ssh public keys. Servers that are enrolled in
FreeIPA can be configured to have sshd lookup users public keys in LDAP by
adding the following lines in /etc/ssh/sshd_config and restarting sshd:

    AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys
    AuthorizedKeysCommandUser nobody

## Hydra Consent and Login Endpoint for OAuth/OpenID Connect

mokey implements the login/consent flow for handling challenge requests from
Hydra. This serves as the bridge between Hydra and FreeIPA identity provider.
For more information on Hydra and the login/consent flow see [here](https://www.ory.sh/docs/hydra/oauth2).

To configure the Hydra login/consent flow set the following variables in
`/etc/mokey/mokey.toml`:

```
[hydra]
admin_url = "http://127.0.0.1:4445"
login_timeout = 86400
fake_tls_termination = true
```

Any OAuth clients configured in Hydra will be authenticated via mokey using
FreeIPA as the identity provider. For an example OAuth 2.0/OIDC client
application see [here](examples/mokey-oidc/main.go).

## Translations

mokey supports multiple languages for its interface and email templates. Default are English and Dutch supported.

### Configuring Translations

1. **Place translation files**  
   Translation files should be placed in `/etc/mokey/translations/`.  
   For example:  
   - `english.toml` for English translations  
   - `dutch.toml` for Dutch translations  

2. **Update the configuration file**  
   Add the following options to `/etc/mokey/mokey.toml`:  
   ```toml
   # Default language for the site
   # Languages supported: English (english), Dutch (dutch)
   # Default is english
   default_language = "english"

   # Directory where translations can be placed
   translations_dir = "/etc/mokey/translations"
   ```

3. **Create custom translations** 
   Users can translate mokey into their own language by creating a new .toml file in the translations_dir and referencing it in the default_language configuration. This allows for complete customization of the interface and email templates in the preferred language.

## Building from source

First, you will need Go v1.21 or greater. Clone the repository:

```
$ git clone https://github.com/tubby1981/mokey
$ cd mokey
$ go build .
```

## License

mokey is released under a BSD style license. See the LICENSE file.
