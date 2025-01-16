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

To install mokey download a copy of the pre-compiled binary [here](https://github.com/ubccr/mokey/releases).

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

Create a user account and role in FreeIPA with the "Modify users and Reset
passwords" privilege. This user account will be used by the mokey application
to reset users passwords. The "Modify Users" permission also needs to have the
"ipauserauthtype" enabled. Run the following commands (requires ipa-admintools
to be installed):

```
$ mkdir /etc/mokey/private
$ kinit adminuser
$ ipa role-add 'Mokey User Manager' --desc='Mokey User management'
$ ipa role-add-privilege 'Mokey User Manager' --privilege='User Administrators'
$ ipa user-add mokeyapp --first Mokey --last App
$ ipa role-add-member 'Mokey User Manager' --users=mokeyapp
$ ipa permission-mod 'System: Modify Users' --includedattrs=ipauserauthtype
$ ipa-getkeytab -s [your.ipa-master.server] -p mokeyapp -k /etc/mokey/private/mokeyapp.keytab
$ chmod 640 /etc/mokey/private/mokeyapp.keytab
$ chgrp mokey /etc/mokey/private/mokeyapp.keytab
```

Edit mokey configuration file and set path to keytab file. The values for
`token_secret` and `csrf_secret` will be automatically generated for you if
left blank. Set these secret values if you'd like sessions to persist after a restart.
For other site specific config options [see here](https://github.com/ubccr/mokey/blob/main/mokey.toml.sample):

```
$ vim /etc/mokey/mokey.toml
# Path to keytab file
keytab = "/etc/mokey/private/mokeyapp.keytab"

# Secret key for branca tokens. Must be 32 bytes. To generate run:
#    openssl rand -hex 32 
token_secret = ""

# CSRF token secret key. Should be a random string
csrf_secret = ""
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
$ git clone https://github.com/ubccr/mokey
$ cd mokey
$ go build .
```

## License

mokey is released under a BSD style license. See the LICENSE file.
