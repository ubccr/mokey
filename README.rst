===============================================================================
FreeIPA self-service account management tool
===============================================================================

.. image:: docs/mokey-logo.png

------------------------------------------------------------------------
What is mokey?
------------------------------------------------------------------------

mokey is web application that provides self-service user account management
tools for `FreeIPA <http://freeipa.org>`_. The motivation for this project was
to implement the self-service password reset functionality missing in FreeIPA.
This feature is not provided by default in FreeIPA, see `here <http://www.freeipa.org/page/Self-Service_Password_Reset>`_ 
for more info and the rationale behind this decision. mokey is not a FreeIPA
plugin but a complete standalone application that uses the FreeIPA JSON API.
mokey requires no changes to the underlying LDAP schema and uses a MariaDB
database to store security questions and access tokens. The user experience and
web interface can be customized to fit the requirements of an organization's
look and feel. mokey is written in Go and released under a modified BSD
license.

------------------------------------------------------------------------
Project status
------------------------------------------------------------------------

mokey should be considered alpha software and used at your own risk. There are
inherent security risks in providing features like self-service password resets
and can make your systems vulnerable to abuse. 

------------------------------------------------------------------------
Features
------------------------------------------------------------------------

- Account Activation / First time password setup
- Forgot Password
- Change Password / Set security question
- Add SSH Public Keys
- Two-Factor Authentication (TOTP)
- Easy to install and configure (requires no FreeIPA/LDAP schema changes)
- PGP/Mime signed emails

------------------------------------------------------------------------
Requirements
------------------------------------------------------------------------

- FreeIPA v4.1.0
- SQLite
- Linux x86_64 (CentOS 7.x preferred)
- Redis (optional)

------------------------------------------------------------------------
Install
------------------------------------------------------------------------

*Note mokey needs to be installed on a machine already enrolled in FreeIPA.
It's also recommended to have the ipa-admintools package installed. Enrolling
a host in FreeIPA is outside the scope of this document. These docs also assume
you're running CentOS 7.x*

Install the RPM release `here <https://github.com/ubccr/mokey/releases>`_::

  $ rpm -Uvh mokey-0.x.x-1.el7.centos.x86_64.rpm

Create the initial sqlite database:

    $ yum install sqlite
    $ sqlite3 /path/to/database.file < /usr/share/mokey/ddl/sqlite.sql

Create a user account and role in FreeIPA with the "Modify users and Reset
passwords" privilege. This user account will be used by the mokey application
to reset users passwords. Run the following commands (requires ipa-admintools
to be installed)::

    $ mkdir /etc/mokey/keytab
    $ kinit adminuser
    $ ipa role-add 'Mokey User Manager' --desc='Mokey User management'
    $ ipa role-add-privilege 'Mokey User Manager' --privilege='Modify users and Reset passwords'
    $ ipa user-add mokeyapp --first Mokey --last App
    $ ipa role-add-member 'Mokey User Manager' --users=mokeyapp
    $ ipa-getkeytab -s [your.ipa-master.server] -p mokeyapp -k /etc/mokey/keytab/mokeyapp.keytab
    $ chmod 640 /etc/mokey/keytab/mokeyapp.keytab
    $ chgrp mokey /etc/mokey/keytab/mokeyapp.keytab
    

Edit mokey configuration file. Add user/pass for MariaDB database, path to
keytab, and secret key::

    $ vim /etc/mokey/mokey.yaml 
    dsn: "user:pass@/dbname?parseTime=true"
    keytab: "/etc/mokey/keytab/mokeyapp.keytab"
    secret_key: "some really long random string"
    [ edit to taste ]

It's highly recommended to run mokey using HTTPS. You'll need an SSL
cert/private_key either using FreeIPA's PKI, self-signed, or from a commercial
certificate authority. Creating SSL certs is outside the scope of this
document. You can also run mokey behind haproxy or Apache/Nginx.

Copy your SSL cert/private_key to the following directories and set correct
paths in /etc/mokey/mokey.yaml. The mokey binary will run as non-root user
(mokey) so need to ensure file perms are set correctly::

    $ mkdir /etc/mokey/{cert,private}
    $ cp my.crt /etc/mokey/cert/my.crt
    $ cp my.key /etc/mokey/private/my.key
    $ chmod 640 /etc/mokey/private/my.key
    $ chgrp mokey /etc/mokey/private/my.key

Start mokey service::

    $ systemctl restart mokey
    $ systemctl enable mokey

Open a web browser to: https://localhost:8080. By default, mokey will listen on
port 8080.

To view mokey system logs run::

    $ journalctl -u mokey

------------------------------------------------------------------------
Upgrading
------------------------------------------------------------------------

Upgrade to v0.0.5 requires manually upgrading the database as follows::

    $ sqlite3 /path/to/database.file < /usr/share/mokey/ddl/upgrade-v0.0.5.sql

------------------------------------------------------------------------
Customizing templates
------------------------------------------------------------------------

The templates for the web interface and emails are installed by default in
/usr/share/mokey/templates. Edit to taste and restart mokey.

------------------------------------------------------------------------
Getting Started with mokey cli tools
------------------------------------------------------------------------

- Account Activation / First time password setup. Use case: create new user and
  send them an email link to setup their password and security question::

    $ kinit adminuser
    $ ipa user-add --first="Jesse" --last="Pinkman" --email="jp@example.com" capncook
    $ mokey newacct --uid capncook 
    (An email will be sent to jp@example.com with a link to setup their password)
    
- Reset user password. Use case: user forgot their password, send the user an
  email link to reset their password using their previously set security
  question. Users can also initiate a password reset using the "Forgot
  Password" link in the web interface::

    $ kinit adminuser
    $ mokey resetpw --uid capncook 
    (An email will be sent to jp@example.com with a link to reset their password)

- Remove TOTP token. Use case: user lost access to their TOTP mobile app and is
  locked out. This command will remove any TOTP tokens and the user will be
  required to login with their security question::

    $ kinit adminuser
    $ mokey removeotp --uid capncook 

------------------------------------------------------------------------
Configure PGP/Mime email 
------------------------------------------------------------------------

mokey can be configured to send PGP/Mime signed email messages. First generate
a gpg keypair::

    $ gpg --gen-key
    $ gpg --armor --output example-key.gpg --export-secret-keys example@example.edu
    $ gpg --armor --output example-pub.gpg --export example@example.edu
    $ mkdir /etc/mokey/gpg
    $ cp example-key.gpg /etc/mokey/gpg
    $ chmod 640 /etc/mokey/gpg/example-key.gpg
    $ chgrp mokey /etc/mokey/gpg/example-key.gpg

Next, edit /etc/mokey/mokey.yaml::

    $ vi /etc/mokey/mokey.yaml
    pgp_sign: true
    pgp_key: "/etc/mokey/gpg/example-key.gpg"
    pgp_passphrase: "my-secret"

    $ systecmtl restart mokey

Publish your public key to a keyserver or other means. Emails will now be PGP
signed using your private key. Users can verify the authenticity of the emails
sent from mokey using your public key.

------------------------------------------------------------------------
Configure rate limiting
------------------------------------------------------------------------

mokey can optionally be configured to rate limit certain paths (login and
forgot password) to limit the number of requests within a given time period. To
enable rate limiting first install redis then update /etc/mokey/mokey.yaml.

Install Redis (install from EPEL)::

    $ yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
    $ yum install redis
    $ systemctl restart redis
    $ systecmtl enable redis

Edit /etc/mokey/mokey.yaml and restart::

    $ vi /etc/mokey/mokey.yaml
    rate_limit: true

    $ systecmtl restart mokey

------------------------------------------------------------------------
SSH Public Key Management
------------------------------------------------------------------------

mokey allows users to add/remove ssh public keys. Servers that are enrolled in
FreeIPA can be configured to have sshd lookup users public keys in LDAP by
adding the following lines in /etc/ssh/sshd_config and restarting sshd::

    AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys
    AuthorizedKeysCommandUser nobody

------------------------------------------------------------------------
Building from source
------------------------------------------------------------------------

First, you will need:

- `glide <https://glide.sh/>`_ to manage project's dependencies.
- The krb5-libs/GSSAPI lib installed on your compilation system

Clone the repository in your $GOPATH::

    $ git clone https://github.com/ubccr/mokey $GOPATH/src/github.com/ubccr/mokey

In the project folder you can now resolve the dependencies and build mokey::

    $ glide install
    $ go build

------------------------------------------------------------------------
License
------------------------------------------------------------------------

mokey is released under a BSD style license. See the LICENSE file. 
