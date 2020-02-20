===============================================================================
FreeIPA self-service account management tool
===============================================================================

.. image:: docs/mokey-logo.png

------------------------------------------------------------------------
What is mokey?
------------------------------------------------------------------------

mokey is web application that provides self-service user account management
tools for `FreeIPA <https://www.freeipa.org>`_. The motivation for this project was
to implement the self-service account creation and password reset functionality
missing in FreeIPA.  This feature is not provided by default in FreeIPA, see
`here <https://www.freeipa.org/page/Self-Service_Password_Reset>`_ for more info
and the rationale behind this decision. mokey is not a FreeIPA plugin but a
complete standalone application that uses the FreeIPA JSON API.  mokey requires
no changes to the underlying LDAP schema and uses a MariaDB database to store
access tokens. The user experience and web interface can be customized to fit
the requirements of an organization's look and feel. mokey is written in Go and
released under a modified BSD license. For screenshots
`see here <docs/>`_

------------------------------------------------------------------------
Project status
------------------------------------------------------------------------

mokey should be considered alpha software and used at your own risk. There are
inherent security risks in providing features like self-service password resets
and can make your systems vulnerable to abuse.

------------------------------------------------------------------------
Features
------------------------------------------------------------------------

- Account Signup
- Forgot/Change Password
- Add/Remove SSH Public Keys
- Add/Remove TOTP Tokens
- Enable/Disable Two-Factor Authentication
- Hydra Consent/Login Endpoint for OAuth/OpenID Connect
- PGP/Mime signed emails
- Easy to install and configure (requires no FreeIPA/LDAP schema changes)

------------------------------------------------------------------------
Requirements
------------------------------------------------------------------------

- FreeIPA v4.5.0
- MariaDB/MySQL
- Linux x86_64 (CentOS 7.x preferred)
- Redis (optional)
- Hydra v1.0.0 (optional)

------------------------------------------------------------------------
Upgrading
------------------------------------------------------------------------

Update to latest rpm release::

    $ rpm -Uvh mokey-0.x.x-x.el7.centos.x86_64.rpm

If upgrading from v0.0.5 or earlier need to run the following command to update
database schema::

    $ mysql -u root -p mokey < /usr/share/mokey/ddl/upgrade-to-v0.0.6.sql

*WARNING* Security questions have been removed in v0.5.1 and are no longer
supported. Please consider using TOTP tokens in FreeIPA for Two-Factor
authentication.

------------------------------------------------------------------------
Install
------------------------------------------------------------------------

*Note mokey needs to be installed on a machine already enrolled in FreeIPA.
It's also recommended to have the ipa-admintools package installed. Enrolling
a host in FreeIPA is outside the scope of this document. These docs also assume
you're running CentOS 7.x*

Install the RPM release `here <https://github.com/ubccr/mokey/releases>`_::

  $ rpm -Uvh mokey-0.x.x-x.el7.centos.x86_64.rpm

Install MariaDB and/or setup database for mokey::

    $ yum install mariadb-server
    $ systemctl restart mariadb
    $ systemctl enable mariadb
    $ mysql_secure_installation
    $ Root Password:  [Create a good, strong password here]
    $ Remove anonymous users? [Y/n] y
    $ Disallow root login remotely? [Y/n] y
    $ Remove test database and access to it? [Y/n] y
    $ Reload privilege tables now? [Y/n] y
    $ mysql -u root -p
    $ mysql> create database mokey;
    $ mysql> grant all on mokey.* to [user]@localhost identified by '[pass]'
    $ mysql> exit
    $ mysql -u root -p mokey < /usr/share/mokey/ddl/schema.sql

Create a user account and role in FreeIPA with the "Modify users and Reset
passwords" privilege. This user account will be used by the mokey application
to reset users passwords. The "Modify Users" permission also needs to have the
"ipauserauthtype" enabled. Run the following commands (requires ipa-admintools
to be installed)::

    $ mkdir /etc/mokey/keytab
    $ kinit adminuser
    $ ipa role-add 'Mokey User Manager' --desc='Mokey User management'
    $ ipa role-add-privilege 'Mokey User Manager' --privilege='User Administrators'
    $ ipa user-add mokeyapp --first Mokey --last App
    $ ipa role-add-member 'Mokey User Manager' --users=mokeyapp
    $ ipa-getkeytab -s [your.ipa-master.server] -p mokeyapp -k /etc/mokey/keytab/mokeyapp.keytab
    $ chmod 640 /etc/mokey/keytab/mokeyapp.keytab
    $ chgrp mokey /etc/mokey/keytab/mokeyapp.keytab


Edit mokey configuration file. Add user/pass for MariaDB database, path to
keytab, auth and encryption keys::

    $ vim /etc/mokey/mokey.yaml
    dsn: "user:pass@/dbname?parseTime=true"
    keytab: "/etc/mokey/keytab/mokeyapp.keytab"
    ktuser: "mokeyapp"
    auth_key: "32 or 64 bytes random key"
    enc_key: "16, 24, or 32 byte random key"
    [ edit to taste ]

It's highly recommended to run mokey using HTTPS. You'll need an SSL
cert/private_key either using FreeIPA's PKI, self-signed, or from a commercial
certificate authority. Creating SSL certs is outside the scope of this
document. You can also run mokey behind haproxy or Apache/Nginx.

Copy your SSL cert/private_key to the following directories and set correct
paths in ``/etc/mokey/mokey.yaml``. The mokey binary will run as non-root user
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
Customizing templates
------------------------------------------------------------------------

The templates for the web interface and emails are installed by default in
/usr/share/mokey/templates. Edit to taste and restart mokey.

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

Next, edit ``/etc/mokey/mokey.yaml``::

    $ vi /etc/mokey/mokey.yaml
    pgp_sign: true
    pgp_key: "/etc/mokey/gpg/example-key.gpg"
    pgp_passphrase: "my-secret"

    $ systemctl restart mokey

Publish your public key to a keyserver or other means. Emails will now be PGP
signed using your private key. Users can verify the authenticity of the emails
sent from mokey using your public key.

------------------------------------------------------------------------
Configure rate limiting
------------------------------------------------------------------------

mokey can optionally be configured to rate limit certain paths (login and
forgot password) to limit the number of requests within a given time period. To
enable rate limiting first install redis then update ``/etc/mokey/mokey.yaml``.

Install Redis (install from EPEL)::

    $ yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
    $ yum install redis
    $ systemctl restart redis
    $ systemctl enable redis

Edit ``/etc/mokey/mokey.yaml`` and restart::

    $ vi /etc/mokey/mokey.yaml
    rate_limit: true

    $ systemctl restart mokey

------------------------------------------------------------------------
SSH Public Key Management
------------------------------------------------------------------------

mokey allows users to add/remove ssh public keys. Servers that are enrolled in
FreeIPA can be configured to have sshd lookup users public keys in LDAP by
adding the following lines in /etc/ssh/sshd_config and restarting sshd::

    AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys
    AuthorizedKeysCommandUser nobody

------------------------------------------------------------------------
Hydra Consent and Login Endpoint for OAuth/OpenID Connect
------------------------------------------------------------------------

mokey implements the login/consent flow for handling challenge requests from
Hydra. This serves as the bridge between Hydra and FreeIPA identity provider.
For more information on Hydra and the login/consent flow see `here
<https://www.ory.sh/docs/hydra/oauth2>`_.

To configure the Hydra login/consent flow set the following variables in
``/etc/mokey/mokey.yaml``::

    hydra_admin_url: "https://localhost:4444"

Any OAuth clients configured in Hydra will be authenticated via mokey using
FreeIPA as the identity provider. For an example OAuth 2.0/OIDC client
application see `here <examples/mokey-oidc/main.go>`_.

------------------------------------------------------------------------
Building from source
------------------------------------------------------------------------

First, you will need Go v1.13 or greater. Clone the repository::

    $ git clone https://github.com/ubccr/mokey
    $ cd mokey
    $ go build .

------------------------------------------------------------------------
License
------------------------------------------------------------------------

mokey is released under a BSD style license. See the LICENSE file.
