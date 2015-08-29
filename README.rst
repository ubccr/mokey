===============================================================================
mokey - FreeIPA self-service account managment tool
===============================================================================

mokey is web application that provides self-service user account management
tools for FreeIPA. The motivation for this project was to implement the
self-service password reset functionality missing in FreeIPA. This feature is
not provided by default in FreeIPA, see `here <http://www.freeipa.org/page/Self-Service_Password_Reset>`_ 
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
- Easy to install and configure (requires no FreeIPA/LDAP schema changes)
- PGP/Mime signed emails

------------------------------------------------------------------------
Requirements
------------------------------------------------------------------------

- FreeIPA v4.1.0
- MariaDB/MySQL
- Redis
- Linux x86_64 (CentOS 7.1 preferred)

------------------------------------------------------------------------
Install
------------------------------------------------------------------------

*Note mokey needs to be installed on a machine already enrolled in FreeIPA.
Enrolling a host in FreeIPA is outside the scope of this document. These docs
also assume you're running CentOS 7.1*

Install the RPM release `here <https://github.com/ubccr/mokey/releases>`_::

  $ rpm -Uvh mokey-0.0.2-1.el7.centos.x86_64.rpm

Install MariaDB and/or setup database for mokey::

    $ yum install mariadb-server
    $ systemctl restart mariadb
    $ systemctl enable mariadb
    $ mysqladmin -u root password 'mypass'
    $ mysql -u root -p
    $ mysql> create database mokey;
    $ mysql> grant all on mokey.* to [user]@localhost identified by '[pass]'
    $ mysql> exit
    $ mysql -u root -p mokey < /usr/share/mokey/ddl/schema.sql

Install Redis (install from EPEL)::

    $ yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
    $ yum install redis
    $ systemctl restart redis
    $ systecmtl enable redis

Configure mokey (add user/pass for MariaDB database)::

    $ vim /etc/mokey/mokey.yaml 
    dsn: "user:pass@/dbname?parseTime=true"
    [ edit to taste ]

It's highly recommended to run mokey using HTTPS. You'll need an SSL
cert/private_key either using FreeIPA's PKI, self-signed, or a commercial
certificate authority. Creating SSL certs is outside the scope of this
document. You can also run mokey behind haproxy or Apache/Nginx. This document
describes how to run mokey using haproxy and SSL passthrough. 

Copy your SSL cert/private_key to the following directories and set correct
paths in /etc/mokey/mokey.yaml. The mokey binary will run as non-root user
(mokey) so need to ensure file perms are set correctly::

    $ mkdir /etc/mokey/{cert,private}
    $ cp my.crt /etc/mokey/cert/my.crt
    $ cp my.key /etc/mokey/private/my.key
    $ chmod 640 /etc/mokey/private/my.key
    $ chgrp mokey /etc/mokey/private/my.key


Install haproxy. This will listen on port 443 and forward SSL requests to mokey
process using SNI TLS extensions. This is referred to as SSL passthrough::

    $ yum install haproxy
    $ vim /etc/haproxy/haproxy.cfg
    #---------------------------------------------------------------------
    # main https frontend which proxys to the backends
    #---------------------------------------------------------------------
    frontend  https-in
        bind *:443
        mode tcp
        option socket-stats
        tcp-request inspect-delay 5s
        tcp-request content accept if { req_ssl_hello_type 1 }
        use_backend mokey if { req_ssl_sni -i portal.example.edu }

    #---------------------------------------------------------------------
    # backend for mokey
    #---------------------------------------------------------------------
    backend mokey
        mode tcp
        stick-table type binary len 32 size 30k expire 30m
        acl clienthello req_ssl_hello_type 1
        acl serverhello rep_ssl_hello_type 2
        tcp-request inspect-delay 5s
        tcp-request content accept if clienthello
        tcp-response content accept if serverhello
        stick on payload_lv(43,1) if clienthello
        stick store-response payload_lv(43,1) if serverhello
        option ssl-hello-chk

        server mokey_app 127.0.0.1:8080


    $ systemctl restart haproxy
    $ systemctl enable haproxy


Start mokey service::

    $ systemctl restart mokey
    $ systemctl enable mokey

To view mokey logs run::

    $ journalctl -u mokey

------------------------------------------------------------------------
Customizing templates
------------------------------------------------------------------------

The templates for the web interface and emails are intstalled by default in
/usr/share/mokey. Edit to taste and restart mokey.

------------------------------------------------------------------------
License
------------------------------------------------------------------------

mokey is released under a BSD style license. See the LICENSE file. 
