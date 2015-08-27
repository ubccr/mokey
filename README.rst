===============================================================================
mokey - FreeIPA account managment tool
===============================================================================

This project is web application to manage user accounts in FreeIPA. It provides
account setup and password reset functionality.

------------------------------------------------------------------------
Deployment
------------------------------------------------------------------------

Copy binary and templates to /srv/mokey::

    /srv/mokey
      |- templates/   HTML templates 
      |- static/      Static css/images
      |- mokey        main binary program
      |- mokey.yaml   config file
      |- cert/        cert/ca-bundle as single PEM
      |- private/     private key

The mokey binary will run as non-root user (apache) so need to ensure file
perms are set correctly::

    $ chmod 640 private/ssl.key mokey.yaml
    $ chgrp apache private/ssl.key mokey.yaml

Install haproxy. This will listen on port 443 and forward SSL requests to mokey
process using SNI TLS extensions. This is refered to as SSL passthrough::

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
        use_backend mokey if { req_ssl_sni -i portal.ccr.buffalo.edu }

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

        server mokey_app 127.0.0.1:8089


    $ systemctl restart haproxy
    $ systemctl enable haproxy


Next, setup mokey systemd unit file::

    $ cat /etc/systemd/system/mokey.service
    [Unit]
    Description=mokey web app

    [Service]
    PIDFile=/var/run/mokey.pid
    User=apache
    Group=apache
    WorkingDirectory=/srv/mokey
    ExecStart=/bin/bash -c '/srv/mokey/mokey server'
    Restart=on-abort

    [Install]
    WantedBy=multi-user.target

    $ systemctl restart mokey
    $ systemctl enable mokey

To view mokey logs run::

    $ journalctl -u mokey

------------------------------------------------------------------------
License
------------------------------------------------------------------------

mokey is released under a BSD style license. See the LICENSE file. 
