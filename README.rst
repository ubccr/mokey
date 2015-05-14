===============================================================================
mokey - Migrate CCR user accounts to FreeIPA
===============================================================================

This project is a simple web application to migrate user accounts from CCR's
old kerberos/ldap systems to FreeIPA. It authenticates users agains the old
system and requires users to accept new terms of service and set a security
question.

------------------------------------------------------------------------
Usage
------------------------------------------------------------------------

Deployment::

    $ edit /etc/mokey.yaml
    $ ./mokey server
