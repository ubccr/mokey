===============================================================================
ChangeLog
===============================================================================

`v0.5.1`_ (2018-09-12)
----------------------

- Major code refactor to use echo framework
- Add user signup/registration (Fixes #8)
- Add support for new Login/Conset flow in hydra 1.0.0
- Add ApiKey support for hydra consent
- Add CAPTCHA support
- Add Globus support to user account sign up
- Simplify login to be more like FreeIPA (password+otp)
- Remove security questions
- Remove dependecy on krb5-libs (now using pure go kerberos library)
- Update build to use vgo

`v0.0.6`_ (2018-01-09)
----------------------

- Add new OAuth/OpenID Connect consent endpoint for Hydra
- Add support for api key access to consent endpoint
- Add user status command
- Add support for FreeIPA 4.5
- Fix optional security question on password reset for fresh accounts (PR #11)

`v0.0.5`_ (2017-08-01)
----------------------

- Add support for managing SSH Public Keys
- Add support for managing OTP Tokens
- Add support for enabling Two-Factor Authentication
- Refresh UI

`v0.0.4`_ (2015-09-03)
----------------------

- Min password length configurable option
- Add HMAC signed tokens

`v0.0.3`_ (2015-09-02)
----------------------

- Rate limiting configurable option
- Re-locate static template directory
- Add check for empty user name in forgot password

`v0.0.2`_ (2015-08-29)
----------------------

- Add rpm spec
- Set ipahost from /etc/ipa/default.conf

`v0.0.1`_ (2015-08-28)
----------------------

- Initial release

.. _v0.0.1: https://github.com/ubccr/mokey/releases/tag/v0.0.1
.. _v0.0.2: https://github.com/ubccr/mokey/releases/tag/v0.0.2
.. _v0.0.3: https://github.com/ubccr/mokey/releases/tag/v0.0.3
.. _v0.0.4: https://github.com/ubccr/mokey/releases/tag/v0.0.4
.. _v0.0.5: https://github.com/ubccr/mokey/releases/tag/v0.0.5
.. _v0.0.6: https://github.com/ubccr/mokey/releases/tag/v0.0.6
.. _v0.5.1: https://github.com/ubccr/mokey/releases/tag/v0.5.1
