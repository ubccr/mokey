# Mokey ChangeLog

## [v0.6.3] - 2023-02-09

- Update fiber
- Update hydra go client
- Trim spaces in names when creating/updating account
- Add better error messages for name length
- Add ability to better control log level

## [v0.6.2] - 2023-01-26

- Fix sshpubkey update bug

## [v0.6.1] - 2023-01-26

- Fix account settings update bug
- Add hydra login prometheus counters

## [v0.6.0] - 2023-01-25

- Major re-write. New login flow and template layout
- Upgrade to bootstrap 5
- Remove database dependency
- Switch to using Fiber web framework and htmx frontend
- New email text/html templates
- Add terms of service url to sign up page [#97](https://github.com/ubccr/mokey/issues/97)
- Add better messaging for disabled user at login [#22](https://github.com/ubccr/mokey/issues/22)
- Notification email sent anytime account updated [#82](https://github.com/ubccr/mokey/issues/82)
- Allow configuring default hash algorithm for OTP [#99](https://github.com/ubccr/mokey/issues/99)
- Add user block list [#83](https://github.com/ubccr/mokey/issues/83)
- Make server timeouts configurable [#109](https://github.com/ubccr/mokey/issues/109)

## [v0.5.6] - 2021-05-18

- Add config option to replace unexpired password tokens
- Add email flag to resetpw command
- Relax CSP settings to allow inline images and js
- Add change expired password login flow

## [v0.5.5] - 2021-03-25

- Add security related HTTP headers #55
- Upgrade to latest hydra sdk. Tested against hydra v1.9.2
- Verify nsaccountlock before sending password reset email @cmd-ntrf
- Add option to require admin verification to enable new account @cmd-ntrf
- Restrict username to lowercase and not only number when signing up @cmd-ntrf
- Add option to always skip consent in hydra login flow @isard-vdi

## [v0.5.4] - 2020-07-14

- Fix bug with missing set-cookie header issue #53

## [v0.5.3] - 2019-10-29

- Update Login/Conset flow for hydra v1.0.3+oryOS.10
- Add support for SMTP AUTH (@cdwertmann)
- Implement fully encrypted SMTP connection (@g5pw)
- Fix bug if session keys change or session gets corrupted
- Upgrade to echo v4

## [v0.5.2] - 2018-09-12

- Add option to disable user signup
- Add new command for re-sending verify emails

## [v0.5.1] - 2018-09-12

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

## [v0.0.6] - 2018-01-09

- Add new OAuth/OpenID Connect consent endpoint for Hydra
- Add support for api key access to consent endpoint
- Add user status command
- Add support for FreeIPA 4.5
- Fix optional security question on password reset for fresh accounts (PR #11)

## [v0.0.5] - 2017-08-01

- Add support for managing SSH Public Keys
- Add support for managing OTP Tokens
- Add support for enabling Two-Factor Authentication
- Refresh UI

## [v0.0.4] - 2015-09-03

- Min password length configurable option
- Add HMAC signed tokens

## [v0.0.3] - 2015-09-02

- Rate limiting configurable option
- Re-locate static template directory
- Add check for empty user name in forgot password

## [v0.0.2] - 2015-08-29

- Add rpm spec
- Set ipahost from /etc/ipa/default.conf

## [v0.0.1] - 2015-08-28

- Initial release

[v0.0.1]: https://github.com/ubccr/mokey/releases/tag/v0.0.1
[v0.0.2]: https://github.com/ubccr/mokey/releases/tag/v0.0.2
[v0.0.3]: https://github.com/ubccr/mokey/releases/tag/v0.0.3
[v0.0.4]: https://github.com/ubccr/mokey/releases/tag/v0.0.4
[v0.0.5]: https://github.com/ubccr/mokey/releases/tag/v0.0.5
[v0.0.6]: https://github.com/ubccr/mokey/releases/tag/v0.0.6
[v0.5.1]: https://github.com/ubccr/mokey/releases/tag/v0.5.1
[v0.5.2]: https://github.com/ubccr/mokey/releases/tag/v0.5.2
[v0.5.3]: https://github.com/ubccr/mokey/releases/tag/v0.5.3
[v0.5.4]: https://github.com/ubccr/mokey/releases/tag/v0.5.4
[v0.5.5]: https://github.com/ubccr/mokey/releases/tag/v0.5.5
[v0.5.6]: https://github.com/ubccr/mokey/releases/tag/v0.5.6
[v0.6.0]: https://github.com/ubccr/mokey/releases/tag/v0.6.0
[v0.6.1]: https://github.com/ubccr/mokey/releases/tag/v0.6.1
[v0.6.2]: https://github.com/ubccr/mokey/releases/tag/v0.6.2
[v0.6.3]: https://github.com/ubccr/mokey/releases/tag/v0.6.3
