%define __spec_install_post %{nil}
%define debug_package %{nil}

Summary:       FreeIPA self-service account managment tool
Name:          mokey
Version:       0.5.3
Release:       1%{?dist}
License:       BSD
Group:         Applications/Internet
SOURCE:        %{name}-%{version}-linux-amd64.tar.gz
URL:           https://github.com/ubccr/mokey
BuildRoot:     %{_tmppath}/%{name}-%{version}-%{release}-root
Requires(pre): /usr/sbin/useradd, /usr/bin/getent

%description
mokey is web application that provides self-service user account management
tools for FreeIPA. The motivation for this project was to implement the
self-service password reset functionality missing in FreeIPA.

%pre
getent group mokey &> /dev/null || \
groupadd -r mokey &> /dev/null
getent passwd mokey &> /dev/null || \
useradd -r -g mokey -d %{_datadir}/%{name} -s /sbin/nologin \
        -c 'Mokey Server' mokey &> /dev/null

%prep
%setup -q -n %{name}-%{version}-linux-amd64

%build
# TODO: consider actually building from source with "go build"

%install
rm -rf %{buildroot}
install -d %{buildroot}%{_datadir}/%{name}
install -d %{buildroot}%{_sysconfdir}/%{name}
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_usr}/lib/systemd/system

cp -a ./%{name}.yaml.sample %{buildroot}%{_sysconfdir}/%{name}/%{name}.yaml
cp -a ./%{name} %{buildroot}%{_bindir}/%{name}
cp -Ra ./templates %{buildroot}%{_datadir}/%{name}
cp -Ra ./ddl %{buildroot}%{_datadir}/%{name}
cat << EOF > %{buildroot}%{_usr}/lib/systemd/system/%{name}.service
[Unit]
Description=mokey server
After=syslog.target network.target mariadb.service

[Service]
Type=simple
User=mokey
Group=mokey
WorkingDirectory=%{_datadir}/%{name}
ExecStart=%{_bindir}/%{name} --debug server
Restart=on-abort

[Install]
WantedBy=multi-user.target
EOF

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_datadir}/%{name}/ddl/*
%doc README.rst AUTHORS.rst ChangeLog.rst NOTICE mokey.yaml.sample
%license LICENSE
%config(noreplace) %{_datadir}/%{name}/templates/*
%attr(0755,root,root) %{_bindir}/%{name}
%attr(640,root,mokey) %config(noreplace) %{_sysconfdir}/%{name}/%{name}.yaml
%attr(644,root,root) %{_usr}/lib/systemd/system/%{name}.service

%changelog
* Wed Sep 12 2018  Andrew E. Bruno <aebruno2@buffalo.edu> 0.5.2-1
- New Features
    - Add option to disable user signup
    - Add new command for re-sending verify emails
* Wed Sep 12 2018  Andrew E. Bruno <aebruno2@buffalo.edu> 0.5.1-1
- New Features
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
* Tue Jan 09 2018  Andrew E. Bruno <aebruno2@buffalo.edu> 0.0.6-14
- New Features
    - OAuth/OpenID Connect consent endpoint for Hydra
    - API key access to consent endpoint
    - User status command
- Bug Fixes
    - Fix optional security question on password reset for fresh accounts
    - Support for FreeIPA 4.5
* Thu May 25 2017  Andrew E. Bruno <aebruno2@buffalo.edu> 0.0.5-1
- New Features
    - Add support for managing SSH Public Keys
    - Add support for managing OTP Tokens
    - Add support for enabling Two-Factor Authentication
    - Refresh UI
* Thu Sep 03 2015  Andrew E. Bruno <aebruno2@buffalo.edu> 0.0.4-1
- New Features
    - Min password length configurable option
    - Add HMAC signed tokens
* Wed Sep 02 2015  Andrew E. Bruno <aebruno2@buffalo.edu> 0.0.3-1
- New Features
    - Rate limiting configurable option
    - Re-locate static template directory
- Bug Fixes
    - Add check for empty user name in forgot password
* Sat Aug 29 2015  Andrew E. Bruno <aebruno2@buffalo.edu> 0.0.2-1
- New Features
    - Set ipahost from /etc/ipa/default.conf
* Fri Aug 28 2015  Andrew E. Bruno <aebruno2@buffalo.edu> 0.0.1-1
- Initial release
