%define __spec_install_post %{nil}
%define debug_package %{nil}

Summary:       FreeIPA self-service account managment tool
Name:          mokey
Version:       0.0.2
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
cp -Ra ./static %{buildroot}%{_datadir}/%{name}
cp -Ra ./ddl %{buildroot}%{_datadir}/%{name}
cat << EOF > %{buildroot}%{_usr}/lib/systemd/system/%{name}.service
[Unit]
Description=mokey server
After=syslog.target
After=network.target

[Service]
Type=simple
User=mokey
Group=mokey
WorkingDirectory=%{_datadir}/%{name}
ExecStart=/bin/bash -c '%{_bindir}/%{name} --debug server'
Restart=on-abort

[Install]
WantedBy=multi-user.target
EOF

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_datadir}/%{name}/ddl/*
%doc README.rst AUTHORS.rst ChangeLog.rst mokey.yaml.sample
%license LICENSE
%config(noreplace) %{_datadir}/%{name}/templates/*
%config(noreplace) %{_datadir}/%{name}/static/*
%attr(0755,root,root) %{_bindir}/%{name}
%attr(640,root,mokey) %config(noreplace) %{_sysconfdir}/%{name}/%{name}.yaml
%attr(644,root,root) %{_usr}/lib/systemd/system/%{name}.service

%changelog
* Fri Aug 28 2015  Andrew E. Bruno <aebruno2@buffalo.edu> 0.0.1-1
- Initial release
