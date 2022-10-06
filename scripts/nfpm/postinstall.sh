#!/bin/sh

cleanInstall() {
    if ! getent passwd mokey > /dev/null; then
        printf "\033[32m Creating mokey system user & group\033[0m\n"
        groupadd -r mokey
        useradd -r -g mokey -d /var/lib/mokey -s /sbin/nologin \
                -c 'Mokey server' mokey
    fi

    mkdir -p /var/lib/mokey
    chown mokey:mokey /var/lib/mokey 
    chmod 755 /var/lib/mokey

    if [ -f "/etc/mokey/mokey" ]; then
        chmod 660 /etc/mokey/mokey
        chown mokey:mokey /etc/mokey/mokey.toml
    fi

    if [ -x "/usr/bin/deb-systemd-helper" ]; then
        deb-systemd-helper purge mokey.service >/dev/null
        deb-systemd-helper unmask mokey.service >/dev/null
    elif [ -x "/usr/bin/systemctl" ]; then
        systemctl daemon-reload ||:
        systemctl unmask mokey.service ||:
        systemctl preset mokey.service ||:
        systemctl enable mokey.service ||:
    fi
}

upgrade() {
    printf "\033[32m Upgrading mokey\033[0m\n"
    if [ -x "/usr/bin/systemctl" ]; then
        systemctl restart mokey.service ||:
    fi
}

# Step 2, check if this is a clean install or an upgrade
action="$1"
if  [ "$1" = "configure" ] && [ -z "$2" ]; then
  # Alpine linux does not pass args, and deb passes $1=configure
  action="install"
elif [ "$1" = "configure" ] && [ -n "$2" ]; then
    # deb passes $1=configure $2=<current version>
    action="upgrade"
fi

case "$action" in
  "1" | "install")
    cleanInstall
    ;;
  "2" | "upgrade")
    upgrade
    ;;
  *)
    # $1 == version being installed
    printf "\033[32m Alpine\033[0m"
    cleanInstall
    ;;
esac

exit 0
