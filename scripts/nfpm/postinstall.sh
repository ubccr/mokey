#!/bin/sh

#!/bin/sh

cleanInstall() {
    # Create mokey system user and group if they don't exist
    if ! getent passwd mokey > /dev/null; then
        printf "\033[32m Creating mokey system user & group\033[0m\n"
        groupadd -r mokey
        useradd -r -g mokey -d /var/lib/mokey -s /sbin/nologin \
                -c 'Mokey server' mokey
    fi

    # Set up data directory permissions
    mkdir -p /var/lib/mokey
    chown mokey:mokey /var/lib/mokey 
    chmod 755 /var/lib/mokey

    # Set up configuration file permissions if it exists
    if [ -f "/etc/mokey/mokey.toml" ]; then
        chmod 640 /etc/mokey/mokey.toml
        chown mokey:mokey /etc/mokey/mokey.toml
    fi

    # Grant the binary permission to bind to privileged ports (like 443)
    # This allows running the service as the non-root 'mokey' user.
    if [ -f "/usr/bin/mokey" ]; then
        if command -v setcap > /dev/null; then
            printf "\033[32m Setting network capabilities for mokey binary\033[0m\n"
            setcap 'cap_net_bind_service=+ep' /usr/bin/mokey
        else
            printf "\033[31m Warning: setcap not found. Mokey may fail to bind to port 443.\033[0m\n"
        fi
    fi

    # Handle systemd integration for Debian-based or standard systemd systems
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
    
    # Re-apply capabilities during upgrade as the binary is usually replaced
    if [ -f "/usr/bin/mokey" ] && command -v setcap > /dev/null; then
        setcap 'cap_net_bind_service=+ep' /usr/bin/mokey
    fi

    if [ -x "/usr/bin/systemctl" ]; then
        systemctl restart mokey.service ||:
    fi
}

# Check if this is a clean install or an upgrade based on arguments
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
    # Default case, often used for Alpine or direct script execution
    printf "\033[32m Executing default installation\033[0m\n"
    cleanInstall
    ;;
esac

exit 0

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
