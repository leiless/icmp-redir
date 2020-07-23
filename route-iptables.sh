#!/bin/sh
#
# Created Jun 2, 2020. leiless.
#

set -euf
#set -x

icmp_enable() {
    if ! sudo ip route add local 0/0 dev lo table 100 2> /dev/null; then
        echo "ip route, iptables seems already enabled? please check manually."
        exit 1
    fi
    sudo ip rule add fwmark 1 lookup 100

    sudo iptables -t mangle -N ICMP_PROXY
    sudo iptables -t mangle -A ICMP_PROXY -p icmp -j MARK --set-mark 1
    sudo iptables -t mangle -A PREROUTING -p icmp -j ICMP_PROXY

    echo Enabled
}

icmp_disable() {
    sudo ip route flush table 100
    if ! sudo ip rule del table 100 2> /dev/null; then
        echo "ip route, iptables seems already disabled? please check manually."
        exit 1
    fi

    sudo iptables -t mangle -F
    sudo iptables -t mangle -X ICMP_PROXY

    echo Disabled
}

#
# see: https://misc.flogisoft.com/bash/tip_colors_and_formatting
#
_GREEN="\e[92m"
_RESET="\e[0m"

#
# Better set -x with TTY coloring for one command
#
exec_trace() {
    # see: https://github.com/koalaman/shellcheck/wiki/SC2145
    echo "$_GREEN+ $*$_RESET"
    "$@"
}

icmp_show() {
    # Cache sudo in advance
    sudo printf ""

    exec_trace ip route show table 100
    echo

    exec_trace ip rule list table 100
    echo

    exec_trace sudo iptables -t mangle -vnL
    echo
}

usage() {
    cat << EOL
Usage:
    $(basename "$0") enable | disable | show

EOL
    exit 1
}

if [ $# -ne 1 ]; then
    usage
fi

case "$1" in
    enable)
        icmp_enable
        ;;
    disable)
        icmp_disable
        ;;
    show)
        icmp_show
        ;;
    *)
        usage
        ;;
esac

