#!/bin/bash

# -------------------------------------------------------------------------------
# LICENSE:
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# -------------------------------------------------------------------------------

# This is an `ifup` script to be used for integrating openfortivpn and
# systemd-resolved. When the network interface goes up, the DNS server information
# will be added to `systemd-resolved` without modifying /etc/resolve.conf.
#
# This script is largely based on the main script from the `update-systemd-resolved`
# package, see: https://github.com/jonathanio/update-systemd-resolved

DBUS_DEST="org.freedesktop.resolve1"
DBUS_NODE="/org/freedesktop/resolve1"

SCRIPT_NAME="${BASH_SOURCE[0]##*/}"

log() {
    logger -s -t "$SCRIPT_NAME" "$@"
}

for level in emerg err warning info debug; do
    printf -v functext -- '%s() { log -p user.%s -- "$@" ; }' "$level" "$level"
    eval "$functext"
done

get_link_info() {
    dev="$1"
    shift

    link=''
    link="$(ip link show dev "$dev")" || return $?

    echo "$dev" "${link%%:*}"
}

busctl_call() {
    # Preserve busctl's exit status
    busctl call "$DBUS_DEST" "$DBUS_NODE" "${DBUS_DEST}.Manager" "$@" || {
	local -i status=$?
	    emerg "'busctl' exited with status $status"
	    return $status
	}
}

up() {
    local link="$1"
    shift
    local if_index="$1"
    shift

    local -a dns_servers=() dns_domain=() dns_search=() dns_routed=()
    local -i dns_server_count=0 dns_domain_count=0 dns_search_count=0 dns_routed_count=0
    local dns_sec=""

    for address in ${DNS_SERVERS}; do
        (( dns_server_count += 1 ))
        dns_servers+=(2 4 ${address//./ })
    done

    for domain in ${DNS_SUFFIX}; do
	 (( dns_search_count += 1 ))
	dns_search+=("${domain}" false)
    done

    if [[ "${#dns_servers[*]}" -gt 0 ]]; then
	busctl_params=("$if_index" "$dns_server_count" "${dns_servers[@]}")
	info "SetLinkDNS(${busctl_params[*]})"
	busctl_call SetLinkDNS 'ia(iay)' "${busctl_params[@]}" || return $?
    fi

    if [[ "${#dns_domain[*]}" -gt 0 \
	|| "${#dns_search[*]}" -gt 0 \
	|| "${#dns_routed[*]}" -gt 0 ]]; then
	    dns_count=$((dns_domain_count+dns_search_count+dns_routed_count))
	    busctl_params=("$if_index" "$dns_count")
	    if [[ "${#dns_domain[*]}" -gt 0 ]]; then
		busctl_params+=("${dns_domain[@]}")
	    fi
	    if [[ "${#dns_search[*]}" -gt 0 ]]; then
		busctl_params+=("${dns_search[@]}")
	    fi
	    if [[ "${#dns_routed[*]}" -gt 0 ]]; then
		busctl_params+=("${dns_routed[@]}")
	    fi
	    info "SetLinkDomains(${busctl_params[*]})"
	    busctl_call SetLinkDomains 'ia(sb)' "${busctl_params[@]}" || return $?
    fi

    if [[ -n "${dns_sec}" ]]; then
	if [[ "${dns_sec}" == "default" ]]; then
	    # We need to provide an empty string to use the default settings
	    info "SetLinkDNSSEC($if_index '')"
	    busctl_call SetLinkDNSSEC 'is' "$if_index" "" || return $?
	else
	    info "SetLinkDNSSEC($if_index ${dns_sec})"
	    busctl_call SetLinkDNSSEC 'is' "$if_index" "${dns_sec}" || return $?
	fi
    fi
}

dev=${NET_DEVICE}
read -r link if_index _ < <(get_link_info "$dev")
up "$link" "$if_index"
systemd-resolve --flush-caches
