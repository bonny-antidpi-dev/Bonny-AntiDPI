#!/usr/bin/env bash
set -Eeuo pipefail

readonly WG_INTERFACE="wg0"
readonly WG_ADDRESS_V4="10.77.0.1/24"
readonly WG_ADDRESS_V6="fd77:77:77::1/64"
readonly CLIENT_ADDRESS_V4="10.77.0.2/32"
readonly CLIENT_ADDRESS_V6="fd77:77:77::2/128"

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

if [[ "${EUID}" -ne 0 ]]; then
    fail "Run this script with sudo: sudo bash setup-wireguard-server.sh <VPS_PUBLIC_IPV4> [UDP_PORT]"
fi

if [[ "$#" -lt 1 || "$#" -gt 2 ]]; then
    fail "Usage: sudo bash setup-wireguard-server.sh <VPS_PUBLIC_IPV4> [UDP_PORT]"
fi

readonly SERVER_IPV4="$1"
readonly WG_PORT="${2:-51820}"

if ! [[ "${WG_PORT}" =~ ^[0-9]+$ ]] || (( WG_PORT < 1 || WG_PORT > 65535 )); then
    fail "UDP_PORT must be between 1 and 65535."
fi

if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 is required to validate the public server address."
fi
python3 - "${SERVER_IPV4}" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit("VPS_PUBLIC_IPV4 is not a valid IP address.")
if address.version != 4 or not address.is_global:
    raise SystemExit("VPS_PUBLIC_IPV4 must be a public IPv4 address.")
PY

if [[ ! -r /etc/os-release ]]; then
    fail "This script supports Debian and Ubuntu VPS images only."
fi
# shellcheck disable=SC1091
source /etc/os-release
if [[ "${ID:-}" != "debian" && "${ID:-}" != "ubuntu" ]]; then
    fail "This script supports Debian and Ubuntu VPS images only."
fi

if [[ -e "/etc/wireguard/${WG_INTERFACE}.conf" || -e /etc/sysctl.d/99-bonny-wireguard.conf ]]; then
    fail "A Bonny WireGuard setup file already exists. Refusing to overwrite it."
fi

OWNER="${SUDO_USER:-root}"
OWNER_HOME="$(getent passwd "${OWNER}" | cut -d: -f6)"
if [[ -z "${OWNER_HOME}" || ! -d "${OWNER_HOME}" ]]; then
    fail "Could not determine the home directory for ${OWNER}."
fi
OWNER_UID="$(id -u "${OWNER}")"
OWNER_GID="$(id -g "${OWNER}")"
CLIENT_CONFIG="${OWNER_HOME}/bonny-germany-client.conf"
if [[ -e "${CLIENT_CONFIG}" ]]; then
    fail "Refusing to overwrite ${CLIENT_CONFIG}. Move the existing file first."
fi

if ! command -v ip >/dev/null 2>&1; then
    fail "The ip command is missing from this server image."
fi

readonly WAN_INTERFACE="$(ip -4 route show default | awk 'NR == 1 { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
if [[ -z "${WAN_INTERFACE}" ]]; then
    fail "Could not determine the VPS IPv4 network interface."
fi

if ! ip -6 route show default | grep -q '^default'; then
    fail "This VPS has no IPv6 default route. Choose a VPS with public IPv6 so IPv6 traffic will not bypass the tunnel."
fi
if ! ip -o -6 addr show dev "${WAN_INTERFACE}" scope global | awk '{print $4}' | cut -d/ -f1 | grep -Eq '^[23][0-9a-fA-F]{3}:'; then
    fail "This VPS has no public IPv6 address on ${WAN_INTERFACE}. Choose a VPS with public IPv6 so IPv6 traffic will not bypass the tunnel."
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y wireguard iptables

if ! ip6tables -t nat -S >/dev/null 2>&1; then
    fail "IPv6 NAT is unavailable on this VPS kernel; refusing to set up an IPv4-only tunnel that could leak IPv6 traffic."
fi

install -d -m 700 /etc/wireguard
umask 077
SERVER_PRIVATE_KEY="$(wg genkey)"
SERVER_PUBLIC_KEY="$(printf '%s\n' "${SERVER_PRIVATE_KEY}" | wg pubkey)"
CLIENT_PRIVATE_KEY="$(wg genkey)"
CLIENT_PUBLIC_KEY="$(printf '%s\n' "${CLIENT_PRIVATE_KEY}" | wg pubkey)"

cat > "/etc/wireguard/${WG_INTERFACE}.conf" <<EOF
[Interface]
Address = ${WG_ADDRESS_V4}, ${WG_ADDRESS_V6}
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIVATE_KEY}
SaveConfig = false
PostUp = iptables -I INPUT 1 -p udp --dport ${WG_PORT} -j ACCEPT; ip6tables -I INPUT 1 -p udp --dport ${WG_PORT} -j ACCEPT; iptables -A FORWARD -i %i -o ${WAN_INTERFACE} -s 10.77.0.0/24 -j ACCEPT; iptables -A FORWARD -i ${WAN_INTERFACE} -o %i -d 10.77.0.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; ip6tables -A FORWARD -i %i -o ${WAN_INTERFACE} -s fd77:77:77::/64 -j ACCEPT; ip6tables -A FORWARD -i ${WAN_INTERFACE} -o %i -d fd77:77:77::/64 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.77.0.0/24 -o ${WAN_INTERFACE} -j MASQUERADE; ip6tables -t nat -A POSTROUTING -s fd77:77:77::/64 -o ${WAN_INTERFACE} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${WG_PORT} -j ACCEPT; ip6tables -D INPUT -p udp --dport ${WG_PORT} -j ACCEPT; iptables -D FORWARD -i %i -o ${WAN_INTERFACE} -s 10.77.0.0/24 -j ACCEPT; iptables -D FORWARD -i ${WAN_INTERFACE} -o %i -d 10.77.0.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; ip6tables -D FORWARD -i %i -o ${WAN_INTERFACE} -s fd77:77:77::/64 -j ACCEPT; ip6tables -D FORWARD -i ${WAN_INTERFACE} -o %i -d fd77:77:77::/64 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.77.0.0/24 -o ${WAN_INTERFACE} -j MASQUERADE; ip6tables -t nat -D POSTROUTING -s fd77:77:77::/64 -o ${WAN_INTERFACE} -j MASQUERADE

[Peer]
PublicKey = ${CLIENT_PUBLIC_KEY}
AllowedIPs = ${CLIENT_ADDRESS_V4}, ${CLIENT_ADDRESS_V6}
EOF
chmod 600 "/etc/wireguard/${WG_INTERFACE}.conf"

if ip -6 route show default | grep -q 'proto ra'; then
    cat > /etc/sysctl.d/99-bonny-wireguard.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.${WAN_INTERFACE}.accept_ra = 2
EOF
else
    cat > /etc/sysctl.d/99-bonny-wireguard.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
fi
chmod 644 /etc/sysctl.d/99-bonny-wireguard.conf
sysctl --system

cat > "${CLIENT_CONFIG}" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
Address = ${CLIENT_ADDRESS_V4}, ${CLIENT_ADDRESS_V6}
DNS = 1.1.1.1, 2606:4700:4700::1111

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${SERVER_IPV4}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
chown "${OWNER_UID}:${OWNER_GID}" "${CLIENT_CONFIG}"
chmod 600 "${CLIENT_CONFIG}"

systemctl enable --now "wg-quick@${WG_INTERFACE}"

printf '\nWireGuard server is configured.\n'
printf 'Client profile: %s (mode 600; contains the client private key)\n' "${CLIENT_CONFIG}"
printf 'Next: allow UDP %s in the VPS provider firewall, download this profile to Windows, and import it in the official WireGuard app.\n' "${WG_PORT}"
