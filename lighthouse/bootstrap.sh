#!/bin/sh
set -eu
test "$(id -u)" = 0
umask 077
test ! -e /var/lib/nebula/config.json
case "$(uname -m)" in
  x86_64)
    architecture=amd64
    checksum=99ac335caeb69d02a6b6b00a3d4b5d0a36ec3971df480a1cc50e6db378342955
    ;;
  aarch64)
    architecture=arm64
    checksum=69b2764b0c27b04e4f3fb47764cf330555beb5a49e62e045ed5f208a14341343
    ;;
  *) echo 'Unsupported lighthouse architecture; expected amd64 or arm64' >&2; exit 1 ;;
esac
nebula_binary=/usr/local/bin/nebula
cert_binary=/usr/local/bin/nebula-cert
if [ -e "$nebula_binary" ] || [ -e "$cert_binary" ]; then
  echo 'Native Nebula binaries already exist; inspect before reinstalling' >&2
  exit 1
fi
if ! command -v curl >/dev/null || [ ! -s /etc/ssl/certs/ca-certificates.crt ]; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl ca-certificates
fi
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
curl --fail --silent --show-error --location \
  --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 60 \
  --output "$temporary/release.tar.gz" \
  "https://github.com/slackhq/nebula/releases/download/v1.10.3/nebula-linux-$architecture.tar.gz"
printf '%s  %s\n' "$checksum" "$temporary/release.tar.gz" | sha256sum --check
tar -xzf "$temporary/release.tar.gz" -C "$temporary" nebula nebula-cert
test "$("$temporary/nebula" -version)" = 'Version: 1.10.3'
test "$("$temporary/nebula-cert" -version)" = 'Version: 1.10.3'
install -d -m 0755 /usr/local/bin
install -m 0755 "$temporary/nebula" "$nebula_binary"
install -m 0755 "$temporary/nebula-cert" "$cert_binary"
install -d -m 0700 /var/lib/nebula
cat > /etc/systemd/system/nebula.service <<UNIT
[Unit]
Description=Nebula network
After=network.target
ConditionPathExists=/var/lib/nebula/config.json

[Service]
Type=exec
ExecStart=$nebula_binary -config /var/lib/nebula/config.json
Restart=on-failure
RestartSec=5
UMask=0077
ProtectHome=true
ProtectSystem=strict
PrivateTmp=true
CapabilityBoundingSet=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 /etc/systemd/system/nebula.service
systemctl daemon-reload
systemctl enable nebula.service
printf 'Nebula 1.10.3 installed; waiting for operator enrollment.\n'
