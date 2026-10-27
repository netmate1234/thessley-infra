#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo 'Run this installer with sudo.' >&2
    exit 1
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
pam_library=/usr/local/lib/thessley-pam
if [[ ! -f "${pam_library}/thessley_pam/listener.py" ]]; then
    echo 'Install or update Thessley PAM Linux first; its shared HTTPS listener is required.' >&2
    exit 1
fi

install -d -o root -g root -m 0755 /opt/thessley-ad/thessley_ad_service
install -d -o root -g root -m 0700 /var/lib/thessley-ad
install -d -o root -g root -m 0700 /etc/thessley-ad
install -m 0644 "${script_dir}"/*.py /opt/thessley-ad/thessley_ad_service/
install -m 0644 "${script_dir}/requirements.txt" /opt/thessley-ad/requirements.txt
install -m 0644 "${script_dir}/thessley-ad.service" /etc/systemd/system/thessley-ad.service
install -m 0644 "${script_dir}/service.toml.example" /etc/thessley-ad/service.toml.example

if [[ ! -e /etc/thessley-ad/service.toml ]]; then
    install -o root -g root -m 0600 "${script_dir}/service.toml.example" /etc/thessley-ad/service.toml
    echo 'Created /etc/thessley-ad/service.toml from the example. Edit it before starting the service.'
fi

if [[ ! -x /opt/thessley-ad/venv/bin/python ]]; then
    python3 -m venv --system-site-packages /opt/thessley-ad/venv
fi
/opt/thessley-ad/venv/bin/python -m pip install --disable-pip-version-check --no-cache-dir \
    --requirement /opt/thessley-ad/requirements.txt
systemctl daemon-reload
echo 'Installed the Thessley AD API service. Configure /etc/thessley-ad/service.toml and its root-only password/CA files before enabling it.'
