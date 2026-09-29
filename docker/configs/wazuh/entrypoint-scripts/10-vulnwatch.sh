#!/usr/bin/env bash
# VulnWatch : mot de passe d'enrollment + pas de vuln-detector Wazuh
set -euo pipefail

CONF="/var/ossec/etc/ossec.conf"
PASSFILE="/var/ossec/etc/authd.pass"
PY="/var/ossec/framework/python/bin/python3"

if [[ -n "${WAZUH_ENROLL_PASSWORD:-}" ]]; then
  printf '%s' "${WAZUH_ENROLL_PASSWORD}" > "${PASSFILE}"
  chown root:wazuh "${PASSFILE}" 2>/dev/null || true
  chmod 640 "${PASSFILE}"
fi

if [[ -f "${CONF}" && -x "${PY}" ]]; then
  "${PY}" - <<'PY'
from pathlib import Path
import re

p = Path("/var/ossec/etc/ossec.conf")
text = p.read_text()
text = re.sub(
    r"(<vulnerability-detection>\s*)<enabled>yes</enabled>",
    r"\1<enabled>no</enabled>",
    text,
    count=1,
    flags=re.I,
)
text = re.sub(
    r"(<vulnerability-detector>\s*)<enabled>yes</enabled>",
    r"\1<enabled>no</enabled>",
    text,
    count=1,
    flags=re.I,
)
text = re.sub(
    r"(<use_password>)no(</use_password>)",
    r"\1yes\2",
    text,
    count=1,
    flags=re.I,
)
p.write_text(text)
PY
fi
