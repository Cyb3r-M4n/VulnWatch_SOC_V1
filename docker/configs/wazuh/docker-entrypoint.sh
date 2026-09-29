#!/bin/bash
# Désactive Filebeat (pas d'indexer Wazuh dans cette stack) puis lance s6.
set -euo pipefail
if [[ -d /etc/services.d/filebeat ]]; then
  rm -rf /etc/services.d/filebeat
fi
exec /init
