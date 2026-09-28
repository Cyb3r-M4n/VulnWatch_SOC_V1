#!/usr/bin/env bash
# Compatibilité : délègue au script de démarrage unique
exec "$(cd "$(dirname "$0")" && pwd)/start.sh" "$@"
