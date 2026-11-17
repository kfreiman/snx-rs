#!/usr/bin/env bash
set -Eeuo pipefail
# Проверка dual-vpn в Multipass VM. Запуск с хоста: ./vm/run-tests.sh
VM_NAME="${VM_NAME:-dual-vpn-test}"
REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

multipass exec "$VM_NAME" -- bash -ec '
set -Eeuo pipefail
dpkg -s python3-yaml python3-dbus >/dev/null 2>&1 || sudo apt-get update && sudo apt-get install -y python3-yaml python3-dbus
cd /mnt/dual-vpn
python3 -m unittest discover -s tests -p "test_*.py" -v
./dual-vpn --config config/dual-vpn.yaml.example doctor || true
' 2>&1

echo "Примечание: VM должна монтировать репозиторий:"
echo "  multipass mount \"$REPO_ROOT\" ${VM_NAME}:/mnt/dual-vpn"
