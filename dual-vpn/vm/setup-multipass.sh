#!/usr/bin/env bash
set -Eeuo pipefail
# Подъём изолированной Ubuntu 24.04 VM для dual-vpn (host не трогаем).
# Требует интерактивного sudo на хосте для установки multipass.
VM_NAME="${VM_NAME:-dual-vpn-test}"

if ! command -v multipass >/dev/null 2>&1; then
  echo "multipass не установлен. Выполните вручную (нужен пароль sudo):"
  echo "  sudo snap install multipass --classic"
  echo "Затем повторите ./vm/setup-multipass.sh"
  exit 1
fi

# shellcheck disable=SC2012
if multipass list --format json 2>/dev/null | grep -q "\"name\": \"${VM_NAME}\"\\b"; then
  echo "VM ${VM_NAME} уже существует."
else
  multipass launch --name "$VM_NAME" --cpus 2 --memory 2G --disk 10G \
    --cloud-init vm/cloud-init.yaml 24.04
fi

multipass info "$VM_NAME"
echo "Готово. Дальше: ./vm/run-tests.sh (unit + dry-run), затем docs/VM-TESTING.md для E2E."
