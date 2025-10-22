#!/usr/bin/env bash
set -euo pipefail
DEB="${1:-kylin-ai-cryptojacking-detect_0.1.0-1.fc40_all.deb}"

sudo apt update
sudo apt install -y python3 python3-pip python3-yaml python3-psutil python3-pandas
sudo dpkg -i "$DEB" || sudo apt -f install -y

# Ubuntu 上修 shebang（避免 -sP）
sudo sed -i '1c #!/usr/bin/env python3' /usr/bin/miner-sentinel

# 让 Ubuntu 的 python 能找到 Fedora 风格的 site-packages
SITE_BASE="$(dpkg -c "$DEB" | awk '{print $6}' | grep 'site-packages/msentinel_cli/cli.py$' | sed 's#/msentinel_cli/cli.py##' | head -n1)"
sudo install -d /usr/lib/python3/dist-packages
echo "$SITE_BASE" | sudo tee /usr/lib/python3/dist-packages/kylin_sentinel.pth >/dev/null

# 运行检查
miner-sentinel --help || true
echo "Run: sudo -E miner-sentinel --monitor"
