#!/bin/bash
###############################################################################
#  Open NAC — Инициализация Git-репозитория
#
#  Этот скрипт:
#    1. Инициализирует git repo
#    2. Создаёт .gitignore
#    3. Делает первый коммит
#    4. Показывает команды для push в GitHub/GitLab
#
#  Использование:
#    chmod +x setup-git.sh
#    ./setup-git.sh
###############################################################################

set -e

echo "============================================"
echo "  Open NAC — Git Repository Setup"
echo "============================================"
echo ""

# ── 1. Проверяем что мы в правильной директории ──

if [ ! -f "docker-compose.yml" ]; then
    echo "ERROR: docker-compose.yml не найден."
    echo "Запустите скрипт из корневой директории проекта open-nac/"
    exit 1
fi

# ── 2. Инициализируем git ──

if [ ! -d ".git" ]; then
    git init
    echo "✓ Git initialized"
else
    echo "✓ Git already initialized"
fi

# ── 3. Создаём .gitignore ──

cat > .gitignore << 'GITIGNORE'
# ══════════════════════════════════════════════
#  Open NAC — .gitignore
# ══════════════════════════════════════════════

# ── Secrets (НИКОГДА не коммитить!) ──
.env
*.key
*.pem
*.p12
*.pfx
!config/freeradius/certs/.gitkeep

# ── Python ──
__pycache__/
*.py[cod]
*$py.class
*.egg-info/
dist/
build/
.eggs/
*.egg
.venv/
venv/
env/
.mypy_cache/
.pytest_cache/
.coverage
htmlcov/

# ── Node.js (Admin UI) ──
node_modules/
.next/
.nuxt/
dist/
build/

# ── Docker ──
*.log
docker-compose.override.yml

# ── Данные (volumes) ──
data/
*.db
*.sqlite3

# ── IDE ──
.idea/
.vscode/
*.swp
*.swo
*~
.DS_Store
Thumbs.db

# ── Terraform / Ansible secrets ──
*.tfstate
*.tfstate.backup
ansible/inventory/production.yml
ansible/vault_password

# ── Certificates (создаются при деплое) ──
config/freeradius/certs/*.pem
config/freeradius/certs/*.key
config/freeradius/certs/dh
config/certs/
!config/certs/.gitkeep

# ── Grafana provisioning data ──
grafana-data/

# ── Логи ──
logs/
*.log
GITIGNORE

echo "✓ .gitignore created"

# ── 4. Создаём placeholder-файлы для пустых директорий ──

mkdir -p config/freeradius/certs
mkdir -p config/certs/portal
mkdir -p config/certs/admin
mkdir -p config/logstash/pipeline
mkdir -p config/prometheus/alerts
mkdir -p config/grafana/provisioning/datasources
mkdir -p config/grafana/provisioning/dashboards
mkdir -p config/grafana/dashboards
mkdir -p config/portal/templates
mkdir -p config/policies
mkdir -p services/profiler/app
mkdir -p services/posture-engine/app
mkdir -p services/guest-portal/backend
mkdir -p services/guest-portal/frontend/src
mkdir -p services/admin-ui/backend
mkdir -p services/admin-ui/frontend/src
mkdir -p ansible/inventory
mkdir -p ansible/playbooks
mkdir -p ansible/roles
mkdir -p tests/load
mkdir -p docs/switch-config-examples

# Placeholder files для git
for dir in \
    config/freeradius/certs \
    config/certs/portal \
    config/certs/admin \
    config/logstash/pipeline \
    config/prometheus/alerts \
    config/grafana/provisioning/datasources \
    config/grafana/dashboards \
    config/portal/templates \
    config/policies \
    services/profiler/app \
    services/posture-engine/app \
    services/guest-portal/backend \
    services/admin-ui/backend \
    ansible/inventory \
    tests/load \
    docs/switch-config-examples
do
    touch "$dir/.gitkeep"
done

echo "✓ Directory structure created"

# ── 5. Настраиваем git ──

git config core.autocrlf input 2>/dev/null || true

# ── 6. Добавляем файлы и коммитим ──

git add -A
git commit -m "feat: initial Open NAC system

Open-source Network Access Control system (Cisco ISE alternative)

Components:
- docker-compose.yml: 23 containers (FreeRADIUS, Galera, Redis, Kafka, ELK, EJBCA, Grafana)
- FreeRADIUS: full 802.1X config (EAP-TLS/PEAP/TTLS, SQL, LDAP/AD, Redis, REST, CoA, multi-site proxy)
- Policy Engine: FastAPI backend (authorization, profiling, events, CoA, guest accounts, admin API)
- Admin UI: Cloudflare-style React dashboard (endpoints, policies, NAS, auth log)
- MariaDB schema: RADIUS tables + NAC endpoints, policies, profiles, guest accounts, audit log
- Test suite: radclient tests, eapol_test configs

Architecture: multi-site HA with Galera cluster, Redis Sentinel, Keepalived VIP"

echo "✓ Initial commit created"
echo ""

# ── 7. Показываем что получилось ──

echo "============================================"
echo "  Repository ready!"
echo "============================================"
echo ""
echo "Files: $(git ls-files | wc -l)"
echo "Size:  $(du -sh .git | awk '{print $1}')"
echo ""
git log --oneline
echo ""

# ── 8. Инструкции для push ──

echo "============================================"
echo "  Следующие шаги — push в remote"
echo "============================================"
echo ""
echo "─── GitHub (новый репозиторий) ───"
echo ""
echo "  1. Создайте репозиторий на github.com (без README)"
echo "  2. Выполните:"
echo ""
echo "     git remote add origin git@github.com:YOUR_USER/open-nac.git"
echo "     git branch -M main"
echo "     git push -u origin main"
echo ""
echo "─── GitLab (новый репозиторий) ───"
echo ""
echo "  1. Создайте проект на gitlab.com"
echo "  2. Выполните:"
echo ""
echo "     git remote add origin git@gitlab.com:YOUR_USER/open-nac.git"
echo "     git branch -M main"
echo "     git push -u origin main"
echo ""
echo "─── Self-hosted Gitea/Forgejo ───"
echo ""
echo "     git remote add origin https://git.corp.local/infra/open-nac.git"
echo "     git push -u origin main"
echo ""
echo "─── Рекомендации по безопасности ───"
echo ""
echo "  • .env файл НЕ коммитится (в .gitignore)"
echo "  • Сертификаты (.pem, .key) НЕ коммитятся"
echo "  • Для секретов используйте:"
echo "    - GitHub: Settings → Secrets → Actions"
echo "    - GitLab: Settings → CI/CD → Variables"
echo "    - Self-hosted: HashiCorp Vault"
echo ""
echo "  • Включите branch protection на main:"
echo "    - Require PR reviews"
echo "    - Require CI/CD pass"
echo "    - No force push"
echo ""
