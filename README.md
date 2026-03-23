# Open NAC System

Open-source аналог Cisco ISE для Network Access Control.

## Архитектура

```
open-nac/
├── docker-compose.yml          # Основной compose-файл (HQ site)
├── docker-compose.branch.yml   # Compose для филиалов (overlay)
├── .env.example                # Шаблон переменных окружения
├── config/
│   ├── freeradius/
│   │   ├── radiusd.conf        # Основная конфигурация RADIUS
│   │   ├── clients.conf        # NAS-клиенты
│   │   ├── proxy.conf          # Multi-site проксирование
│   │   ├── huntgroups           # Группировка NAS по сайтам
│   │   ├── certs/              # EAP-TLS сертификаты
│   │   │   ├── ca.pem
│   │   │   ├── server.pem
│   │   │   └── server.key
│   │   ├── sites-enabled/
│   │   │   ├── default         # Основной virtual server
│   │   │   ├── inner-tunnel    # PEAP/TTLS inner tunnel
│   │   │   └── coa             # CoA virtual server
│   │   ├── mods-enabled/
│   │   │   ├── eap             # EAP-TLS / PEAP / TTLS
│   │   │   ├── sql             # MariaDB backend
│   │   │   ├── ldap            # AD/LDAP integration
│   │   │   ├── mschap          # MS-CHAPv2 via winbind
│   │   │   ├── redis           # Session cache
│   │   │   ├── rest            # REST API calls to policy-engine
│   │   │   └── python          # Custom Python modules
│   │   └── policy.d/
│   │       ├── nac-policy      # NAC-специфичные unlang-правила
│   │       ├── profiling       # Post-auth profiling triggers
│   │       └── coa-triggers    # CoA automation rules
│   ├── tacacs/
│   │   └── tac_plus.cfg        # TACACS+ конфигурация
│   ├── proxysql/
│   │   └── proxysql.cnf        # R/W splitting для Galera
│   ├── mariadb/
│   │   └── initdb.d/
│   │       └── 01-schema.sql   # Инициализация БД
│   ├── logstash/
│   │   ├── logstash.yml
│   │   └── pipeline/
│   │       ├── radius-auth.conf
│   │       ├── radius-acct.conf
│   │       └── syslog.conf
│   ├── prometheus/
│   │   ├── prometheus.yml
│   │   └── alerts/
│   │       ├── radius.rules.yml
│   │       └── infra.rules.yml
│   ├── grafana/
│   │   ├── provisioning/
│   │   │   ├── datasources/
│   │   │   └── dashboards/
│   │   └── dashboards/
│   │       ├── nac-overview.json
│   │       ├── radius-performance.json
│   │       └── endpoint-inventory.json
│   ├── portal/
│   │   └── templates/          # HTML-шаблоны guest portal
│   ├── certs/
│   │   ├── portal/             # TLS для guest portal
│   │   └── admin/              # TLS для admin UI
│   └── policies/
│       ├── authorization.yml   # Правила авторизации (YAML)
│       ├── profiling.yml       # Правила профилирования
│       └── posture.yml         # Правила posture compliance
├── services/
│   ├── policy-engine/          # Python FastAPI
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   ├── app/
│   │   │   ├── main.py
│   │   │   ├── api/
│   │   │   │   ├── endpoints.py
│   │   │   │   ├── policies.py
│   │   │   │   ├── auth.py
│   │   │   │   └── coa.py
│   │   │   ├── core/
│   │   │   │   ├── policy_evaluator.py
│   │   │   │   ├── coa_client.py
│   │   │   │   └── kafka_producer.py
│   │   │   ├── models/
│   │   │   │   ├── endpoint.py
│   │   │   │   ├── policy.py
│   │   │   │   └── session.py
│   │   │   └── integrations/
│   │   │       ├── fingerbank.py
│   │   │       ├── fleet.py
│   │   │       ├── active_directory.py
│   │   │       └── mdm.py
│   │   └── tests/
│   ├── profiler/               # Python profiling service
│   │   ├── Dockerfile
│   │   ├── app/
│   │   │   ├── main.py
│   │   │   ├── engines/
│   │   │   │   ├── fingerbank_engine.py
│   │   │   │   ├── p0f_engine.py
│   │   │   │   ├── nmap_engine.py
│   │   │   │   └── scoring.py
│   │   │   └── consumers/
│   │   │       └── kafka_consumer.py
│   │   └── tests/
│   ├── posture-engine/         # Posture compliance checker
│   │   ├── Dockerfile
│   │   ├── app/
│   │   │   ├── main.py
│   │   │   ├── fleet_client.py
│   │   │   ├── compliance_rules.py
│   │   │   └── coa_trigger.py
│   │   └── tests/
│   ├── guest-portal/           # React + FastAPI portal
│   │   ├── Dockerfile
│   │   ├── backend/
│   │   │   ├── main.py
│   │   │   ├── auth_providers/
│   │   │   │   ├── local.py
│   │   │   │   ├── oauth2.py
│   │   │   │   ├── saml.py
│   │   │   │   └── sms.py
│   │   │   └── scep_proxy.py
│   │   └── frontend/
│   │       └── src/
│   └── admin-ui/               # React admin dashboard
│       ├── Dockerfile
│       ├── backend/
│       │   └── main.py
│       └── frontend/
│           └── src/
│               ├── pages/
│               │   ├── Dashboard.tsx
│               │   ├── Endpoints.tsx
│               │   ├── Policies.tsx
│               │   ├── Sessions.tsx
│               │   ├── DeviceProfiles.tsx
│               │   ├── GuestAccounts.tsx
│               │   └── AuditLog.tsx
│               └── components/
├── ansible/
│   ├── inventory/
│   │   ├── production.yml
│   │   └── staging.yml
│   ├── playbooks/
│   │   ├── deploy-hq.yml
│   │   ├── deploy-branch.yml
│   │   ├── upgrade.yml
│   │   └── backup.yml
│   └── roles/
│       ├── freeradius/
│       ├── mariadb-galera/
│       ├── keepalived/
│       └── monitoring/
├── tests/
│   ├── eapol_test/             # 802.1X test configs
│   │   ├── peap-mschapv2.conf
│   │   ├── eap-tls.conf
│   │   └── mab.conf
│   ├── radclient/              # RADIUS test scripts
│   │   ├── test-auth.sh
│   │   ├── test-acct.sh
│   │   └── test-coa.sh
│   └── load/                   # Нагрузочное тестирование
│       └── radperf.sh
└── docs/
    ├── architecture.md
    ├── deployment-guide.md
    ├── switch-config-examples/
    │   ├── cisco-catalyst.md
    │   ├── juniper-ex.md
    │   ├── aruba-cx.md
    │   └── hp-procurve.md
    └── troubleshooting.md
```

## Быстрый старт

```bash
# 1. Клонировать и настроить
git clone <repo-url> open-nac && cd open-nac
cp .env.example .env
# Редактировать .env — изменить ВСЕ пароли changeme_*

# 2. Запустить стек
docker compose up -d

# 3. Проверить статус
docker compose ps
docker compose logs -f freeradius-1

# 4. Тестовая аутентификация
radtest testuser testpass 127.0.0.1:1812 0 testing123
```

## Порты

| Сервис | Порт | Протокол | Назначение |
|--------|------|----------|------------|
| FreeRADIUS-1 | 1812/1813 | UDP | Auth/Acct |
| FreeRADIUS-1 | 3799 | UDP | CoA/DM |
| FreeRADIUS-2 | 11812/11813 | UDP | Auth/Acct (secondary) |
| TACACS+ | 49 | TCP | Device administration |
| Guest Portal | 8443 | TCP/HTTPS | Captive portal |
| Admin UI | 443 | TCP/HTTPS | Dashboard |
| Policy API | 8000 | TCP/HTTP | REST API |
| EJBCA | 8444 | TCP/HTTPS | PKI admin |
| Grafana | 3000 | TCP/HTTP | Мониторинг |
| Kibana | 5601 | TCP/HTTP | Логи |
| Prometheus | 9090 | TCP/HTTP | Метрики |
| ProxySQL | 6033 | TCP | MySQL frontend |

## Сопоставление с Cisco ISE

| ISE компонент | Open NAC эквивалент |
|---------------|---------------------|
| PAN (Policy Admin Node) | Admin UI + Policy Engine + MariaDB primary |
| PSN (Policy Service Node) | FreeRADIUS + Policy Engine |
| MnT (Monitoring Node) | ELK + Prometheus + Grafana |
| pxGrid | Apache Kafka |
| ISE Profiler | Profiler service + Fingerbank |
| ISE Posture | Posture Engine + osquery/Fleet |
| ISE Guest Portal | Guest Portal service |
| ISE CA | EJBCA Community Edition |
| TACACS+ Work Center | tac_plus-ng |
| ISE Internal DB (Oracle) | MariaDB Galera Cluster |
| ISE Messaging (RabbitMQ) | Apache Kafka |
| ISE Session Cache | Redis Sentinel |

## Лицензия

MIT
