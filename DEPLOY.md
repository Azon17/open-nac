# Open NAC — Быстрое развёртывание для тестирования

## Требования к серверу

- **ОС**: Ubuntu 22.04 / 24.04 LTS (или Debian 12)
- **RAM**: 16 GB минимум (32 GB рекомендуется)
- **CPU**: 4 cores минимум
- **Диск**: 50 GB свободного места
- **Сеть**: статический IP, доступ к интернету для pull образов

## Шаг 1 — Установка Docker

```bash
# Обновляем систему
sudo apt update && sudo apt upgrade -y

# Устанавливаем Docker
curl -fsSL https://get.docker.com | sudo sh

# Добавляем пользователя в группу docker
sudo usermod -aG docker $USER

# Устанавливаем Docker Compose V2
sudo apt install -y docker-compose-plugin

# Перелогиниваемся чтобы группа применилась
exit
# ...заходим снова...

# Проверяем
docker --version
docker compose version
```

## Шаг 2 — Клонируем проект

```bash
cd ~
git clone https://github.com/Azon17/open-nac.git
cd open-nac
```

## Шаг 3 — Настраиваем переменные

```bash
cp .env.example .env
nano .env
```

**Обязательно меняем пароли** (замените `changeme_*` на свои):

```
MARIADB_ROOT_PASSWORD=MyStr0ngR00t!2025
MYSQL_PASSWORD=MyR4d1usP@ss!
REDIS_PASSWORD=MyR3d1sP@ss!
GALERA_BACKUP_PWD=MyG4l3raP@ss!
EJBCA_DB_PASSWORD=MyEjbc4P@ss!
GRAFANA_PASSWORD=MyGr4f4n4!
PORTAL_SECRET_KEY=MyP0rt4lS3cr3t!
ADMIN_SECRET_KEY=MyAdm1nS3cr3t!
```

## Шаг 4 — Генерируем тестовые сертификаты

```bash
mkdir -p config/freeradius/certs

# CA (Certificate Authority)
openssl req -new -x509 -days 3650 -nodes \
  -keyout config/freeradius/certs/ca.key \
  -out config/freeradius/certs/ca.pem \
  -subj "/C=RU/ST=Moscow/O=Open NAC/CN=Open NAC CA"

# Server certificate для FreeRADIUS
openssl req -new -nodes \
  -keyout config/freeradius/certs/server.key \
  -out config/freeradius/certs/server.csr \
  -subj "/C=RU/ST=Moscow/O=Open NAC/CN=radius.corp.local"

openssl x509 -req -days 730 \
  -in config/freeradius/certs/server.csr \
  -CA config/freeradius/certs/ca.pem \
  -CAkey config/freeradius/certs/ca.key \
  -CAcreateserial \
  -out config/freeradius/certs/server.pem

# DH parameters (занимает ~1 минуту)
openssl dhparam -out config/freeradius/certs/dh 2048

# Проверяем
ls -la config/freeradius/certs/
# Должны быть: ca.pem, ca.key, server.pem, server.key, dh
```

## Шаг 5 — Запускаем (поэтапно)

```bash
# Сначала БД и кэш (ждём пока Galera синхронизируется)
docker compose up -d mariadb-1
sleep 30
docker compose up -d mariadb-2 mariadb-3
sleep 20

# Проверяем Galera кластер
docker exec nac-mariadb-1 mysql -uroot -p"$MARIADB_ROOT_PASSWORD" \
  -e "SHOW STATUS LIKE 'wsrep_cluster_size';"
# Должно быть: 3

# Redis
docker compose up -d redis-1 redis-2 redis-3 redis-sentinel

# Kafka
docker compose up -d zookeeper kafka
sleep 15
docker compose up -d kafka-init

# Всё остальное
docker compose up -d

# Проверяем статус
docker compose ps
```

## Шаг 6 — Проверяем что работает

```bash
# Health checks
curl http://localhost:8000/health          # Policy Engine
curl http://localhost:9090/-/ready         # Prometheus
curl http://localhost:5601/api/status      # Kibana
curl http://localhost:3000/api/health      # Grafana

# RADIUS test
docker exec nac-freeradius-1 \
  radtest testuser testpass 127.0.0.1 0 testing123

# Полный тест (если radclient установлен на хосте)
chmod +x tests/radclient/test-all.sh
./tests/radclient/test-all.sh localhost
```

## Шаг 7 — Открываем веб-интерфейсы

| Сервис | URL | Логин / Пароль |
|--------|-----|----------------|
| Policy Engine API | http://SERVER_IP:8000/docs | — (Swagger UI) |
| Grafana | http://SERVER_IP:3000 | admin / (из .env) |
| Kibana | http://SERVER_IP:5601 | — |
| Prometheus | http://SERVER_IP:9090 | — |
| EJBCA | https://SERVER_IP:8444 | (настраивается при первом входе) |

## Шаг 8 — Подключаем тестовый коммутатор

На коммутаторе (пример Cisco):

```
! AAA
aaa new-model
aaa authentication dot1x default group radius
aaa authorization network default group radius
aaa accounting dot1x default start-stop group radius

! RADIUS server
radius server OPEN-NAC
 address ipv4 SERVER_IP auth-port 1812 acct-port 1813
 key YOUR_RADIUS_SECRET

! 802.1X globally
dot1x system-auth-control

! На порту
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 100
 authentication port-control auto
 dot1x pae authenticator
 mab
 authentication order dot1x mab
 authentication priority dot1x mab
```

Не забудьте добавить IP коммутатора в `clients.conf` или через API:

```bash
curl -X POST http://localhost:8000/api/v1/network-devices \
  -H "Content-Type: application/json" \
  -d '{
    "nasname": "10.0.1.1",
    "shortname": "test-switch",
    "type": "cisco",
    "secret": "YOUR_RADIUS_SECRET",
    "description": "Test switch"
  }'
```

## Полезные команды

```bash
# Логи FreeRADIUS (debug)
docker logs -f nac-freeradius-1

# Логи Policy Engine
docker logs -f nac-policy-engine

# Статус всех контейнеров
docker compose ps

# Перезапуск одного сервиса
docker compose restart freeradius-1

# Остановить всё
docker compose down

# Остановить и удалить данные (полный сброс)
docker compose down -v
```

## Устранение проблем

**Galera не стартует (mariadb-2/3 в restart loop)**:
```bash
docker compose down
docker volume rm open-nac_galera-2-data open-nac_galera-3-data
docker compose up -d mariadb-1 && sleep 30
docker compose up -d mariadb-2 mariadb-3
```

**FreeRADIUS не стартует**:
```bash
# Проверяем конфиг
docker exec nac-freeradius-1 radiusd -XC
# Смотрим логи
docker logs nac-freeradius-1
```

**Policy Engine не подключается к БД**:
```bash
# Проверяем ProxySQL
docker exec nac-proxysql mysql -h127.0.0.1 -P6032 -uradmin -padmin \
  -e "SELECT * FROM mysql_servers;"
```

**Kafka topics не создались**:
```bash
docker compose up kafka-init
docker exec nac-kafka kafka-topics.sh --bootstrap-server localhost:9092 --list
```
