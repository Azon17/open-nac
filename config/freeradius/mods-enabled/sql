###############################################################################
#  Open NAC — FreeRADIUS SQL Module (MariaDB через ProxySQL)
#  Эквивалент: Cisco ISE Internal Database + Oracle backend
#
#  Все SQL-запросы идут через ProxySQL (port 6033):
#    - READ: распределяются по всем Galera-узлам
#    - WRITE: направляются на primary writer
#
#  Таблицы:
#    radcheck / radreply       — локальные пользователи
#    radusergroup / radgroup*  — группы и VLAN assignment
#    radacct                   — accounting (сессии)
#    radpostauth               — лог аутентификаций
#    nac_endpoints              — реестр эндпоинтов (profiling)
#    nac_guest_accounts         — гостевые аккаунты
###############################################################################

sql {
	driver = "rlm_sql_mysql"
	dialect = "mysql"

	server = "proxysql"
	port = 6033
	login = "${MYSQL_USER}"
	password = "${MYSQL_PASSWORD}"
	radius_db = "${MYSQL_DATABASE}"

	#--- Connection pool ---
	pool {
		start = 5
		min = 3
		max = 32
		spare = 5
		uses = 0
		retry_delay = 30
		lifetime = 0
		idle_timeout = 60
	}

	#--- Маппинг таблиц ---
	read_clients = yes
	client_table = "nas"

	#--- Стандартные запросы FreeRADIUS ---
	#  Используем дефолтные из raddb/mods-config/sql/main/mysql/

	#--- Authorize: поиск пользователя ---
	authorize_check_query = "\
		SELECT id, username, attribute, value, op \
		FROM ${authcheck_table} \
		WHERE username = '%{SQL-User-Name}' \
		ORDER BY id"

	authorize_reply_query = "\
		SELECT id, username, attribute, value, op \
		FROM ${authreply_table} \
		WHERE username = '%{SQL-User-Name}' \
		ORDER BY id"

	authorize_group_check_query = "\
		SELECT ${groupcheck_table}.id, ${groupcheck_table}.groupname, \
			${groupcheck_table}.attribute, ${groupcheck_table}.value, \
			${groupcheck_table}.op \
		FROM ${groupcheck_table},${usergroup_table} \
		WHERE ${usergroup_table}.username = '%{SQL-User-Name}' \
		AND ${groupcheck_table}.groupname = ${usergroup_table}.groupname \
		ORDER BY ${groupcheck_table}.id"

	authorize_group_reply_query = "\
		SELECT ${groupreply_table}.id, ${groupreply_table}.groupname, \
			${groupreply_table}.attribute, ${groupreply_table}.value, \
			${groupreply_table}.op \
		FROM ${groupreply_table},${usergroup_table} \
		WHERE ${usergroup_table}.username = '%{SQL-User-Name}' \
		AND ${groupreply_table}.groupname = ${usergroup_table}.groupname \
		ORDER BY ${groupreply_table}.id"

	group_membership_query = "\
		SELECT groupname FROM ${usergroup_table} \
		WHERE username = '%{SQL-User-Name}' \
		ORDER BY priority"

	#--- Accounting ---
	accounting {
		reference = "%{tolower:type.%{Acct-Status-Type}.query}"

		type {
			start {
				query = "\
					INSERT INTO ${acct_table1} \
						(acctsessionid, acctuniqueid, username, realm, \
						nasipaddress, nasportid, nasporttype, \
						acctstarttime, acctupdatetime, \
						acctauthentic, connectinfo_start, \
						acctinputoctets, acctoutputoctets, \
						calledstationid, callingstationid, \
						acctterminatecause, servicetype, \
						framedprotocol, framedipaddress, \
						framedipv6address, framedipv6prefix, \
						framedinterfaceid, delegatedipv6prefix, \
						class) \
					VALUES \
						('%{Acct-Session-Id}', '%{Acct-Unique-Session-Id}', \
						'%{SQL-User-Name}', '%{Realm}', \
						'%{NAS-IP-Address}', '%{%{NAS-Port-ID}:-}', \
						'%{NAS-Port-Type}', \
						FROM_UNIXTIME(%{integer:Event-Timestamp}), \
						FROM_UNIXTIME(%{integer:Event-Timestamp}), \
						'%{Acct-Authentic}', '%{Connect-Info}', \
						0, 0, \
						'%{Called-Station-Id}', '%{Calling-Station-Id}', \
						'', '%{Service-Type}', \
						'%{Framed-Protocol}', '%{Framed-IP-Address}', \
						'%{Framed-IPv6-Address}', '%{Framed-IPv6-Prefix}', \
						'%{Framed-Interface-Id}', '%{Delegated-IPv6-Prefix}', \
						'%{Class}')"
			}

			interim-update {
				query = "\
					UPDATE ${acct_table1} SET \
						acctupdatetime = FROM_UNIXTIME(%{integer:Event-Timestamp}), \
						acctinterval = %{%{Acct-Delay-Time}:-0} + %{integer:%{Event-Timestamp}} - %{integer:%{Acct-Session-Time}} + %{integer:%{Event-Timestamp}}, \
						framedipaddress = '%{Framed-IP-Address}', \
						framedipv6address = '%{Framed-IPv6-Address}', \
						framedipv6prefix = '%{Framed-IPv6-Prefix}', \
						framedinterfaceid = '%{Framed-Interface-Id}', \
						delegatedipv6prefix = '%{Delegated-IPv6-Prefix}', \
						acctsessiontime = %{%{Acct-Session-Time}:-0}, \
						acctinputoctets = '%{%{Acct-Input-Gigawords}:-0}' \
							<< 32 | '%{%{Acct-Input-Octets}:-0}', \
						acctoutputoctets = '%{%{Acct-Output-Gigawords}:-0}' \
							<< 32 | '%{%{Acct-Output-Octets}:-0}' \
					WHERE acctuniqueid = '%{Acct-Unique-Session-Id}'"
			}

			stop {
				query = "\
					UPDATE ${acct_table2} SET \
						acctstoptime = FROM_UNIXTIME(%{integer:Event-Timestamp}), \
						acctsessiontime = %{%{Acct-Session-Time}:-0}, \
						acctinputoctets = '%{%{Acct-Input-Gigawords}:-0}' \
							<< 32 | '%{%{Acct-Input-Octets}:-0}', \
						acctoutputoctets = '%{%{Acct-Output-Gigawords}:-0}' \
							<< 32 | '%{%{Acct-Output-Octets}:-0}', \
						acctterminatecause = '%{Acct-Terminate-Cause}', \
						connectinfo_stop = '%{Connect-Info}' \
					WHERE acctuniqueid = '%{Acct-Unique-Session-Id}'"
			}
		}
	}

	#--- Post-Auth logging ---
	post-auth {
		query = "\
			INSERT INTO ${postauth_table} \
				(username, pass, reply, authdate, \
				class, calledstationid, callingstationid, nasipaddress) \
			VALUES \
				('%{SQL-User-Name}', '%{%{User-Password}:-%{Chap-Password}}', \
				'%{reply.Packet-Type}', NOW(), \
				'%{reply.Class}', '%{Called-Station-Id}', \
				'%{Calling-Station-Id}', '%{NAS-IP-Address}')"
	}
}

###############################################################################
#  NAC-специфичные SQL-запросы (вынесены в отдельные модули)
###############################################################################

#--- MAB: проверка MAC в nac_endpoints ---
sql nac_mab_check {
	driver = "rlm_sql_mysql"
	dialect = "mysql"
	server = "proxysql"
	port = 6033
	login = "${MYSQL_USER}"
	password = "${MYSQL_PASSWORD}"
	radius_db = "${MYSQL_DATABASE}"

	pool {
		start = 2
		min = 1
		max = 10
		spare = 2
	}

	authorize_check_query = "\
		SELECT e.id, e.mac_address AS username, \
			'Cleartext-Password' AS attribute, \
			e.mac_address AS value, ':=' AS op \
		FROM nac_endpoints e \
		WHERE e.mac_address = '%{tolower:%{Calling-Station-Id}}' \
		AND e.auth_status != 'rejected'"

	authorize_reply_query = "\
		SELECT e.id, e.mac_address AS username, \
			'Tunnel-Private-Group-Id' AS attribute, \
			COALESCE(p.default_vlan, '999') AS value, '=' AS op \
		FROM nac_endpoints e \
		LEFT JOIN nac_device_profiles p ON e.device_profile = p.name \
		WHERE e.mac_address = '%{tolower:%{Calling-Station-Id}}'"
}

#--- Обновление endpoint при accounting ---
sql nac_endpoint_update {
	driver = "rlm_sql_mysql"
	dialect = "mysql"
	server = "proxysql"
	port = 6033
	login = "${MYSQL_USER}"
	password = "${MYSQL_PASSWORD}"
	radius_db = "${MYSQL_DATABASE}"

	pool {
		start = 2
		min = 1
		max = 10
		spare = 2
	}

	accounting {
		reference = "nac_endpoint_upsert"
	}

	nac_endpoint_upsert {
		query = "\
			INSERT INTO nac_endpoints \
				(mac_address, ip_address, username, nas_ip, nas_port, \
				auth_status, auth_method, last_seen, last_auth) \
			VALUES \
				('%{tolower:%{Calling-Station-Id}}', \
				'%{Framed-IP-Address}', \
				'%{SQL-User-Name}', \
				'%{NAS-IP-Address}', \
				'%{%{NAS-Port-ID}:-}', \
				'authenticated', \
				'%{%{EAP-Type}:-MAB}', \
				NOW(), NOW()) \
			ON DUPLICATE KEY UPDATE \
				ip_address = VALUES(ip_address), \
				username = VALUES(username), \
				nas_ip = VALUES(nas_ip), \
				nas_port = VALUES(nas_port), \
				auth_status = VALUES(auth_status), \
				last_seen = NOW(), \
				last_auth = NOW()"
	}
}
