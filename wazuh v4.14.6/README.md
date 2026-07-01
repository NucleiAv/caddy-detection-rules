# wazuh-caddy-ruleset

Wazuh decoder and detection rules for the Caddy web server.

Caddy is a modern open-source web server with automatic HTTPS. This ruleset parses its structured JSON access logs and detects common web attacks, reconnaissance activity, and anomalous behavior.
A working v4.14.6 implementation exists here. It includes a parent/child XML decoder pair and 29 detection rules (IDs 996000-996032) covering path traversal, SQL injection, XSS, command injection, Log4Shell JNDI injection, LFI/RFI file inclusion, SSRF, scanner user-agents, sensitive file and credential access, source control artifact access, encoding evasion, dangerous file uploads, double extension bypass, GraphQL introspection, brute force correlation, and directory enumeration. All rules use PCRE2 matching and are MITRE ATT&CK mapped. This repo includes a caddy.ini test file with 26 passing unit tests via runtests.py (3 frequency-based rules are excluded per convention as they require live traffic).

For v5.0, I spun up the beta2 Docker deployment, read the documentation for beta v5.0 and inspected the running manager to understand the new format. I also referred to [Issue #18806](https://github.com/wazuh/wazuh/issues/18806). Decoders are now stored as JSON assets at `/var/wazuh-manager/data/ruleset/` and follow a `name / parents / check / normalize` structure using ECS field names (confirmed by reading the built-in Apache and CloudTrail decoders). The v5.0 GitHub repo (`v5.0.0-beta2` branch) no longer contains decoder or rule source files in the `ruleset/` directory. No `wazuh-logtest` binary or `/logtest` API endpoint exists in beta2, so live testing of custom decoders is not currently possible. Based on the compiled decoder format observed in the running container, a reference v5.0 decoder for Caddy would look like:
```json
{
  "name": "decoder/caddy-access/0",
  "parents": ["decoder/core-wazuh-message/0"],
  "check": "string_equal($_tmp_json.logger, 'http.log.access')",
  "normalize": [
    {
      "map": [
        {"event.kind": "event"},
        {"event.category": "array_append(web)"},
        {"event.type": "array_append(access)"},
        {"event.action": "http-request"},
        {"event.dataset": "caddy-access"},
        {"service.type": "caddy"},
        {"source.ip": "$_tmp_json.request.remote_ip"},
        {"source.address": "$_tmp_json.request.remote_ip"},
        {"http.request.method": "$_tmp_json.request.method"},
        {"url.original": "$_tmp_json.request.uri"},
        {"destination.domain": "$_tmp_json.request.host"},
        {"http.response.status_code": "$_tmp_json.status"},
        {"http.response.body.bytes": "$_tmp_json.size"},
        {"event.duration": "$_tmp_json.duration"},
        {"network.protocol": "$_tmp_json.request.proto"},
        {"user_agent.original": "$_tmp_json.request.headers.User-Agent.0"}
      ]
    },
    {
      "check": "int_less($http.response.status_code, 400)",
      "map": [{"event.outcome": "success"}]
    },
    {
      "check": "int_greater_or_equal($http.response.status_code, 400)",
      "map": [{"event.outcome": "failure"}]
    },
    {
      "map": [{"_tmp_json": "delete()"}]
    }
  ],
  "enabled": true
}
```
So the decoder and rules are for wazuh 4.14.6

## What it detects

| Rule ID | Description | Level |
|---------|-------------|-------|
| 996000 | Caddy access log (base rule) | 0 |
| 996003 | Path traversal attempt | 10 |
| 996004 | SQL injection attempt | 10 |
| 996005 | Sensitive path probe | 8 |
| 996008 | XSS attempt in URI | 10 |
| 996009 | Command injection attempt | 10 |
| 996010 | Known scanner tool (sqlmap, nikto, gobuster, etc.) | 8 |
| 996011 | HTTP TRACE/TRACK method | 6 |
| 996012 | Log4Shell JNDI injection attempt | 15 |
| 996013 | Sensitive file access (wp-config, htaccess, etc.) | 8 |
| 996014 | Credential or private key file access (.env, id_rsa, etc.) | 12 |
| 996015 | Backup or database dump file access (.sql, .bak, etc.) | 10 |
| 996016 | Source control artifact access (.git, .svn, etc.) | 10 |
| 996017 | Application log file access | 8 |
| 996018 | Directory enumeration (repeated sensitive path probes) | 14 |
| 996019 | Aggressive scanning (repeated path traversal attempts) | 14 |
| 996020 | Request for suspicious filename (password, secret, token, etc.) | 8 |
| 996021 | Authentication endpoint access | 3 |
| 996022 | Possible brute force on auth endpoint | 10 |
| 996023 | Encoding evasion / WAF bypass attempt | 10 |
| 996024 | LFI/RFI file inclusion attempt | 12 |
| 996025 | SSRF attempt targeting internal resource | 12 |
| 996026 | GraphQL introspection or API schema probe | 8 |
| 996027 | Unusual or dangerous HTTP method (DEBUG, CONNECT, FUZZ, etc.) | 8 |
| 996028 | Suspicious User-Agent (empty or oversized) | 6 |
| 996029 | Dangerous file upload (web shell, script files) | 12 |
| 996030 | Oversized URI (possible fuzzing) | 8 |
| 996031 | Double extension bypass upload attempt (shell.php.jpg) | 13 |
| 996032 | Archive or macro-enabled file upload (.zip, .docm, etc.) | 8 |

All rules are PCRE2-based and MITRE ATT&CK mapped.

## Requirements

- Wazuh 4.x
- Caddy configured to write JSON access logs

## Caddy log format

Make sure Caddy is writing structured JSON logs. In your Caddyfile:

```
{
    log {
        format json
    }
}
```

A sample Caddy JSON log line looks like this:

```json
{"level":"info","ts":1700000000.0,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"10.0.0.1","remote_port":"12345","proto":"HTTP/1.1","method":"GET","host":"example.com","uri":"/","headers":{"User-Agent":["Mozilla/5.0"]}},"status":200,"size":1024,"duration":0.002}
```

## Installation

### Step 1. Copy the decoder file

```bash
cp caddy_decoders.xml /var/ossec/etc/decoders/caddy_decoders.xml
chown wazuh:wazuh /var/ossec/etc/decoders/caddy_decoders.xml
chmod 640 /var/ossec/etc/decoders/caddy_decoders.xml
```

### Step 2. Copy the rules file

```bash
cp caddy_rules.xml /var/ossec/etc/rules/caddy_rules.xml
chown wazuh:wazuh /var/ossec/etc/rules/caddy_rules.xml
chmod 640 /var/ossec/etc/rules/caddy_rules.xml
```

### Step 3. Configure Wazuh to read Caddy logs

Add the following to your Wazuh agent config (`/var/ossec/etc/ossec.conf`):

```xml
<localfile>
    <log_format>json</log_format>
    <location>/var/log/caddy/access.log</location>
</localfile>
```

### Step 4. Restart Wazuh

```bash
/var/ossec/bin/wazuh-control restart
```

## Testing with Docker

If you want to test the rules before deploying to a live Wazuh instance, you can use a Docker container.

### Step 1. Start a Wazuh manager container

```bash
docker run -d --name wazuh-test \
  -p 55000:55000 \
  wazuh/wazuh-manager:4.14.5

docker start wazuh-test
```

### Step 2. Load the rules into the container and restart

```bash
docker exec wazuh-test bash -c "
  cp /path/to/caddy_rules.xml /var/ossec/etc/rules/caddy_rules.xml &&
  chown wazuh:wazuh /var/ossec/etc/rules/caddy_rules.xml &&
  chmod 640 /var/ossec/etc/rules/caddy_rules.xml &&
  /var/ossec/bin/wazuh-control restart
"
```

### Step 3a. Test a single log line interactively

```bash
docker exec -it wazuh-test bash
/var/ossec/bin/wazuh-logtest
```

Paste any Caddy JSON log line and press Enter twice.

### Step 3b. Test using a log file

```bash
docker exec -i wazuh-test /var/ossec/bin/wazuh-logtest < test-logs.txt
```

### Step 3c. Test using a log file and save output

```bash
docker exec wazuh-test bash -c "
  cp /path/to/caddy_rules.xml /var/ossec/etc/rules/caddy_rules.xml &&
  chown wazuh:wazuh /var/ossec/etc/rules/caddy_rules.xml &&
  chmod 640 /var/ossec/etc/rules/caddy_rules.xml &&
  /var/ossec/bin/wazuh-control restart
" && sleep 5 && docker exec -i wazuh-test /var/ossec/bin/wazuh-logtest \
  < test-logs.txt \
  > logtest-output.txt 2>&1
```

### Step 4. View only rule hits from the output

```bash
grep -E "id:|description:|level:" logtest-output.txt
```

## Running the unit tests

This requires a local clone of the wazuh/wazuh source repo.

### Step 1. Copy the testing files into the container

```bash
docker cp /path/to/wazuh/ruleset/testing/runtests.py wazuh-test:/tmp/runtests.py
docker cp /path/to/wazuh/ruleset/testing/coverage.py wazuh-test:/tmp/coverage.py
docker cp /path/to/wazuh/ruleset/testing/. wazuh-test:/tmp/testing/
docker cp caddy.ini wazuh-test:/tmp/testing/tests/caddy.ini
```

### Step 2. Run the tests

```bash
docker exec wazuh-test bash -c "cd /tmp/testing && python3 runtests.py --path /var/ossec --testfile tests/caddy.ini"
```

Expected output:

```
|          File           |  Passed  |  Failed  |  Status  |
|./tests/caddy.ini        |    26    |    0     |    ✅     |
```

## Notes

- Rules 996018, 996019, and 996022 are frequency-based (brute force / repeated scanning correlation). They require multiple matching events within a time window and cannot be triggered with a single log line in wazuh-logtest.
- The `status` field is reserved by Wazuh and cannot be used in custom rules. Status-based detection (4xx, 5xx) is not supported.
- All patterns use PCRE2 (`type="pcre2"`) for proper literal dot matching and case-insensitive flags.
