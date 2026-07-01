# Snort 3 Setup and Testing Notes (Caddy Rules)

This file is a plain record of how the Caddy Snort 3 rules were set up, what broke, how it was fixed, and how it was tested. Keep it around so the same steps don't need to be worked out again next time.

## Files in this folder

- `caddy_snort3.rules` - the Snort 3 rule file for detecting attacks against a Caddy web server (scanners, XSS, command injection, LFI/RFI, brute force, suspicious uploads, etc).
- `caddy.rules` - older/reference rule file.

## Environment

- Snort++ version: 3.12.2.0
- Snort config: `/etc/snort/snort.lua`
- Rules loaded with: `-R /path/to/caddy_snort3.rules`
- Test traffic: `caddy_test.pcap` (captured on localhost, Caddy running on 127.0.0.1:8080)

## Step 1: Validate the rule file loads

Command used to just check the rules parse correctly, without reading any pcap:

```bash
snort -c /etc/snort/snort.lua --plugin-path /usr/lib/snort_extra -R /path/to/caddy_snort3.rules --warn-all
```

This is a dry run. It loads the config and rules, reports errors and warnings, and exits without processing any traffic.

## Problems found and fixed

### Problem 1: unknown rule keyword "field"

Two rules (User-Agent scanner detection and User-Agent empty/oversized detection) were written like this:

```
http_header; field:"User-Agent";
```

Snort 3 does not have a standalone `field` keyword. `field` is a modifier that has to be attached directly to the buffer option, not written as its own separate option. So this was first changed to:

```
http_header:field "User-Agent";
```

### Problem 2: "Unrecognized header field name"

After the syntax fix above, Snort still rejected it, this time with:

```
ERROR: caddy_snort3.rules:45 Unrecognized header field name
ERROR: caddy_snort3.rules:140 Unrecognized header field name
```

Turns out the `field` option in Snort 3 only works for a small fixed list of headers that `http_inspect` specifically tracks internally (things like Host, Cookie, Content-Type, Content-Length, X-Forwarded-For). `User-Agent` is not one of them, so it can never be used with `field`, no matter how it's written.

Fix: drop `field` entirely and just use the plain `http_header` buffer (which contains all request headers), then match the specific header line using an anchored, multi-line pcre pattern instead. This is the same approach already used elsewhere in the file (the Log4Shell header rule, sid 3996033).

Before:
```
http_header:field "User-Agent"; pcre:"/(sqlmap|nikto|nmap|.../i"
```

After:
```
http_header; pcre:"/^User-Agent:\s*.*(sqlmap|nikto|nmap|.../mi"
```

The `m` flag makes `^` match the start of each header line, not just the start of the whole buffer, so it correctly targets only the User-Agent line.

Same fix applied to the empty/oversized User-Agent rule.

After this change, the rule file loaded clean:

```
Snort successfully validated the configuration (with 31 warnings).
```

The 31 remaining warnings are just "no fast pattern" notices for http2/http3 rules that only use pcre without a content match. These are performance notes, not errors, and don't block anything.

## Step 2: Test against a pcap

Made an output folder for logs:

```bash
mkdir /tmp/snort3-output
```

Ran Snort against a captured pcap of test traffic against Caddy:

```bash
snort -c /etc/snort/snort.lua -R /path/to/caddy_snort3.rules -r caddy_test.pcap -A fast -l /tmp/snort3-output/
```

First run produced 0 alerts, which was suspicious given the pcap had deliberate attack traffic in it.

### Problem 3: all packets failing checksum

Packet stats from that run showed almost every TCP packet failing checksum:

```
bad_tcp4_checksum: 641
bad_tcp6_checksum: 108
```

out of 749 TCP packets total. Only 7 packets ever made it to the binder/detection stage. This is a very common issue with pcaps captured on the same machine that generated the traffic (loopback or VM virtual NIC). The NIC/OS does checksum offload, meaning the real checksum gets calculated in hardware after the packet is captured, so what libpcap grabs looks invalid even though the traffic itself is completely fine.

By default Snort validates checksums (`checksum_eval = all`) and silently drops anything that fails before it reaches detection, which is why nothing matched.

Fix: override checksum evaluation for this test run only, using `--lua` on the command line:

```bash
snort -c /etc/snort/snort.lua --lua 'network = { checksum_eval = "none" }' -R /path/to/caddy_snort3.rules -r caddy_test.pcap -A fast -l /tmp/snort3-output/
```

This got 61 alerts across most of the rule set, confirming rules were matching correctly once packets could actually reach the detection engine.

Note: only turn checksum validation off for offline pcap analysis like this. On a live sensor watching real network traffic, leave checksum validation on, since a bad checksum in the wild can be a real sign of corrupted or spoofed packets.

## Final working commands

Validate rule syntax only (no traffic):
```bash
snort -c /etc/snort/snort.lua --plugin-path /usr/lib/snort_extra -R /path/to/caddy_snort3.rules --warn-all
```

Test rules against a pcap (checksum validation disabled for offline analysis):
```bash
mkdir -p /tmp/snort3-output
snort -c /etc/snort/snort.lua --lua 'network = { checksum_eval = "none" }' -R /path/to/caddy_snort3.rules -r caddy_test.pcap -A fast -l /tmp/snort3-output/
```

Check the alerts:
```bash
cat /tmp/snort3-output/alert_fast.txt
```

## Result

- 248 rules load without errors.
- 61 alerts fired against the test pcap, covering scanner detection, XSS, command injection, TRACE/TRACK method, sensitive file/path probing, credential file access, backup/db dump access, source control artifact access, log file access, directory enumeration, oversized URI, encoding evasion, LFI/RFI, SSRF, dangerous file upload, double extension bypass, archive/macro upload, auth endpoint access, and brute force detection on the auth endpoint.
- Both `User-Agent` rules (scanner tool detection and empty/oversized detection) fired correctly after the fix.

## If this needs to be done again

1. Always dry-run with `--warn-all` first before testing against real traffic. It catches syntax errors fast.
2. If a rule needs to check one specific HTTP header, don't assume `field` works for it. It only works for a handful of headers `http_inspect` already tracks. For anything else (like User-Agent, Referer, Accept-Language) use the plain `http_header` buffer with an anchored pcre using the `m` flag.
3. If a pcap gives zero alerts unexpectedly, check the packet stats for `bad_tcp4_checksum` / `bad_tcp6_checksum`. If most packets are failing checksum, it's almost always a capture artifact from loopback/local capture, not a real problem with the traffic or the rules.
