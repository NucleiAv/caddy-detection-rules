# caddy-detection-rules
A single detection logic, implemented and independently tested across four security tools: **Wazuh**, **Suricata**, **Snort 3**, and **Zeek**.

[Caddy](https://caddyserver.com) is a modern, widely used open-source web server with automatic HTTPS. Despite its adoption, it has little to no out-of-the-box detection coverage in most security monitoring stacks. This repo closes that gap with a ruleset covering **29 attack categories** — path traversal, SQL injection, XSS, command injection, Log4Shell (JNDI, both in URI and headers), LFI/RFI, SSRF, scanner/tool user-agents, sensitive file and credential access, source control artifact exposure, encoding evasion, dangerous file uploads, double-extension bypass, GraphQL introspection abuse, brute force correlation, and directory enumeration.

Every rule ID (996000–996033) is consistent across all four engines, so the same attack maps to the same rule number whether it's caught by Wazuh, Suricata, Snort, or Zeek.

## Why four tools

Each engine sees traffic differently, and porting the same logic across all of them surfaced real, tool-specific gaps that a single implementation would have hidden:

- **Wazuh** — log-based detection, parsing Caddy's structured JSON access logs via a custom decoder. ([wazuh v4.14.6/README.md](https://github.com/NucleiAv/caddy-detection-rules/blob/main/wazuh%20v4.14.6/README.md))
- **Suricata** — network-based detection, matching on live/replayed packet captures. ([suricata/README.md](https://github.com/NucleiAv/caddy-detection-rules/blob/main/suricata/README.md))
- **Snort 3** — network-based detection, using `http_inspect` buffers instead of Suricata's buffer model. ([snort/README.md](https://github.com/NucleiAv/caddy-detection-rules/blob/main/snort/README.md))
- **Zeek** — event-driven detection, using its scripting layer instead of static signatures — and the only one of the four where the raw vs. decoded URI distinction had to be handled manually. ([zeek/README.md](https://github.com/NucleiAv/caddy-detection-rules/blob/main/zeek/README.md))

## What's in this repo

| Folder | Tool | Contents |
|---|---|---|
| [`wazuh v4.14.6/`](./wazuh%20v4.14.6) | Wazuh | XML decoder + 29 rules, unit-tested with `runtests.py` (26/26 passing), plus a working v5.0 beta2 decoder migration |
| [`suricata/`](./suricata) | Suricata 8.0.5 | `caddy.rules` signature file, pcap + live-capture testing notes, `attack_traffic.sh` |
| [`snort/`](./snort) | Snort++ 3.12.2.0 | `caddy_snort3.rules`, pcap testing notes |
| [`zeek/`](./zeek) | Zeek 8.2.0 | `caddy_detection.zeek` event-driven script, pcap testing notes |

Each folder has its own README with full install steps, exact commands, every error hit along the way, and how it was fixed — treat those as the detailed lab notebooks. This top-level README is the map.

## Rule reference

All 29 rules use the same category and ID scheme across every engine:

| Rule ID | Description |
|---|---|
| 996003 | Path traversal attempt |
| 996004 | SQL injection attempt |
| 996005 | Sensitive path probe |
| 996008 | XSS attempt in URI |
| 996009 | Command injection attempt |
| 996010 | Known scanner/attack tool user-agent |
| 996011 | HTTP TRACE/TRACK method |
| 996012 | Log4Shell JNDI injection (URI) |
| 996033 | Log4Shell JNDI injection (headers) |
| 996013 | Sensitive file access |
| 996014 | Credential or private key file access |
| 996015 | Backup or database dump file access |
| 996016 | Source control artifact access |
| 996017 | Application log file access |
| 996018 | Directory enumeration (frequency-based) |
| 996019 | Aggressive scanning / repeated traversal (frequency-based) |
| 996020 | Suspicious filename (password, secret, token, etc.) |
| 996021 | Authentication endpoint access |
| 996022 | Brute force on auth endpoint (frequency-based) |
| 996023 | Encoding evasion / WAF bypass |
| 996024 | LFI/RFI file inclusion |
| 996025 | SSRF targeting internal resource |
| 996026 | GraphQL introspection / API schema probe |
| 996027 | Unusual/dangerous HTTP method |
| 996028 | Suspicious User-Agent (empty or oversized) |
| 996029 | Dangerous file upload |
| 996030 | Oversized URI (possible fuzzing) |
| 996031 | Double extension upload bypass |
| 996032 | Archive or macro-enabled file upload |

Three rules (996018, 996019, 996022) are frequency-based and require repeated matching events inside a time window rather than a single log line or packet.

## A cross-engine gotcha worth knowing up front

The most important lesson that came out of building this across four tools: **Wazuh, Suricata/Snort, and Zeek don't all give you the same URI by default.** Suricata and Snort expose a raw (`http.uri.raw`) buffer that preserves encoding, which is what rules like SQL injection, path traversal, and encoding evasion need to actually see the attack string. Zeek's default `HTTP::Info$uri` is already URL-decoded, which silently breaks 8 of the 29 rules unless you capture the raw URI separately via the `http_request` event. Details and the fix are in [`zeek/README.md`](./zeek/README.md#48-zeek-decodes-the-uri-before-the-script-ever-sees-it).

## Status

- **Wazuh v4.14.6** — complete, unit-tested (26/26 passing), submitted as [PR #37032](https://github.com/wazuh/wazuh/pull/37032) / [Issue #37033](https://github.com/wazuh/wazuh/issues/37033).
- **Wazuh v5.0** — decoder migrated to the new JSON asset format based on the built-in Apache/CloudTrail decoders; live testing blocked until `wazuh-logtest` / the `/logtest` API ships in beta.
- **Suricata, Snort 3, Zeek** — all 29 rules confirmed firing via pcap replay and live capture.

## License

GPL-3.0 — see [LICENSE](./LICENSE).
