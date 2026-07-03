# Caddy web server detection script for Zeek
# Created by NucleiAv
# Covers all 29 detection categories from the Wazuh v4.14.6 ruleset
# Tested with Zeek 5.x+
#
# Deploy: zeek -C -i <interface> caddy_detection.zeek
# Offline: zeek -C -r caddy_test.pcap caddy_detection.zeek
#
# Alerts are written to notice.log
# Frequency-based rules (996018, 996019, 996022) use per-source-IP counters
# with expiry tables to count events within a 60-second window.

module CaddyDetection;

export {
    redef enum Notice::Type += {
        CaddyDetection::PathTraversal,           # 996003
        CaddyDetection::SQLInjection,            # 996004
        CaddyDetection::SensitivePathProbe,      # 996005
        CaddyDetection::XSS,                     # 996008
        CaddyDetection::CommandInjection,        # 996009
        CaddyDetection::ScannerUserAgent,        # 996010
        CaddyDetection::TraceTrackMethod,        # 996011
        CaddyDetection::Log4Shell,               # 996012
        CaddyDetection::Log4ShellHeader,         # 996033
        CaddyDetection::SensitiveFileAccess,     # 996013
        CaddyDetection::CredentialFileAccess,    # 996014
        CaddyDetection::BackupFileAccess,        # 996015
        CaddyDetection::SourceControlAccess,     # 996016
        CaddyDetection::LogFileAccess,           # 996017
        CaddyDetection::DirectoryEnumeration,    # 996018 (frequency)
        CaddyDetection::AggressiveScanning,      # 996019 (frequency)
        CaddyDetection::SuspiciousFilename,      # 996020
        CaddyDetection::AuthEndpointAccess,      # 996021
        CaddyDetection::BruteForce,              # 996022 (frequency)
        CaddyDetection::EncodingEvasion,         # 996023
        CaddyDetection::LFI_RFI,                 # 996024
        CaddyDetection::SSRF,                    # 996025
        CaddyDetection::GraphQLProbe,            # 996026
        CaddyDetection::DangerousMethod,         # 996027
        CaddyDetection::SuspiciousUserAgent,     # 996028
        CaddyDetection::DangerousUpload,         # 996029
        CaddyDetection::OversizedURI,            # 996030
        CaddyDetection::DoubleExtensionUpload,   # 996031
        CaddyDetection::ArchiveUpload,           # 996032
    };
}

# -------------------------------------------------------------------------
# Frequency tracking tables for rules 996018, 996019, 996022
# Each table maps source IP -> event count within a 60-second window
# -------------------------------------------------------------------------

# 996018 - directory enumeration counter (sensitive path probes per src IP)
global dir_enum_count: table[addr] of count &default=0 &create_expire=60sec;

# 996019 - path traversal counter
global traversal_count: table[addr] of count &default=0 &create_expire=60sec;

# 996022 - auth endpoint brute force counter
global auth_brute_count: table[addr] of count &default=0 &create_expire=60sec;

# -------------------------------------------------------------------------
# Raw (still percent-encoded) request URI, keyed by connection uid.
# HTTP::Info$uri is always the decoded/normalized URI (Zeek decodes %XX
# before logging), equivalent to Suricata's http.uri buffer. Rules that
# need to see the still-encoded attack string (path traversal, SQLi,
# XSS, command injection, Log4Shell, encoding evasion, LFI/RFI, SSRF —
# the ones written against Suricata's http.uri.raw buffer) must check
# this raw copy instead, captured from the http_request event.
# -------------------------------------------------------------------------
global raw_uri_table: table[string] of string &create_expire=1min;

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    raw_uri_table[c$uid] = original_URI;
}

# -------------------------------------------------------------------------
# Main HTTP request detection hook
# Fires once per completed HTTP transaction with full request metadata
# -------------------------------------------------------------------------
hook HTTP::log_policy(rec: HTTP::Info, id: Log::ID, filter: Log::Filter)
{
    if ( !rec?$uri )
        return;

    local uri     = rec$uri;
    local raw_uri = rec$uid in raw_uri_table ? raw_uri_table[rec$uid] : uri;
    local method  = rec?$method      ? rec$method      : "";
    local ua      = rec?$user_agent  ? rec$user_agent  : "";
    local src_ip  = rec$id$orig_h;

    # ------------------------------------------------------------------
    # 996003 - Path traversal
    # ------------------------------------------------------------------
    if ( /(\.\.\x2f|\.\.\\|%2e%2e|%252e%252e)/i in raw_uri )
    {
        NOTICE([$note=CaddyDetection::PathTraversal,
                $src=src_ip,
                $msg=fmt("Caddy: Path traversal attempt - URI: %s", uri),
                $identifier=cat(src_ip, uri)]);

        # Feed frequency counter for 996019
        traversal_count[src_ip] += 1;
        if ( traversal_count[src_ip] >= 8 )
        {
            NOTICE([$note=CaddyDetection::AggressiveScanning,
                    $src=src_ip,
                    $msg=fmt("Caddy: Aggressive scanning - %d path traversal attempts in 60s from %s",
                             traversal_count[src_ip], src_ip),
                    $identifier=cat("traversal_flood", src_ip)]);
        }
    }

    # ------------------------------------------------------------------
    # 996004 - SQL injection
    # ------------------------------------------------------------------
    if ( /(union.+select|select.+from|insert.+into|drop.+table|(%27|')(\s|%20)*(or)(\s|%20)+|(\s|%20)(or)(\s|%20)+1(\s|%20)*(%3D|=)(\s|%20)*1)/i in raw_uri )
    {
        NOTICE([$note=CaddyDetection::SQLInjection,
                $src=src_ip,
                $msg=fmt("Caddy: SQL injection attempt - URI: %s", uri),
                $identifier=cat(src_ip, uri)]);
    }

    # ------------------------------------------------------------------
    # 996005 - Sensitive path probe
    # ------------------------------------------------------------------
    if ( /(\/\.env$|\/\.git|\/wp-admin|\/phpmyadmin|\/admin\.php|\/config\.php|\/backup)/i in uri )
    {
        NOTICE([$note=CaddyDetection::SensitivePathProbe,
                $src=src_ip,
                $msg=fmt("Caddy: Sensitive path probe - URI: %s", uri),
                $identifier=cat(src_ip, uri)]);

        # Feed frequency counter for 996018
        dir_enum_count[src_ip] += 1;
        if ( dir_enum_count[src_ip] >= 10 )
        {
            NOTICE([$note=CaddyDetection::DirectoryEnumeration,
                    $src=src_ip,
                    $msg=fmt("Caddy: Directory enumeration - %d sensitive path probes in 60s from %s",
                             dir_enum_count[src_ip], src_ip),
                    $identifier=cat("dir_enum_flood", src_ip)]);
        }
    }

    # ------------------------------------------------------------------
    # 996008 - XSS attempt in URI
    # ------------------------------------------------------------------
    if ( /(%3Cscript|<script|javascript:|onerror=|onload=|alert\(|document\.cookie|eval\()/i in raw_uri )
    {
        NOTICE([$note=CaddyDetection::XSS,
                $src=src_ip,
                $msg=fmt("Caddy: XSS attempt in URI - URI: %s", uri),
                $identifier=cat(src_ip, uri)]);
    }

    # ------------------------------------------------------------------
    # 996009 - Command injection
    # ------------------------------------------------------------------
    if ( /(%7C|%60|\||\`).*?(ls|id|whoami|cat\s|wget\s|curl\s|bash|\/bin\/sh|cmd\.exe)/i in raw_uri )
    {
        NOTICE([$note=CaddyDetection::CommandInjection,
                $src=src_ip,
                $msg=fmt("Caddy: Command injection attempt - URI: %s", uri),
                $identifier=cat(src_ip, uri)]);
    }

    # ------------------------------------------------------------------
    # 996010 - Known scanner or attack tool User-Agent
    # ------------------------------------------------------------------
    if ( /(sqlmap|nikto|nmap|masscan|nuclei|gobuster|dirbuster|wfuzz|acunetix|nessus|openvas|zgrab|whatweb)/i in ua )
    {
        NOTICE([$note=CaddyDetection::ScannerUserAgent,
                $src=src_ip,
                $msg=fmt("Caddy: Known scanner/attack tool detected - User-Agent: %s", ua),
                $identifier=cat(src_ip, ua)]);
    }

    # ------------------------------------------------------------------
    # 996011 - HTTP TRACE or TRACK method
    # ------------------------------------------------------------------
    if ( method == "TRACE" || method == "TRACK" )
    {
        NOTICE([$note=CaddyDetection::TraceTrackMethod,
                $src=src_ip,
                $msg=fmt("Caddy: HTTP %s method - possible cross-site tracing", method),
                $identifier=cat(src_ip, method)]);
    }

    # ------------------------------------------------------------------
    # 996012 - Log4Shell JNDI injection
    # ------------------------------------------------------------------
    if ( /(\$\{jndi:|%24%7Bjndi(%3A|:))/i in raw_uri )
    {
        NOTICE([$note=CaddyDetection::Log4Shell,
                $src=src_ip,
                $msg=fmt("Caddy: Log4Shell JNDI injection attempt - URI: %s", uri),
                $identifier=cat(src_ip, uri)]);
    }

    # ------------------------------------------------------------------
    # 996013 - Sensitive file access
    # ------------------------------------------------------------------
    if ( /(\/xmlrpc\.php|\/\.htaccess|\/\.htpasswd|\/wp-config\.php|\/config\.php|\/backup|\/dump\.sql|\/proc\/self|\/etc\/shadow)/i in uri )
    {
        NOTICE([$note=CaddyDetection::SensitiveFileAccess,
                $src=src_ip,
                $msg=fmt("Caddy: Sensitive file access attempt - URI: %s", uri),
                $identifier=cat(src_ip, uri)]);
    }

    # ------------------------------------------------------------------
    # 996014 - Credential or private key file access
    # ------------------------------------------------------------------
    if ( /(\/\.env(\.|$|\/)|\/id_rsa|\/id_dsa|\/id_ed25519|\/id_ecdsa|credentials?\.json|credentials?\.xml|secrets?\.json|secrets?\.ya?ml|jwt\.(pem|secret)|private\.key|oauth\.json|token\.json|authorized_keys|known_hosts|\.p12$|\.pfx$|\.pem$|\.key$)/i in uri )
    {
        NOTICE([$note=CaddyDetection::CredentialFileAccess,
                $src=src_ip,
                $msg=fmt("Caddy: Credential or private key file access - URI: %s", uri),
                $identifier=cat(src_ip, uri)]);
    }

    # ------------------------------------------------------------------
    # 996015 - Backup or database dump file access
    # ------------------------------------------------------------------
    if ( /\.(bak|backup|old|orig|save|swp|sql|dump|sqlite|db|mdb|tar\.gz|tar\.bz2|tgz|7z|rar)(\?|$)/i in uri )
    {
        NOTICE([$note=CaddyDetection::BackupFileAccess,
                $src=src_ip,
                $msg=fmt("Caddy: Backup or database dump file access - URI: %s", uri),
                $identifier=cat(src_ip, uri)]);
    }

    # ------------------------------------------------------------------
    # 996016 - Source control artifact access
    # ------------------------------------------------------------------
    if ( /(\/\.git(\/|$)|\/\.svn\/|\/\.hg\/|\/\.gitignore|\/\.gitattributes|\/\.gitmodules)/i in uri )
    {
        NOTICE([$note=CaddyDetection::SourceControlAccess,
                $src=src_ip,
                $msg=fmt("Caddy: Source control artifact access - URI: %s", uri),
                $identifier=cat(src_ip, uri)]);
    }

    # ------------------------------------------------------------------
    # 996017 - Application log file access
    # ------------------------------------------------------------------
    if ( /\/(error|access|debug|app|application|server|system|audit|exception)\.(log|txt|out)(\?|$)/i in uri )
    {
        NOTICE([$note=CaddyDetection::LogFileAccess,
                $src=src_ip,
                $msg=fmt("Caddy: Application log file access - URI: %s", uri),
                $identifier=cat(src_ip, uri)]);
    }

    # ------------------------------------------------------------------
    # 996020 - Request for suspicious filename
    # ------------------------------------------------------------------
    if ( /\/(password|passwd|secret|confidential|credential|private|token|apikey|api[_\-]key|auth)[^\/]*(\.[a-z]{1,5})?$/i in uri )
    {
        NOTICE([$note=CaddyDetection::SuspiciousFilename,
                $src=src_ip,
                $msg=fmt("Caddy: Request for suspicious filename - URI: %s", uri),
                $identifier=cat(src_ip, uri)]);
    }

    # ------------------------------------------------------------------
    # 996021 - Authentication endpoint access
    # 996022 - Brute force on auth endpoint (frequency: 10 in 60s)
    # ------------------------------------------------------------------
    if ( /\/(login|signin|sign-in|logon|auth|authenticate|wp-login\.php|admin\/login|account\/login|session\/new|user\/login|api\/login|api\/auth|oauth\/token|token)(\/|\?|$)/i in uri )
    {
        NOTICE([$note=CaddyDetection::AuthEndpointAccess,
                $src=src_ip,
                $msg=fmt("Caddy: Authentication endpoint access from %s - URI: %s", src_ip, uri),
                $identifier=cat(src_ip, uri)]);

        auth_brute_count[src_ip] += 1;
        if ( auth_brute_count[src_ip] >= 10 )
        {
            NOTICE([$note=CaddyDetection::BruteForce,
                    $src=src_ip,
                    $msg=fmt("Caddy: Possible brute force - %d auth endpoint hits in 60s from %s",
                             auth_brute_count[src_ip], src_ip),
                    $identifier=cat("brute_flood", src_ip)]);
        }
    }

    # ------------------------------------------------------------------
    # 996023 - Encoding evasion / WAF bypass
    # ------------------------------------------------------------------
    if ( /(%c0%ae|%c0%2f|%c1%9c|%uff0e|%u2215|%u002f|%252f|%255c|\.\.%ef%bc%8f|\.\.%c0%af)/i in raw_uri )
    {
        NOTICE([$note=CaddyDetection::EncodingEvasion,
                $src=src_ip,
                $msg=fmt("Caddy: Encoding evasion/WAF bypass attempt - URI: %s", uri),
                $identifier=cat(src_ip, uri)]);
    }

    # ------------------------------------------------------------------
    # 996024 - LFI/RFI file inclusion
    # ------------------------------------------------------------------
    if ( /(php:\/\/|phar:\/\/|data:\/\/|expect:\/\/|zip:\/\/|glob:\/\/|file:\/\/|gopher:\/\/|dict:\/\/|\.(php|phtml|phar).*=)/i in raw_uri )
    {
        NOTICE([$note=CaddyDetection::LFI_RFI,
                $src=src_ip,
                $msg=fmt("Caddy: LFI/RFI file inclusion attempt - URI: %s", uri),
                $identifier=cat(src_ip, uri)]);
    }

    # ------------------------------------------------------------------
    # 996025 - SSRF targeting internal resources
    # ------------------------------------------------------------------
    if ( /(169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2|100\.100\.100\.200)/i in raw_uri ||
         /[?&][^&]*=https?:\/\/(127\.|10\.|192\.168\.|localhost)/i in raw_uri ||
         /[?&][^&]*=https?:\/\/[^\/]*\.(internal|local|corp|intranet)/i in raw_uri )
    {
        NOTICE([$note=CaddyDetection::SSRF,
                $src=src_ip,
                $msg=fmt("Caddy: SSRF attempt targeting internal resource - URI: %s", uri),
                $identifier=cat(src_ip, uri)]);
    }

    # ------------------------------------------------------------------
    # 996026 - GraphQL introspection or API schema probe
    # ------------------------------------------------------------------
    if ( /(\/graphql|\/graphiql|\/gql|__schema|__type|__typename|introspectionquery)/i in uri )
    {
        NOTICE([$note=CaddyDetection::GraphQLProbe,
                $src=src_ip,
                $msg=fmt("Caddy: GraphQL introspection or API schema probe - URI: %s", uri),
                $identifier=cat(src_ip, uri)]);
    }

    # ------------------------------------------------------------------
    # 996027 - Unusual or dangerous HTTP method
    # ------------------------------------------------------------------
    if ( /^(CONNECT|DEBUG|MOVE|COPY|PROPFIND|PROPPATCH|MKCOL|LOCK|UNLOCK|BREW|TEST|FUZZ|SEARCH|PURGE)$/ in method )
    {
        NOTICE([$note=CaddyDetection::DangerousMethod,
                $src=src_ip,
                $msg=fmt("Caddy: Unusual or dangerous HTTP method - Method: %s", method),
                $identifier=cat(src_ip, method)]);
    }

    # ------------------------------------------------------------------
    # 996028 - Suspicious User-Agent (empty placeholder or oversized)
    # ------------------------------------------------------------------
    if ( /^(\[\]|''|-)$/ in ua || |ua| >= 500 )
    {
        NOTICE([$note=CaddyDetection::SuspiciousUserAgent,
                $src=src_ip,
                $msg=fmt("Caddy: Suspicious User-Agent (empty or oversized %d chars) from %s",
                         |ua|, src_ip),
                $identifier=cat(src_ip, "suspicious_ua")]);
    }

    # ------------------------------------------------------------------
    # 996029 - Dangerous file upload (web shell / executable extension)
    # ------------------------------------------------------------------
    if ( /(\/upload|\/uploads|\/files|\/media|\/assets|\/static)[^?]*\.(php[0-9]?|phtml|phar|asp|aspx|jsp|jspx|cfm|cgi|pl|py|rb|sh|exe|dll|bat|cmd|vbs|ps1)/i in uri )
    {
        NOTICE([$note=CaddyDetection::DangerousUpload,
                $src=src_ip,
                $msg=fmt("Caddy: Dangerous file upload attempt - URI: %s", uri),
                $identifier=cat(src_ip, uri)]);
    }

    # ------------------------------------------------------------------
    # 996030 - Oversized URI (possible fuzzing)
    # ------------------------------------------------------------------
    if ( |uri| >= 1000 )
    {
        NOTICE([$note=CaddyDetection::OversizedURI,
                $src=src_ip,
                $msg=fmt("Caddy: Oversized URI (%d chars) from %s - possible fuzzing", |uri|, src_ip),
                $identifier=cat(src_ip, "oversized_uri")]);
    }

    # ------------------------------------------------------------------
    # 996031 - Double extension upload bypass (e.g. shell.php.jpg)
    # ------------------------------------------------------------------
    if ( /(\/upload|\/uploads|\/files|\/media|\/assets|\/static)[^?]*\.(php[0-9]?|phtml|phar|asp|aspx|jsp|jspx|cfm|cgi|pl|py|rb|sh|exe|dll|bat|cmd|vbs|ps1)\.[a-z]{2,4}(\?|$)/i in uri )
    {
        NOTICE([$note=CaddyDetection::DoubleExtensionUpload,
                $src=src_ip,
                $msg=fmt("Caddy: Double extension upload bypass attempt - URI: %s", uri),
                $identifier=cat(src_ip, uri)]);
    }

    # ------------------------------------------------------------------
    # 996032 - Archive or macro-enabled file upload
    # ------------------------------------------------------------------
    if ( /(\/upload|\/uploads|\/files|\/media|\/assets|\/static)[^?]*\.(zip|rar|7z|tar|gz|tgz|iso|img|docm|xlsm|pptm|xlam|svg)(\?|$)/i in uri )
    {
        NOTICE([$note=CaddyDetection::ArchiveUpload,
                $src=src_ip,
                $msg=fmt("Caddy: Archive or macro-enabled file upload - URI: %s", uri),
                $identifier=cat(src_ip, uri)]);
    }

    if ( rec$uid in raw_uri_table )
        delete raw_uri_table[rec$uid];
}

# -------------------------------------------------------------------------
# 996033 - Log4Shell JNDI injection in request headers
# Fires per-header as Zeek parses the HTTP request, since HTTP::Info
# only exposes a handful of named fields (user_agent, host, referrer, ...)
# and not arbitrary header values.
# -------------------------------------------------------------------------
event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    if ( ! is_orig )
        return;

    if ( /(\$\{jndi:|%24%7Bjndi(%3A|:))/i in value )
    {
        NOTICE([$note=CaddyDetection::Log4ShellHeader,
                $src=c$id$orig_h,
                $msg=fmt("Caddy: Log4Shell JNDI injection attempt in header %s: %s", name, value),
                $identifier=cat(c$id$orig_h, name, value)]);
    }
}
