//! Secret-shape matcher, v2 — informed by the OSS scanners:
//! gitleaks (222 rules, MIT), Kingfisher (MongoDB, 1051 rules, Rust+Hyperscan),
//! Nosey Parker, trufflehog. See docs/matcher-research.md.
//!
//! Hot path: no allocation, no syscalls — raw byte scans only.
//! Design fact: the guard is VETO-only (the shell expands $VARS before exec;
//! the child needs its real argv — redact-and-continue cannot exist).

/// Tail charset selector per pattern.
const CS_STD: u8 = 0; // alnum + . _ ~ -
const CS_UPPER32: u8 = 1; // A-Z, 2-7 (base32 — gitleaks' AWS family charset)

pub struct Pattern {
    pub name: &'static str,
    pub needle: &'static [u8],
    pub tail_min: usize,
    pub cs: u8,
}

const fn p(name: &'static str, needle: &'static [u8], tail_min: usize) -> Pattern {
    Pattern { name, needle, tail_min, cs: CS_STD }
}
const fn p32(name: &'static str, needle: &'static [u8], tail_min: usize) -> Pattern {
    Pattern { name, needle, tail_min, cs: CS_UPPER32 }
}

fn in_cs(b: u8, cs: u8) -> bool {
    match cs {
        CS_UPPER32 => b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b),
        _ => b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'~' || b == b'-',
    }
}

/// v2 table — curated from gitleaks' 222 rules for argv context.
/// (provider prefixes + tail shape; case-sensitive needles)
pub const PATTERNS: &[Pattern] = &[
    // GitHub (ghp_/gho_/ghu_/ghs_/ghr_ + fine-grained)
    p("github-app-token",      b"ghp_",         30),
    p("github-fine-grained",   b"github_pat_",  40),
    p("github-oauth",          b"gho_",         30),
    p("github-server-token",   b"ghs_",         30),
    p("github-refresh",        b"ghr_",         30),
    // GitLab
    p("gitlab-pat",            b"glpat-",       20),
    p("gitlab-runner",         b"glrt-",        20),
    // AI providers
    p("openai-key",            b"T3BlbkFJ",     40), // mid-token of every OpenAI key
    p("anthropic-api",         b"sk-ant-api03-", 60),
    p("anthropic-admin",       b"sk-ant-admin01-", 60),
    p("huggingface-token",     b"hf_",          30),
    // Cloud
    p32("aws-access-key",      b"AKIA",         16),
    p32("aws-access-key",      b"ASIA",         16),
    p32("aws-access-key",      b"ABIA",         16),
    p32("aws-access-key",      b"ACCA",         16),
    p32("aws-temp",            b"A3T",          16),
    p("gcp-api-key",           b"AIza",         35),
    p("alibaba-access-key",    b"LTAI",         20),
    p("digitalocean-pat",      b"dop_v1_",      40),
    p("digitalocean-oauth",    b"doo_v1_",      40),
    // registries / CI / SaaS
    p("npm-token",             b"npm_",         20),
    p("pypi-upload-token",     b"pypi-AgEI",    40),
    p("databricks-token",      b"dapi",         20),
    p("artifactory-ref",       b"cmVmd",        40),
    p("artifactory-api",       b"AKCp",         40),
    p("clojars-token",         b"CLOJARS_",     20),
    p("stripe-live-key",       b"sk_live_",     10),
    p("stripe-rk",             b"rk_live_",     10),
    p("shopify-pat",           b"shpat_",       20),
    p("postman-token",         b"PMAK-",        20),
    p("netlify-token",         b"nfp_",         20),
    p("sourcegraph-token",     b"sgp_",         20),
    p("linear-api-key",        b"lin_api_",     20),
    p("sentry-token",          b"sntrys_",      20),
    p("notion-integration",    b"secret_",      40),
    p("atlassian-token",       b"ATATT3",       60),
    p("flyio-token",           b"fo1_",         20),
    p("docker-pat",            b"dckr_pat_",    20),
    p("hashicorp-vault",       b"hvs.",         20),
    p("doppler-token",         b"dp.pt.",       20),
    p("dynatrace-token",       b"dt0c01.",      40),
    p("age-key",               b"AGE-SECRET-KEY-1", 30),
    p("easytest",              b"EZTK",         30),
    p("easyprod",              b"EZAK",         30),
    // chat
    p("slack-token",           b"xoxb-",        10),
    p("slack-token",           b"xoxp-",        10),
    p("slack-token",           b"xoxa-",        10),
    p("slack-token",           b"xoxs-",        10),
    // structural shapes
    p("openshift-oauth",       b"sha256~",      20),
    p("jwt",                   b"eyJ",          40),
    p("pem-block",             b"-----BEGIN",   0),
    p("bearer-token",          b"Bearer ",      18),
    p("basic-auth",            b"Basic ",       12),
];

fn contains(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    let last = hay.len() - needle.len();
    let first = needle[0];
    let mut i = 0;
    while i <= last {
        if hay[i] == first && &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Case-insensitive find for the keyword rules.
fn ci_contains(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    let last = hay.len() - needle.len();
    let mut i = 0;
    'outer: while i <= last {
        for (j, &n) in needle.iter().enumerate() {
            let h = hay[i + j];
            let hl = if h.is_ascii_uppercase() { h + 32 } else { h };
            let nl = if n.is_ascii_uppercase() { n + 32 } else { n };
            if hl != nl {
                i += 1;
                continue 'outer;
            }
        }
        return Some(i);
    }
    None
}

/// table + structural scan for one argv element.
/// Returns (pattern name, match offset, preview length).
pub fn scan_arg(s: &[u8]) -> Option<(&'static str, usize, usize)> {
    for p in PATTERNS {
        if let Some(pos) = contains(s, p.needle) {
            let tail = &s[pos + p.needle.len()..];
            let mut run = 0usize;
            for &b in tail {
                if in_cs(b, p.cs) {
                    run += 1;
                } else {
                    break;
                }
            }
            if run >= p.tail_min {
                return Some((p.name, pos, p.needle.len()));
            }
        }
    }
    scan_structural(s)
}

/// gitleaks' curl-auth-header/general-api-key concepts, ported to argv.
fn scan_structural(s: &[u8]) -> Option<(&'static str, usize, usize)> {
    // Authorization:<value> / X-Api-Key:<value> (col-space-skip, >=10 run)
    if let Some(pos) = ci_contains(s, b"uthorization:") {
        let mut v = pos + b"uthorization:".len();
        while v < s.len() && (s[v] == b' ' || s[v] == b'\t') {
            v += 1;
        }
        let mut run = 0usize;
        for &b in &s[v..] {
            if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-' | b'+' | b'/' | b'=' | b'%' | b'@') {
                run += 1;
            } else {
                break;
            }
        }
        if run >= 10 && v < s.len() && s[v] != b'<' {
            return Some(("auth-header", v, 6));
        }
    }
    // keyword (=|:) value  — the FP killer: a letter right after the keyword
    // disqualifies (author, authorize, keyboard, keyring, secretariat…)
    const KEYWORDS: &[&[u8]] = &[
        b"token", b"password", b"passwd", b"secret", b"apikey", b"api_key",
        b"api-key", b"access_key", b"access-key", b"credential", b"auth",
    ];
    for kw in KEYWORDS {
        if let Some(pos) = ci_contains(s, kw) {
            let mut v = pos + kw.len();
            // keyword must end at a non-letter boundary
            if v < s.len() && (s[v].is_ascii_alphabetic() || s[v] == b'_') {
                continue;
            }
            let mut seps = 0usize;
            while v < s.len() && (s[v] == b' ' || s[v] == b'\t') && seps < 3 {
                v += 1;
                seps += 1;
            }
            if v >= s.len() || (s[v] != b'=' && s[v] != b':') {
                continue;
            }
            v += 1;
            while v < s.len() && (s[v] == b' ' || s[v] == b'\t' || s[v] == b'"' || s[v] == b'\'') {
                v += 1;
            }
            let mut run = 0usize;
            for &b in &s[v..] {
                if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-' | b'+' | b'/' | b'=' | b'%') {
                    run += 1;
                } else {
                    break;
                }
            }
            if run >= 16 {
                return Some(("keyword-value", v, 6));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(s: &str) -> Option<&'static str> {
        scan_arg(s.as_bytes()).map(|(n, _, _)| n)
    }

    #[test]
    fn matches_real_shapes() {
        assert_eq!(hits("Authorization: Bearer ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"), Some("github-app-token"));
        assert_eq!(hits("oc login --token=sha256~eyJhbGciOiJSUzI1NiIsImtpZCI6"), Some("openshift-oauth"));
        assert_eq!(hits("awskey AKIAIOSFODNN7EXAMPLE"), Some("aws-access-key"));
        assert_eq!(hits("assume-role ASIAABCDEFGHIJKLMNOP"), Some("aws-access-key"));
        assert_eq!(hits("slack xoxb-123456789012-abcdef"), Some("slack-token"));
        assert_eq!(hits("HF_TOKEN=hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"), Some("huggingface-token"));
        assert_eq!(hits("glpat-abcdefghijklmnopqrst"), Some("gitlab-pat"));
        assert_eq!(hits("sk-proj-abc T3BlbkFJabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ"), Some("openai-key"));
        assert_eq!(hits("npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"), Some("npm-token"));
        assert_eq!(hits("vault login hvs.ABCDEFGHIJKLMNOPQRSTUVWXYZ1234"), Some("hashicorp-vault"));
        assert_eq!(hits("gcp key AIzaSyA1234567890abcdefghijklmnopqrstuv"), Some("gcp-api-key"));
        // JWT: eyJ + 40 charset incl dots
        assert_eq!(hits("tok eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeK"), Some("jwt"));
        assert_eq!(hits("-----BEGIN OPENSSH PRIVATE KEY-----"), Some("pem-block"));
        assert_eq!(hits("stripe sk_live_abcdefghijklmnopqrst"), Some("stripe-live-key"));
    }

    #[test]
    fn structural_rules() {
        assert_eq!(hits("curl -H 'Authorization: ZGVhZGJlZWZmZWVkY2FmZQ==' host"), Some("auth-header"));
        assert_eq!(hits("curl -H 'X-Api-Key: a1b2c3d4e5f6g7h8i9j0' host"), Some("keyword-value"));
        assert_eq!(hits("psql --password=supersecretpassword123"), Some("keyword-value"));
        assert_eq!(hits("cmd --token=abcdefghijklmnop"), Some("keyword-value"));
        assert_eq!(hits("run --auth:abcdefgh1234567890"), Some("keyword-value"));
    }

    #[test]
    fn no_false_positives() {
        assert_eq!(hits("grep -ri akia ./docs"), None);                     // lowercase needle
        assert_eq!(hits("echo the AKIA team meeting is at 3"), None);       // no 16-char tail
        assert_eq!(hits("ls /usr/share/doc/ASIA-pacific-region"), None);    // base32 charset: lowercase tail
        assert_eq!(hits("/usr/share/doc/Bearer"), None);
        assert_eq!(hits("Bearer of good news"), None);
        assert_eq!(hits("git commit -m 'add ghp_notes.md'"), None);
        assert_eq!(hits("export GITHUB_APP=ghp_"), None);
        assert_eq!(hits("the author=smith option"), None);                  // letter after keyword
        assert_eq!(hits("--keyboard-shortcuts"), None);                     // key+board
        assert_eq!(hits("--token-file=/long/path/value"), None);            // no sep within window
        assert_eq!(hits("psql --password=hunter2"), None);                  // value < 16
        assert_eq!(hits("curl -H 'Authorization: <token>'"), None);         // placeholder
        assert_eq!(hits("openssl req -newkey rsa:2048"), None);             // keyword absent
        assert_eq!(hits("xoxb-"), None);
        assert_eq!(scan_arg(b"").is_none(), true);
    }

    #[test]
    fn boundaries() {
        assert!(scan_arg(b"ghp_").is_none());
        assert!(hits("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ12345").is_some()); // 31-char run >= 30
        assert!(hits("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ12").is_none()); // 29-char run < 30
        assert!(hits("ghp_ABCDEFGHIJKLMNOP QR").is_none()); // run stops at space: 16 < 30
    }
}
