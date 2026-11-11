# Makefile targetsMatcher research — what the open-source community does (2026-11-11)

## The landscape

| Tool | Rules | Language/Engine | License | Notes |
|---|---|---|---|---|
| gitleaks | 222 | Go regex + per-rule entropy + keywords | MIT | the de-facto ruleset standard; `config/gitleaks.toml` is auto-generated from `cmd/generate` |
| trufflehog | ~800 detectors | Go, many with live verification | GPL-2.0 | breadth king; **license: do not copy code/rules text verbatim** |
| Kingfisher (MongoDB) | 1,051 | **Rust + Hyperscan (SIMD) + tree-sitter** | Apache-2.0 | fork of Nosey Parker; live validation + revocation; the current speed/state-of-the-art |
| Nosey Parker (Praetorian) | ~150 | Rust, custom regex engine | MIT | fast, structured rules (pre-filter + capture) |
| detect-secrets (Yelp) | ~30 plugins | Python, baseline-diff model | Apache-2.0 | low-FP philosophy |
| GitHub secret scanning | ~200 partner patterns | closed | — | the partner-pattern catalog is the reference for provider shapes |

## The two rule shapes that matter

1. **Provider-prefix rules** (~60% of gitleaks): distinctive literal prefix

   (`ghp_`, `AKIA`, `sk-ant-api03-`, `AIza`, `glpat-`, `dop_v1_`, `dckr_pat_`,
    `hf_`, `npm_`, `pypi-AgEI`, `xox[abprs]-`, `T3BlbkFJ` (OpenAI mid-token!)…)
    plus an exact-length/charset tail. Perfect fit for argv-guard's
    no-alloc needle+tail-run scanner — these port 1:1.
2. **Context-anchored rules**: gitleaks' generic shape is

   `keyword … separator … value{10,150}` with a **giant stopword list**
    (`author`, `monkey`, `keyboard`, `keychain`…) — their FP engineering.
    Ported to argv: keyword + `[=:]` + ≥16 token-charset chars, with a
    cheaper FP killer: keyword must not be immediately followed by a letter
    (kills `author`, `authorize`, `keyboard`, `keyring`… without stopwords).

## The gem: gitleaks has curl-command rules

`curl-auth-header` and `curl-auth-user` — regexes matching secrets *inside
curl command lines* (`-H "Authorization: Bearer …"`, `-u user:pass`). That is
literally argv-guard's use case, published by the gitleaks project. We port
the concept structurally (arg contains `Authorization:` + value) rather than
as one monster regex.

## Other transferable details

- **JWT detection**: `eyJ` prefix (base64 of `{"`) + two-dot structure —
gitleaks: `ey[a-zA-Z0-9]{17,}\.ey…\.` — our charset tail (includes `.`)
approximates this with `eyJ` + 40.
- **OpenAI**: the literal `T3BlbkFJ` appears mid-token in *every* OpenAI key —
a needle better than any prefix.
- **Per-rule entropy** (2.5–4.5 Shannon): gitleaks' FP control. Deliberately
NOT ported in v2 — on argv, entropy flags paths/flags/version strings;
the tail-run + keyword-structure rules give better precision per byte.
(Future: entropy only for unclassified ≥25-char runs.)
- **Kingfisher's trick** worth stealing later: Hyperscan SIMD prefilter +
tree-sitter context to know "this string is an argument to a token flag".
For a preload hook, tree-sitter is off the table; our flag-proximity rules
approximate it.

## Licensing

Prefix facts and shapes are not copyrightable expression, and gitleaks/
Nosey Parker/Kingfisher are MIT/Apache-2.0 anyway. trufflehog is GPL-2.0 —
**patterns were informed by, not copied from** it.

## v2 ruleset decision (implemented in src/matcher.rs)

- Tier A: ~45 provider-prefix rules (needle + tail-run), the ones a typical
dev ecosystem actually touches + broad OSS coverage
- Tier B: structural specials — JWT (`eyJ`+40), `Basic`  base64,
`Authorization:` header value, `pem-block`
- Tier C: keyword+`=`/`:`+≥16 (token/password/secret/api_key/credential…)
with the letter-follows-keyword FP killer
- NOT ported: entropy backstop, pattern-file loading, gitleaks stopword list
