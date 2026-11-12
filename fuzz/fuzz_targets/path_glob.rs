#![no_main]
//! WS3: the three glob matchers (`PathPattern`, `IdPattern`,
//! `scopes_authorize`'s `path:` glob) agree with a reference implementation,
//! and `scopes_authorize` is OR-within / AND-across. Input: NUL-separated
//! `pattern \0 path \0 idpattern \0 id \0 scope...`. The matchers are memoised
//! (W3-1 / W3-2 fixed under `sbo-0qqq`), so wildcard-heavy inputs are exercised
//! too; a `path:` scope over the spec's wildcard cap fails closed by design, so
//! the scope assertions only run under the cap.

use libfuzzer_sys::fuzz_target;
use sbo_core::authorize::scopes_authorize;
use sbo_core::message::Path;
use sbo_core::policy::{IdPattern, PathPattern, PolicyVars};

fn reference_path(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let seg: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut memo = vec![vec![None; seg.len() + 1]; pat.len() + 1];
    fn go(pat: &[&str], seg: &[&str], i: usize, j: usize, memo: &mut Vec<Vec<Option<bool>>>) -> bool {
        if let Some(v) = memo[i][j] { return v; }
        let r = if i == pat.len() { j == seg.len() }
            else if pat[i] == "**" { (j..=seg.len()).any(|k| go(pat, seg, i + 1, k, memo)) }
            else if j == seg.len() { false }
            else { (pat[i] == "*" || pat[i] == seg[j]) && go(pat, seg, i + 1, j + 1, memo) };
        memo[i][j] = Some(r);
        r
    }
    go(&pat, &seg, 0, 0, &mut memo)
}

fn reference_glob(pattern: &str, s: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = s.chars().collect();
    let mut dp = vec![vec![false; t.len() + 1]; p.len() + 1];
    dp[0][0] = true;
    for i in 1..=p.len() {
        for j in 0..=t.len() {
            dp[i][j] = if p[i - 1] == '*' { dp[i - 1][j] || (j > 0 && dp[i][j - 1]) }
                       else { j > 0 && p[i - 1] == t[j - 1] && dp[i - 1][j - 1] };
        }
    }
    dp[p.len()][t.len()]
}

fuzz_target!(|data: &[u8]| {
    let s = sbo_fuzz::text(data);
    let mut parts = s.split('\0');
    let pattern = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let idpat = parts.next().unwrap_or("");
    let id = parts.next().unwrap_or("");
    let scopes: Vec<String> = parts.map(String::from).collect();
    let vars = PolicyVars::default();
    if let Ok(p) = Path::parse(path) {
        if !pattern.contains('$') {
            assert_eq!(PathPattern::new(pattern).matches(&p, &vars), reference_path(pattern, path), "PathPattern {pattern:?} vs {path:?}");
        }
    }
    if !idpat.contains('$') {
        assert_eq!(IdPattern::new(idpat).matches(id, &vars), reference_glob(idpat, id), "IdPattern {idpat:?} vs {id:?}");
    }
    let under_cap = |sc: &String| match sc.strip_prefix("path:") {
        Some(v) => sbo_core::policy::glob::segment_wildcards(v) <= sbo_core::policy::glob::MAX_WILDCARDS,
        None => true,
    };
    if scopes.iter().all(under_cap) {
        let r = scopes_authorize(&scopes, "post", path, Some("post.v1"));
        // Fail-closed shape: any scope with an unknown dimension (or a bare
        // `sign:` that is not `sign:sbo:`) ⇒ false.
        let bad = scopes.iter().any(|sc| match sc.split_once(':') {
            Some(("action" | "path" | "schema" | "as", _)) => false,
            Some(("sign", v)) => !v.starts_with("sbo:"),
            _ => true,
        });
        if bad { assert!(!r, "unknown scope dimension authorized: {scopes:?}"); }
        // Adding an `action:post` scope never flips false → true when an
        // action scope already exists (OR within a dimension only widens
        // that dimension; the others still gate).
        if !r && scopes.iter().any(|x| x.starts_with("action:")) {
            let mut more = scopes.clone();
            more.push("action:post".into());
            let r2 = scopes_authorize(&more, "post", path, Some("post.v1"));
            if r2 { assert!(scopes.iter().all(|x| !x.starts_with("action:") || x != "action:post")); }
        }
    }
});
