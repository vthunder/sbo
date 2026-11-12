//! The one glob matcher behind policy path patterns, policy id patterns and
//! warrant `path:` scopes (security audit 2026-11, W3-1 / W3-2, decision Q38 (c)).
//!
//! Both matchers are memoised (dynamic programming over the pattern × subject
//! table), so a pattern with `k` wildcards costs O(k·n) against an `n`-element
//! subject instead of the O(n^k) a backtracking matcher pays. On top of that
//! the Policy and Authorization specs state a size bound on wildcards per
//! pattern, [`MAX_WILDCARDS`], enforced where a pattern enters the system
//! (policy write, scope evaluation) — the same kind of bound as the 256-char
//! identifier limit.

/// The most wildcards (`*` or `**` segments of a path pattern or scope; `*`
/// characters of an id pattern) a single pattern may carry. A pattern over the
/// cap is rejected at policy write time and, for a warrant scope, fails closed
/// at evaluation. Generous on purpose: real patterns carry one or two.
pub const MAX_WILDCARDS: usize = 32;

/// Split a path pattern or path into its non-empty `/`-separated segments.
pub fn segments(s: &str) -> Vec<&str> {
    s.split('/').filter(|seg| !seg.is_empty()).collect()
}

/// Number of wildcard segments (`*` or `**`) in a path pattern or scope value.
pub fn segment_wildcards(pattern: &str) -> usize {
    segments(pattern).iter().filter(|s| **s == "*" || **s == "**").count()
}

/// Number of `*` characters in an id glob.
pub fn char_wildcards(pattern: &str) -> usize {
    pattern.matches('*').count()
}

/// Segment glob: `*` matches exactly one segment, `**` matches zero or more
/// segments, anything else matches a segment literally. Memoised: O(k·n).
pub fn segments_match(pat: &[&str], seg: &[&str]) -> bool {
    let (k, n) = (pat.len(), seg.len());
    // dp[i][j]: pat[i..] matches seg[j..]. Filled from the end so every
    // reference is to an already-computed cell.
    let mut dp = vec![vec![false; n + 1]; k + 1];
    dp[k][n] = true;
    for i in (0..k).rev() {
        for j in (0..=n).rev() {
            dp[i][j] = if pat[i] == "**" {
                dp[i + 1][j] || (j < n && dp[i][j + 1])
            } else {
                j < n && (pat[i] == "*" || pat[i] == seg[j]) && dp[i + 1][j + 1]
            };
        }
    }
    dp[0][0]
}

/// Character glob: `*` matches any run of characters (including none);
/// everything else is literal. Memoised: O(k·n). Compares by `char`, so a
/// multi-byte subject can never split a code point.
pub fn chars_match(pattern: &str, s: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = s.chars().collect();
    let mut dp = vec![vec![false; t.len() + 1]; p.len() + 1];
    dp[0][0] = true;
    for i in 1..=p.len() {
        for j in 0..=t.len() {
            dp[i][j] = if p[i - 1] == '*' {
                dp[i - 1][j] || (j > 0 && dp[i][j - 1])
            } else {
                j > 0 && p[i - 1] == t[j - 1] && dp[i - 1][j - 1]
            };
        }
    }
    dp[p.len()][t.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_semantics() {
        let m = |p: &str, s: &str| segments_match(&segments(p), &segments(s));
        assert!(m("/users/alice", "/users/alice/"));
        assert!(m("/users/*", "/users/bob/"));
        assert!(!m("/users/*", "/users/bob/x/"));
        assert!(m("/users/**", "/users/"));
        assert!(m("/users/**", "/users/a/b/c/"));
        assert!(m("/**/zz", "/a/b/zz/"));
        assert!(!m("/**/zz", "/a/b/"));
        assert!(m("/", "/"));
        assert!(!m("/a", "/"));
    }

    #[test]
    fn char_semantics() {
        assert!(chars_match("ev_*", "ev_"));
        assert!(chars_match("*a*b", "xxaxxb"));
        assert!(!chars_match("*a*b", "xxaxx"));
        assert!(chars_match("", ""));
        assert!(!chars_match("", "x"));
        assert!(chars_match("é*", "éclair"));
    }

    #[test]
    fn wildcard_heavy_patterns_are_fast() {
        let pat = format!("/{}/zz/", vec!["**"; 10].join("/"));
        let path = format!("/{}/", vec!["a"; 24].join("/"));
        assert!(!segments_match(&segments(&pat), &segments(&path)));
        assert!(!chars_match(&format!("{}b", "*a".repeat(14)), &"a".repeat(40)));
        assert_eq!(segment_wildcards("/a/*/**/b*"), 2);
        assert_eq!(char_wildcards("*a*b"), 2);
    }
}
