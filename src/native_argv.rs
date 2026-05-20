//! Normalize Windows-style `signtool.exe` argv (`/pa`, `/v`, …) into GNU-style tokens for clap.
//!
//! Unknown slash-prefixed tokens are left untouched so Unix absolute paths still pass through.

use std::ffi::OsString;

#[cfg(any(windows, unix, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verb {
    CertStore,
    Verify,
    Sign,
    Timestamp,
    Catdb,
    Remove,
    Rdp,
    Unknown,
}

#[cfg(any(windows, unix, test))]
fn lossy(arg: &OsString) -> String {
    arg.to_string_lossy().into_owned()
}

#[cfg(any(windows, unix, test))]
fn is_verb(s: &str) -> Option<Verb> {
    match s.to_ascii_lowercase().as_str() {
        "verify" => Some(Verb::Verify),
        "cert-store" | "certstore" => Some(Verb::CertStore),
        "sign" => Some(Verb::Sign),
        "timestamp" => Some(Verb::Timestamp),
        "catdb" => Some(Verb::Catdb),
        "remove" => Some(Verb::Remove),
        "rdp" => Some(Verb::Rdp),
        _ => None,
    }
}

#[cfg(any(windows, unix))]
fn is_windows_slash_switch(arg: &OsString) -> bool {
    let s = arg.to_string_lossy();
    s.len() >= 2 && s.starts_with('/') && !s.starts_with("//")
}

#[cfg(any(windows, unix, test))]
fn strip_leading_slash(arg: &OsString) -> String {
    lossy(arg).trim_start_matches('/').to_ascii_lowercase()
}

/// Returns replacement argv pieces and how many **following** tokens to consume (0, 1, or 2).
#[cfg(any(windows, unix, test))]
fn translate_slash_switch(
    verb: Verb,
    key: &str,
    next: Option<&str>,
    next2: Option<&str>,
) -> (Vec<String>, usize) {
    use Verb::*;
    let n = next.map(str::trim);
    let n2 = next2.map(str::trim);
    match verb {
        Verify => match key {
            "pa" => (vec!["--policy".into(), "pa".into()], 0),
            "kp" => (vec!["--kp".into()], 0),
            "all" => (vec!["--all".into()], 0),
            "tw" => (vec!["--tw".into()], 0),
            "ms" => (vec!["--ms".into()], 0),
            "p7" => (vec!["--p7".into()], 0),
            "d" => (vec!["--d".into()], 0),
            "ph" => (vec!["--ph".into()], 0),
            "vr" => (vec!["--vr".into()], 0),
            "testroot" => (vec!["--testroot".into()], 0),
            "w2010pca" => (vec!["--w2010pca".into()], 0),
            "now2010pca" => (vec!["--now2010pca".into()], 0),
            "sl" => (vec!["--sl".into()], 0),
            "bp" => (vec!["--bp".into()], 0),
            "enclave" => (vec!["--enclave".into()], 0),
            "a" => (vec!["--catalog-search".into(), "all".into()], 0),
            "ad" => (vec!["--catalog-search".into(), "default-db".into()], 0),
            "as" => (vec!["--catalog-search".into(), "system".into()], 0),
            "pg" => {
                let v = n.unwrap_or("");
                (
                    vec![
                        "--policy".into(),
                        "pg".into(),
                        "--policy-guid".into(),
                        v.to_string(),
                    ],
                    1,
                )
            }
            "ag" => {
                let v = n.unwrap_or("");
                (vec!["--ag".into(), v.to_string()], 1)
            }
            "c" => {
                let v = n.unwrap_or("");
                (vec!["--c".into(), v.to_string()], 1)
            }
            "hash" => {
                let v = n.unwrap_or("sha256").to_ascii_lowercase();
                (vec!["--hash".into(), v], 1)
            }
            "o" => {
                let v = n.unwrap_or("");
                (vec!["--os-version-check".into(), v.to_string()], 1)
            }
            "r" => {
                let v = n.unwrap_or("");
                (vec!["--r".into(), v.to_string()], 1)
            }
            "sha1" => {
                let v = n.unwrap_or("");
                (vec!["--sha1".into(), v.to_string()], 1)
            }
            "ca" => {
                let v = n.unwrap_or("");
                (vec!["--ca".into(), v.to_string()], 1)
            }
            "u" => {
                let v = n.unwrap_or("");
                (vec!["--u".into(), v.to_string()], 1)
            }
            "ds" => {
                let v = n.unwrap_or("0");
                (vec!["--ds".into(), v.to_string()], 1)
            }
            "p7content" => {
                let v = n.unwrap_or("");
                (vec!["--p7content".into(), v.to_string()], 1)
            }
            "p7s" => {
                let v = n.unwrap_or("");
                (vec!["--p7s".into(), v.to_string()], 1)
            }
            "rust-sip-pe-digest-check" => (vec!["--rust-sip-pe-digest-check".into()], 0),
            "rust-sip-script-digest-check" => (vec!["--rust-sip-script-digest-check".into()], 0),
            "rust-sip-msi-digest-check" => (vec!["--rust-sip-msi-digest-check".into()], 0),
            "rust-sip-esd-digest-check" => (vec!["--rust-sip-esd-digest-check".into()], 0),
            "rust-sip-msix-digest-check" => (vec!["--rust-sip-msix-digest-check".into()], 0),
            "rust-sip-cab-digest-check" => (vec!["--rust-sip-cab-digest-check".into()], 0),
            "rust-sip-catalog-digest-check" => (vec!["--rust-sip-catalog-digest-check".into()], 0),
            "rust-sip-all-digest-checks" => (vec!["--rust-sip-all-digest-checks".into()], 0),
            _ => (vec![], 0),
        },
        CertStore => match key {
            "sm" => (vec!["--sm".into()], 0),
            "p" => {
                let v = n.unwrap_or("");
                (vec!["--p".into(), v.to_string()], 1)
            }
            "s" => {
                let v = n.unwrap_or("MY");
                (vec!["--s".into(), v.to_string()], 1)
            }
            "sha1" => {
                let v = n.unwrap_or("");
                (vec!["--sha1".into(), v.to_string()], 1)
            }
            _ => (vec![], 0),
        },
        Sign => match key {
            "a" => (vec!["--a".into()], 0),
            "sm" => (vec!["--sm".into()], 0),
            "as" => (vec!["--as".into()], 0),
            "ph" => (vec!["--ph".into()], 0),
            "nph" => (vec!["--nph".into()], 0),
            "uw" => (vec!["--uw".into()], 0),
            "dxml" => (vec!["--dxml".into()], 0),
            "ds" => (vec!["--ds".into()], 0),
            "f" => {
                let v = n.unwrap_or("");
                (vec!["--f".into(), v.to_string()], 1)
            }
            "p" => {
                let v = n.unwrap_or("");
                (vec!["--p".into(), v.to_string()], 1)
            }
            "n" => {
                let v = n.unwrap_or("");
                (vec!["--n".into(), v.to_string()], 1)
            }
            "i" => {
                let v = n.unwrap_or("");
                (vec!["--i".into(), v.to_string()], 1)
            }
            "sha1" => {
                let v = n.unwrap_or("");
                (vec!["--sha1".into(), v.to_string()], 1)
            }
            "csp" => {
                let v = n.unwrap_or("");
                (vec!["--csp".into(), v.to_string()], 1)
            }
            "kc" => {
                let v = n.unwrap_or("");
                (vec!["--kc".into(), v.to_string()], 1)
            }
            "s" => {
                let v = n.unwrap_or("MY");
                (vec!["--s".into(), v.to_string()], 1)
            }
            "fd" => {
                let v = n.unwrap_or("sha256").to_ascii_lowercase();
                (vec!["--fd".into(), v], 1)
            }
            "tr" => {
                let v = n.unwrap_or("");
                (vec!["--tr".into(), v.to_string()], 1)
            }
            "tseal" => {
                let v = n.unwrap_or("");
                (vec!["--tseal".into(), v.to_string()], 1)
            }
            "t" => {
                let v = n.unwrap_or("");
                (vec!["--t".into(), v.to_string()], 1)
            }
            "td" => {
                let v = n.unwrap_or("sha256").to_ascii_lowercase();
                (vec!["--td".into(), v], 1)
            }
            "d" => {
                let v = n.unwrap_or("");
                (vec!["--d".into(), v.to_string()], 1)
            }
            "du" => {
                let v = n.unwrap_or("");
                (vec!["--du".into(), v.to_string()], 1)
            }
            "ac" => {
                let v = n.unwrap_or("");
                (vec!["--ac".into(), v.to_string()], 1)
            }
            "r" => {
                let v = n.unwrap_or("");
                (vec!["--r".into(), v.to_string()], 1)
            }
            "u" => {
                let v = n.unwrap_or("");
                (vec!["--u".into(), v.to_string()], 1)
            }
            "dlib" => {
                let v = n.unwrap_or("");
                (vec!["--dlib".into(), v.to_string()], 1)
            }
            "dmdf" => {
                let v = n.unwrap_or("");
                (vec!["--dmdf".into(), v.to_string()], 1)
            }
            "dg" => {
                let v = n.unwrap_or("");
                (vec!["--dg".into(), v.to_string()], 1)
            }
            "di" => {
                let v = n.unwrap_or("");
                (vec!["--di".into(), v.to_string()], 1)
            }
            "p7" => {
                let v = n.unwrap_or("");
                (vec!["--p7".into(), v.to_string()], 1)
            }
            "p7co" => {
                let v = n.unwrap_or("");
                (vec!["--p7co".into(), v.to_string()], 1)
            }
            "p7ce" => {
                let v = n.unwrap_or("");
                (vec!["--p7ce".into(), v.to_string()], 1)
            }
            "c" => {
                let v = n.unwrap_or("");
                (vec!["--certificate-template".into(), v.to_string()], 1)
            }
            "sa" => {
                let oid = n.unwrap_or("");
                let val = n2.unwrap_or("");
                if oid.is_empty() || val.is_empty() {
                    (vec![], 0)
                } else {
                    (
                        vec!["--sign-auth".into(), oid.to_string(), val.to_string()],
                        2,
                    )
                }
            }
            "fdchw" => (vec!["--fdchw".into()], 0),
            "tdchw" => (vec!["--tdchw".into()], 0),
            "rmc" => (vec!["--rmc".into()], 0),
            "seal" => (vec!["--seal".into()], 0),
            "itos" => (vec!["--itos".into()], 0),
            "force" => (vec!["--force".into()], 0),
            "nosealwarn" => (vec!["--nosealwarn".into()], 0),
            "noenclavewarn" => (vec!["--noenclavewarn".into()], 0),
            "rust-sip" => {
                let v = n.unwrap_or("pe").to_ascii_lowercase();
                (vec!["--rust-sip".into(), v], 1)
            }
            _ => (vec![], 0),
        },
        Timestamp => match key {
            "tr" => {
                let v = n.unwrap_or("");
                (vec!["--tr".into(), v.to_string()], 1)
            }
            "tseal" => {
                let v = n.unwrap_or("");
                (vec!["--tseal".into(), v.to_string()], 1)
            }
            "t" => {
                let v = n.unwrap_or("");
                (vec!["--t".into(), v.to_string()], 1)
            }
            "td" => {
                let v = n.unwrap_or("sha256").to_ascii_lowercase();
                (vec!["--td".into(), v], 1)
            }
            "tp" => {
                let v = n.unwrap_or("0");
                (vec!["--tp".into(), v.to_string()], 1)
            }
            "p7" => (vec!["--p7".into()], 0),
            "force" => (vec!["--force".into()], 0),
            "nosealwarn" => (vec!["--nosealwarn".into()], 0),
            _ => (vec![], 0),
        },
        Catdb => match key {
            "d" => (vec!["--d".into()], 0),
            "g" => {
                let v = n.unwrap_or("");
                (vec!["--g".into(), v.to_string()], 1)
            }
            "r" => (vec!["--r".into()], 0),
            "u" => (vec!["--u".into()], 0),
            _ => (vec![], 0),
        },
        Remove => match key {
            "s" => (vec!["--s".into()], 0),
            "c" => (vec!["--c".into()], 0),
            "u" => (vec!["--u".into()], 0),
            _ => (vec![], 0),
        },
        Rdp => match key {
            "sha1" => {
                let v = n.unwrap_or("");
                (vec!["--sha1".into(), v.to_string()], 1)
            }
            "sha256" => {
                let v = n.unwrap_or("");
                (vec!["--sha256".into(), v.to_string()], 1)
            }
            "l" => (vec!["--dry-run".into()], 0),
            _ => (vec![], 0),
        },
        Unknown => (vec![], 0),
    }
}

#[cfg(any(windows, unix))]
fn try_global_slash(arg: &OsString) -> Option<Vec<OsString>> {
    if !is_windows_slash_switch(arg) {
        return None;
    }
    let k = strip_leading_slash(arg);
    match k.as_str() {
        "q" => Some(vec![OsString::from("-q")]),
        "v" => Some(vec![OsString::from("-v")]),
        "debug" => Some(vec![OsString::from("--debug")]),
        _ => None,
    }
}

#[cfg(any(windows, unix))]
pub fn normalize_native_signtool_argv(args: Vec<OsString>) -> Vec<OsString> {
    if args.len() < 2 {
        return args;
    }

    let mut verb_idx: Option<usize> = None;
    let mut verb_kind = Verb::Unknown;
    for (i, arg) in args.iter().enumerate().skip(1) {
        let s = lossy(arg);
        if let Some(v) = is_verb(s.trim()) {
            verb_idx = Some(i);
            verb_kind = v;
            break;
        }
    }
    let Some(vi) = verb_idx else {
        return args;
    };

    let mut globals: Vec<OsString> = Vec::new();
    for arg in args.iter().skip(1).take(vi - 1) {
        if let Some(g) = try_global_slash(arg) {
            globals.extend(g);
        } else {
            globals.push(arg.clone());
        }
    }

    let mut out: Vec<OsString> = Vec::with_capacity(args.len() + 4);
    out.push(args[0].clone());
    out.extend(globals);
    out.push(OsString::from(lossy(&args[vi]).to_ascii_lowercase()));

    let mut i = vi + 1;
    while i < args.len() {
        let arg = &args[i];
        if let Some(g) = try_global_slash(arg) {
            out.extend(g);
            i += 1;
            continue;
        }
        if !is_windows_slash_switch(arg) {
            out.push(arg.clone());
            i += 1;
            continue;
        }
        let key = strip_leading_slash(arg);
        let next = args.get(i + 1).map(lossy);
        let next2 = args.get(i + 2).map(lossy);
        let (pieces, eat) =
            translate_slash_switch(verb_kind, &key, next.as_deref(), next2.as_deref());
        if pieces.is_empty() {
            // Unknown `/foo`: pass through unchanged for clap to report.
            out.push(arg.clone());
            i += 1;
            continue;
        }
        for p in pieces {
            out.push(OsString::from(p));
        }
        i += 1 + eat;
    }

    out
}

#[cfg(not(any(windows, unix)))]
pub fn normalize_native_signtool_argv(args: Vec<OsString>) -> Vec<OsString> {
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translate_verify_pa() {
        let (v, e) = translate_slash_switch(Verb::Verify, "pa", None, None);
        assert_eq!(e, 0);
        assert_eq!(v, vec!["--policy", "pa"]);
    }

    #[test]
    fn translate_cert_store_selection_aliases() {
        let (sm, esm) = translate_slash_switch(Verb::CertStore, "sm", None, None);
        assert_eq!(esm, 0);
        assert_eq!(sm, vec!["--sm"]);
        let (store, estore) = translate_slash_switch(Verb::CertStore, "s", Some("Root"), None);
        assert_eq!(estore, 1);
        assert_eq!(store, vec!["--s", "Root"]);
        let (sha1, esha1) = translate_slash_switch(
            Verb::CertStore,
            "sha1",
            Some("0011223344556677889900112233445566778899"),
            None,
        );
        assert_eq!(esha1, 1);
        assert_eq!(
            sha1,
            vec!["--sha1", "0011223344556677889900112233445566778899"]
        );
        let (password, epassword) =
            translate_slash_switch(Verb::CertStore, "p", Some("secret"), None);
        assert_eq!(epassword, 1);
        assert_eq!(password, vec!["--p", "secret"]);
    }

    #[test]
    fn translate_verify_pg_guid() {
        let (v, e) = translate_slash_switch(
            Verb::Verify,
            "pg",
            Some("{F750E6C3-38EE-11d1-85E5-00C04FC295EE}"),
            None,
        );
        assert_eq!(e, 1);
        assert_eq!(
            v,
            vec![
                "--policy",
                "pg",
                "--policy-guid",
                "{F750E6C3-38EE-11d1-85E5-00C04FC295EE}"
            ]
        );
    }

    #[test]
    fn translate_verify_os_version_check() {
        let (v, e) = translate_slash_switch(Verb::Verify, "o", Some("386:10.0.26100.0"), None);
        assert_eq!(e, 1);
        assert_eq!(v, vec!["--os-version-check", "386:10.0.26100.0"]);
    }

    #[test]
    fn translate_verify_catalog_search_native_aliases() {
        let (a, ea) = translate_slash_switch(Verb::Verify, "a", None, None);
        assert_eq!(ea, 0);
        assert_eq!(a, vec!["--catalog-search", "all"]);
        let (ad, ead) = translate_slash_switch(Verb::Verify, "ad", None, None);
        assert_eq!(ead, 0);
        assert_eq!(ad, vec!["--catalog-search", "default-db"]);
        let (sys, es) = translate_slash_switch(Verb::Verify, "as", None, None);
        assert_eq!(es, 0);
        assert_eq!(sys, vec!["--catalog-search", "system"]);
    }

    #[test]
    fn translate_verify_sl_bp_enclave() {
        let (sl, e) = translate_slash_switch(Verb::Verify, "sl", None, None);
        assert_eq!(e, 0);
        assert_eq!(sl, vec!["--sl"]);
        let (bp, eb) = translate_slash_switch(Verb::Verify, "bp", None, None);
        assert_eq!(eb, 0);
        assert_eq!(bp, vec!["--bp"]);
        let (en, ee) = translate_slash_switch(Verb::Verify, "enclave", None, None);
        assert_eq!(ee, 0);
        assert_eq!(en, vec!["--enclave"]);
    }

    #[test]
    fn translate_verify_p7s_and_testroot() {
        let (v, e) = translate_slash_switch(Verb::Verify, "p7s", Some("C:\\sig.p7s"), None);
        assert_eq!(e, 1);
        assert_eq!(v, vec!["--p7s", "C:\\sig.p7s"]);
        let (t, et) = translate_slash_switch(Verb::Verify, "testroot", None, None);
        assert_eq!(et, 0);
        assert_eq!(t, vec!["--testroot"]);
    }

    #[test]
    fn translate_verify_value_switches_and_defaults() {
        for (key, value, flag) in [
            ("ag", "{F750E6C3-38EE-11d1-85E5-00C04FC295EE}", "--ag"),
            ("c", "driver.cat", "--c"),
            ("r", "Microsoft Root", "--r"),
            ("sha1", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "--sha1"),
            ("ca", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "--ca"),
            ("u", "1.3.6.1.5.5.7.3.3", "--u"),
            ("p7content", "payload.bin", "--p7content"),
        ] {
            let (v, e) = translate_slash_switch(Verb::Verify, key, Some(value), None);
            assert_eq!(e, 1, "{key}");
            assert_eq!(v, vec![flag, value], "{key}");
        }

        let (hash, eh) = translate_slash_switch(Verb::Verify, "hash", None, None);
        assert_eq!(eh, 1);
        assert_eq!(hash, vec!["--hash", "sha256"]);
        let (ds, eds) = translate_slash_switch(Verb::Verify, "ds", None, None);
        assert_eq!(eds, 1);
        assert_eq!(ds, vec!["--ds", "0"]);
    }

    #[test]
    fn translate_timestamp_force_flags() {
        let (f, ef) = translate_slash_switch(Verb::Timestamp, "force", None, None);
        assert_eq!(ef, 0);
        assert_eq!(f, vec!["--force"]);
        let (n, en) = translate_slash_switch(Verb::Timestamp, "nosealwarn", None, None);
        assert_eq!(en, 0);
        assert_eq!(n, vec!["--nosealwarn"]);
    }

    #[test]
    fn translate_timestamp_p7_td_tp_and_catdb_flags() {
        let (p7, ep7) = translate_slash_switch(Verb::Timestamp, "p7", None, None);
        assert_eq!(ep7, 0);
        assert_eq!(p7, vec!["--p7"]);
        let (td, etd) = translate_slash_switch(Verb::Timestamp, "td", None, None);
        assert_eq!(etd, 1);
        assert_eq!(td, vec!["--td", "sha256"]);
        let (tp, etp) = translate_slash_switch(Verb::Timestamp, "tp", Some("2"), None);
        assert_eq!(etp, 1);
        assert_eq!(tp, vec!["--tp", "2"]);

        for (key, flag) in [("d", "--d"), ("r", "--r"), ("u", "--u")] {
            let (v, e) = translate_slash_switch(Verb::Catdb, key, None, None);
            assert_eq!(e, 0, "{key}");
            assert_eq!(v, vec![flag], "{key}");
        }
        let (g, eg) = translate_slash_switch(Verb::Catdb, "g", Some("{GUID}"), None);
        assert_eq!(eg, 1);
        assert_eq!(g, vec!["--g", "{GUID}"]);
    }

    #[test]
    fn translate_remove_cu_flags() {
        let (c, ec) = translate_slash_switch(Verb::Remove, "c", None, None);
        assert_eq!(ec, 0);
        assert_eq!(c, vec!["--c"]);
        let (u, eu) = translate_slash_switch(Verb::Remove, "u", None, None);
        assert_eq!(eu, 0);
        assert_eq!(u, vec!["--u"]);
    }

    #[test]
    fn translate_rdp_rdpsign_switches() {
        let (sha, esha) = translate_slash_switch(Verb::Rdp, "sha256", Some("AABBCC"), None);
        assert_eq!(esha, 1);
        assert_eq!(sha, vec!["--sha256", "AABBCC"]);
        let (sha1, esha1) = translate_slash_switch(Verb::Rdp, "sha1", Some("001122"), None);
        assert_eq!(esha1, 1);
        assert_eq!(sha1, vec!["--sha1", "001122"]);
        let (dry, edry) = translate_slash_switch(Verb::Rdp, "l", None, None);
        assert_eq!(edry, 0);
        assert_eq!(dry, vec!["--dry-run"]);
    }

    #[test]
    fn translate_timestamp_tseal() {
        let (v, e) = translate_slash_switch(
            Verb::Timestamp,
            "tseal",
            Some("http://seal.example/ts"),
            None,
        );
        assert_eq!(e, 1);
        assert_eq!(v, vec!["--tseal", "http://seal.example/ts"]);
    }

    #[test]
    fn translate_sign_fd_tr() {
        let (v, e) = translate_slash_switch(Verb::Sign, "fd", Some("SHA384"), None);
        assert_eq!(e, 1);
        assert_eq!(v, vec!["--fd", "sha384"]);
        let (v2, e2) = translate_slash_switch(Verb::Sign, "tr", Some("http://ts/x"), None);
        assert_eq!(e2, 1);
        assert_eq!(v2, vec!["--tr", "http://ts/x"]);
    }

    #[test]
    fn translate_sign_value_switches_and_p7_modes() {
        for (key, value, flag) in [
            ("f", "cert.pfx", "--f"),
            ("p", "secret", "--p"),
            ("n", "Subject", "--n"),
            ("i", "Issuer", "--i"),
            ("sha1", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "--sha1"),
            (
                "csp",
                "Microsoft Enhanced RSA and AES Cryptographic Provider",
                "--csp",
            ),
            ("kc", "container", "--kc"),
            ("s", "MY", "--s"),
            ("td", "sha384", "--td"),
            ("d", "Description", "--d"),
            ("du", "https://example.invalid", "--du"),
            ("ac", "extra.cer", "--ac"),
            ("r", "Root", "--r"),
            ("u", "1.3.6.1.5.5.7.3.3", "--u"),
            ("dlib", "Azure.CodeSigning.Dlib.dll", "--dlib"),
            ("dmdf", "metadata.json", "--dmdf"),
            ("dg", "digest-dir", "--dg"),
            ("di", "signed-digest.p7", "--di"),
            ("p7", "out-dir", "--p7"),
            ("p7co", "1.3.6.1.4.1.311.2.1.4", "--p7co"),
            ("p7ce", "DetachedSignedData", "--p7ce"),
        ] {
            let (v, e) = translate_slash_switch(Verb::Sign, key, Some(value), None);
            assert_eq!(e, 1, "{key}");
            assert_eq!(v, vec![flag, value], "{key}");
        }

        let (store, es) = translate_slash_switch(Verb::Sign, "s", None, None);
        assert_eq!(es, 1);
        assert_eq!(store, vec!["--s", "MY"]);
    }

    #[test]
    fn translate_sign_tseal() {
        let (v, e) =
            translate_slash_switch(Verb::Sign, "tseal", Some("http://seal.example/ts"), None);
        assert_eq!(e, 1);
        assert_eq!(v, vec!["--tseal", "http://seal.example/ts"]);
    }

    #[test]
    fn translate_sign_certificate_template_c() {
        let (v, e) = translate_slash_switch(Verb::Sign, "c", Some("MyTemplate"), None);
        assert_eq!(e, 1);
        assert_eq!(v, vec!["--certificate-template", "MyTemplate"]);
    }

    #[test]
    fn translate_sign_sa_two_following_tokens() {
        let (v, e) =
            translate_slash_switch(Verb::Sign, "sa", Some("1.3.6.1.4.1.999"), Some("utf8value"));
        assert_eq!(e, 2);
        assert_eq!(v, vec!["--sign-auth", "1.3.6.1.4.1.999", "utf8value"]);
    }

    #[test]
    fn translate_sign_sealing_switches() {
        for (k, flag) in [
            ("fdchw", "--fdchw"),
            ("tdchw", "--tdchw"),
            ("rmc", "--rmc"),
            ("seal", "--seal"),
            ("itos", "--itos"),
            ("force", "--force"),
            ("nosealwarn", "--nosealwarn"),
            ("noenclavewarn", "--noenclavewarn"),
        ] {
            let (v, e) = translate_slash_switch(Verb::Sign, k, None, None);
            assert_eq!(e, 0, "{}", k);
            assert_eq!(v, vec![flag], "{}", k);
        }
    }

    #[test]
    fn translate_sign_rust_sip_pe() {
        let (v, e) = translate_slash_switch(Verb::Sign, "rust-sip", Some("pe"), None);
        assert_eq!(e, 1);
        assert_eq!(v, vec!["--rust-sip", "pe"]);
    }

    #[test]
    fn translate_sign_rust_sip_script() {
        let (v, e) = translate_slash_switch(Verb::Sign, "rust-sip", Some("script"), None);
        assert_eq!(e, 1);
        assert_eq!(v, vec!["--rust-sip", "script"]);
    }

    #[test]
    fn translate_verify_rust_sip_pe_digest_check() {
        let (v, e) = translate_slash_switch(Verb::Verify, "rust-sip-pe-digest-check", None, None);
        assert_eq!(e, 0);
        assert_eq!(v, vec!["--rust-sip-pe-digest-check"]);
    }

    #[test]
    fn translate_verify_rust_sip_script_digest_check() {
        let (v, e) =
            translate_slash_switch(Verb::Verify, "rust-sip-script-digest-check", None, None);
        assert_eq!(e, 0);
        assert_eq!(v, vec!["--rust-sip-script-digest-check"]);
    }

    #[test]
    fn translate_sign_rust_sip_msi() {
        let (v, e) = translate_slash_switch(Verb::Sign, "rust-sip", Some("msi"), None);
        assert_eq!(e, 1);
        assert_eq!(v, vec!["--rust-sip", "msi"]);
    }

    #[test]
    fn translate_verify_rust_sip_msi_digest_check() {
        let (v, e) = translate_slash_switch(Verb::Verify, "rust-sip-msi-digest-check", None, None);
        assert_eq!(e, 0);
        assert_eq!(v, vec!["--rust-sip-msi-digest-check"]);
    }

    #[test]
    fn translate_sign_rust_sip_esd() {
        let (v, e) = translate_slash_switch(Verb::Sign, "rust-sip", Some("esd"), None);
        assert_eq!(e, 1);
        assert_eq!(v, vec!["--rust-sip", "esd"]);
    }

    #[test]
    fn translate_verify_rust_sip_esd_digest_check() {
        let (v, e) = translate_slash_switch(Verb::Verify, "rust-sip-esd-digest-check", None, None);
        assert_eq!(e, 0);
        assert_eq!(v, vec!["--rust-sip-esd-digest-check"]);
    }

    #[test]
    fn translate_sign_rust_sip_msix() {
        let (v, e) = translate_slash_switch(Verb::Sign, "rust-sip", Some("msix"), None);
        assert_eq!(e, 1);
        assert_eq!(v, vec!["--rust-sip", "msix"]);
    }

    #[test]
    fn translate_verify_rust_sip_msix_digest_check() {
        let (v, e) = translate_slash_switch(Verb::Verify, "rust-sip-msix-digest-check", None, None);
        assert_eq!(e, 0);
        assert_eq!(v, vec!["--rust-sip-msix-digest-check"]);
    }

    #[test]
    fn translate_sign_rust_sip_cab() {
        let (v, e) = translate_slash_switch(Verb::Sign, "rust-sip", Some("cab"), None);
        assert_eq!(e, 1);
        assert_eq!(v, vec!["--rust-sip", "cab"]);
    }

    #[test]
    fn translate_verify_rust_sip_cab_digest_check() {
        let (v, e) = translate_slash_switch(Verb::Verify, "rust-sip-cab-digest-check", None, None);
        assert_eq!(e, 0);
        assert_eq!(v, vec!["--rust-sip-cab-digest-check"]);
    }

    #[test]
    fn translate_sign_rust_sip_catalog() {
        let (v, e) = translate_slash_switch(Verb::Sign, "rust-sip", Some("catalog"), None);
        assert_eq!(e, 1);
        assert_eq!(v, vec!["--rust-sip", "catalog"]);
    }

    #[test]
    fn translate_verify_rust_sip_catalog_digest_check() {
        let (v, e) =
            translate_slash_switch(Verb::Verify, "rust-sip-catalog-digest-check", None, None);
        assert_eq!(e, 0);
        assert_eq!(v, vec!["--rust-sip-catalog-digest-check"]);
    }

    #[test]
    fn translate_verify_rust_sip_all_digest_checks() {
        let (v, e) = translate_slash_switch(Verb::Verify, "rust-sip-all-digest-checks", None, None);
        assert_eq!(e, 0);
        assert_eq!(v, vec!["--rust-sip-all-digest-checks"]);
    }
}
