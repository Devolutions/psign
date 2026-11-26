//! Expand native `signtool @responsefile` argument lists (see `signtool-help-root.txt`).
//!
//! Delegates response-file parsing and expansion to [`psign_portable_core::response_file`].

pub use psign_portable_core::response_file::{
    decode_response_arg_token, expand_inline_args, expand_invocations, read_response_args,
};

/// Combine exit codes like a batch: any hard failure wins; else Azure HRESULT-style outcomes; else any warning.
pub fn combine_batch_exit_codes(acc: i32, next: i32) -> i32 {
    use crate::{AZURE_SIGN_EXIT_ALL_FAILED, AZURE_SIGN_EXIT_PARTIAL_SUCCESS};
    if acc == 1 || next == 1 {
        return 1;
    }
    if acc == AZURE_SIGN_EXIT_ALL_FAILED || next == AZURE_SIGN_EXIT_ALL_FAILED {
        return AZURE_SIGN_EXIT_ALL_FAILED;
    }
    if acc == AZURE_SIGN_EXIT_PARTIAL_SUCCESS || next == AZURE_SIGN_EXIT_PARTIAL_SUCCESS {
        return AZURE_SIGN_EXIT_PARTIAL_SUCCESS;
    }
    if acc == 2 || next == 2 { 2 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;

    #[test]
    fn expands_at_file_to_extra_args() {
        let dir = std::env::temp_dir();
        let inner = dir.join("psign_rsp_inner.txt");
        fs::write(&inner, "/pa\n").expect("write inner");
        let rsp = dir.join("psign_rsp_outer.txt");
        fs::write(&rsp, format!("verify\n@{}\nx.exe\n", inner.display())).expect("write rsp");

        let exe = OsString::from("psign-tool");
        let inv = expand_invocations(
            exe.clone(),
            vec![OsString::from(format!("@{}", rsp.display()))],
        )
        .expect("expand");
        assert_eq!(inv.len(), 1);
        assert_eq!(
            inv[0]
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>(),
            vec!["psign-tool", "verify", "/pa", "x.exe",]
        );
        let _ = fs::remove_file(&inner);
        let _ = fs::remove_file(&rsp);
    }

    #[test]
    fn at_only_form_two_command_blocks() {
        let dir = std::env::temp_dir();
        let rsp = dir.join("psign_rsp_multiblock.txt");
        fs::write(&rsp, "verify\n/pa\na.exe\n\nsign\n/fd\nSHA256\nb.exe\n").expect("write");

        let exe = OsString::from("psign-tool");
        let inv = expand_invocations(
            exe.clone(),
            vec![OsString::from(format!("@{}", rsp.display()))],
        )
        .expect("expand");
        assert_eq!(inv.len(), 2);
        assert_eq!(
            inv[0]
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>(),
            vec!["psign-tool", "verify", "/pa", "a.exe",]
        );
        assert_eq!(
            inv[1]
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>(),
            vec!["psign-tool", "sign", "/fd", "SHA256", "b.exe",]
        );
        let _ = fs::remove_file(&rsp);
    }

    #[test]
    fn combine_codes() {
        use crate::{AZURE_SIGN_EXIT_ALL_FAILED, AZURE_SIGN_EXIT_PARTIAL_SUCCESS};
        assert_eq!(combine_batch_exit_codes(0, 2), 2);
        assert_eq!(combine_batch_exit_codes(2, 0), 2);
        assert_eq!(combine_batch_exit_codes(2, 1), 1);
        assert_eq!(combine_batch_exit_codes(0, 1), 1);
        assert_eq!(combine_batch_exit_codes(0, 0), 0);
        assert_eq!(
            combine_batch_exit_codes(0, AZURE_SIGN_EXIT_PARTIAL_SUCCESS),
            AZURE_SIGN_EXIT_PARTIAL_SUCCESS
        );
        assert_eq!(
            combine_batch_exit_codes(AZURE_SIGN_EXIT_PARTIAL_SUCCESS, AZURE_SIGN_EXIT_ALL_FAILED),
            AZURE_SIGN_EXIT_ALL_FAILED
        );
        assert_eq!(
            combine_batch_exit_codes(AZURE_SIGN_EXIT_PARTIAL_SUCCESS, 1),
            1
        );
    }

    #[test]
    fn decode_response_arg_token_quotes() {
        assert_eq!(decode_response_arg_token("  plain  "), "plain");
        assert_eq!(
            decode_response_arg_token(r#""C:\Program Files\app.exe""#),
            r"C:\Program Files\app.exe"
        );
        assert_eq!(
            decode_response_arg_token(r#""say ""hi"" today""#),
            r#"say "hi" today"#
        );
    }

    #[test]
    fn response_file_quoted_path_single_argument() {
        let dir = std::env::temp_dir();
        let spaced = dir.join("psign_rsp spaced target.exe");
        fs::write(&spaced, b"0").expect("write target");
        let rsp = dir.join("psign_rsp_quoted_path.txt");
        fs::write(
            &rsp,
            format!("verify\n--policy\npa\n\"{}\"\n", spaced.to_string_lossy()),
        )
        .expect("write rsp");

        let exe = OsString::from("psign-tool");
        let inv = expand_invocations(
            exe.clone(),
            vec![OsString::from(format!("@{}", rsp.display()))],
        )
        .expect("expand");
        assert_eq!(inv.len(), 1);
        let argv: Vec<String> = inv[0]
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            argv,
            vec![
                "psign-tool".to_string(),
                "verify".to_string(),
                "--policy".to_string(),
                "pa".to_string(),
                spaced.to_string_lossy().into_owned(),
            ]
        );
        let _ = fs::remove_file(&spaced);
        let _ = fs::remove_file(&rsp);
    }

    #[test]
    fn response_file_quoted_include_path() {
        let dir = std::env::temp_dir();
        let inner_name = "signtool rs inner inc.txt";
        let inner = dir.join(inner_name);
        fs::write(&inner, "/pa\n").expect("write inner");
        let rsp = dir.join("psign_rsp_quote_include.txt");
        fs::write(
            &rsp,
            format!("verify\n\"@{}\"\nx.exe\n", inner.to_string_lossy()),
        )
        .expect("write rsp");

        let exe = OsString::from("psign-tool");
        let inv = expand_invocations(
            exe.clone(),
            vec![OsString::from(format!("@{}", rsp.display()))],
        )
        .expect("expand");
        assert_eq!(inv.len(), 1);
        let argv: Vec<String> = inv[0]
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            argv,
            vec![
                "psign-tool".to_string(),
                "verify".to_string(),
                "/pa".to_string(),
                "x.exe".to_string(),
            ]
        );
        let _ = fs::remove_file(&inner);
        let _ = fs::remove_file(&rsp);
    }

    #[test]
    fn response_file_utf16_le_bom_roundtrip() {
        let dir = std::env::temp_dir();
        let rsp = dir.join("psign_rsp_utf16le_bom.rsp");
        let text = "verify\n/pa\nx.exe\n";
        let mut raw: Vec<u8> = vec![0xFF, 0xFE];
        for u in text.encode_utf16() {
            raw.extend_from_slice(&u.to_le_bytes());
        }
        fs::write(&rsp, &raw).expect("write utf-16 rsp");

        let exe = OsString::from("psign-tool");
        let inv = expand_invocations(
            exe.clone(),
            vec![OsString::from(format!("@{}", rsp.display()))],
        )
        .expect("expand");
        assert_eq!(inv.len(), 1);
        assert_eq!(
            inv[0]
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>(),
            vec![
                "psign-tool".to_string(),
                "verify".to_string(),
                "/pa".to_string(),
                "x.exe".to_string(),
            ]
        );
        let _ = fs::remove_file(&rsp);
    }

    #[test]
    fn response_file_utf16_be_bom_roundtrip() {
        let dir = std::env::temp_dir();
        let rsp = dir.join("psign_rsp_utf16be_bom.rsp");
        let text = "verify\n/pa\ny.exe\n";
        let mut raw: Vec<u8> = vec![0xFE, 0xFF];
        for u in text.encode_utf16() {
            raw.extend_from_slice(&u.to_be_bytes());
        }
        fs::write(&rsp, &raw).expect("write utf-16be rsp");

        let exe = OsString::from("psign-tool");
        let inv = expand_invocations(
            exe.clone(),
            vec![OsString::from(format!("@{}", rsp.display()))],
        )
        .expect("expand");
        assert_eq!(inv.len(), 1);
        assert_eq!(
            inv[0]
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>(),
            vec![
                "psign-tool".to_string(),
                "verify".to_string(),
                "/pa".to_string(),
                "y.exe".to_string(),
            ]
        );
        let _ = fs::remove_file(&rsp);
    }

    #[test]
    fn response_file_utf8_bom_roundtrip() {
        let dir = std::env::temp_dir();
        let rsp = dir.join("psign_rsp_utf8_bom.rsp");
        let body = "verify\n/pa\nz.exe\n";
        let mut raw = vec![0xEFu8, 0xBB, 0xBF];
        raw.extend_from_slice(body.as_bytes());
        fs::write(&rsp, &raw).expect("write utf-8 bom rsp");

        let exe = OsString::from("psign-tool");
        let inv = expand_invocations(
            exe.clone(),
            vec![OsString::from(format!("@{}", rsp.display()))],
        )
        .expect("expand");
        assert_eq!(inv.len(), 1);
        assert_eq!(
            inv[0]
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>(),
            vec![
                "psign-tool".to_string(),
                "verify".to_string(),
                "/pa".to_string(),
                "z.exe".to_string(),
            ]
        );
        let _ = fs::remove_file(&rsp);
    }

    #[test]
    fn inline_double_at_strips_one_at_for_literal() {
        let exe = OsString::from("psign-tool");
        let inv = expand_invocations(
            exe.clone(),
            vec![
                OsString::from("sign"),
                OsString::from("y.exe"),
                OsString::from("--f"),
                OsString::from("@@C:/certs/spaced name.pfx"),
            ],
        )
        .expect("expand");
        assert_eq!(inv.len(), 1);
        let argv: Vec<String> = inv[0]
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            argv,
            vec![
                "psign-tool".to_string(),
                "sign".to_string(),
                "y.exe".to_string(),
                "--f".to_string(),
                "@C:/certs/spaced name.pfx".to_string(),
            ]
        );
    }

    #[test]
    fn inline_double_at_only_is_single_at_token() {
        let exe = OsString::from("psign-tool");
        let inv = expand_invocations(
            exe.clone(),
            vec![OsString::from("verify"), OsString::from("@@")],
        )
        .expect("expand");
        let argv: Vec<String> = inv[0]
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            argv,
            vec![
                "psign-tool".to_string(),
                "verify".to_string(),
                "@".to_string(),
            ]
        );
    }
}
