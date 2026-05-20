use crate::win::verify_chain::VerifyChainSummary;

pub fn format_verify_success(
    path: &std::path::Path,
    summary: Option<&VerifyChainSummary>,
) -> String {
    let algorithm = summary.map(|s| s.algorithm.as_str()).unwrap_or("unknown");
    let timestamp = summary.map(|s| s.timestamp.as_str()).unwrap_or("unknown");
    let signer = summary
        .map(|s| s.signer_subject.as_str())
        .unwrap_or("unknown");

    format!(
        "File: {path}\nIndex  Algorithm  Timestamp    \n========================================\n0      {algorithm:<10}{timestamp:<13}\nSigner: {signer}\n\nSuccessfully verified: {path}\n",
        path = path.display(),
        algorithm = algorithm,
        timestamp = timestamp,
        signer = signer
    )
}

pub fn format_verify_failure(path: &std::path::Path, status: i32) -> String {
    format!(
        "File: {path}\nIndex  Algorithm  Timestamp    \n========================================\nSignTool Error: WinVerifyTrust returned 0x{status:08X}\n\nNumber of errors: 1\n",
        path = path.display(),
        status = status
    )
}
