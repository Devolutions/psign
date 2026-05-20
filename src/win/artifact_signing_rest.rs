//! Azure Code Signing **data-plane** REST client (`CertificateProfileOperations_Sign` LRO).
//!
//! Swagger: Azure REST API specs  
//! `specification/codesigning/data-plane/Azure.CodeSigning/preview/2023-06-15-preview/azure.codesigning.json`.

use crate::CommandOutput;
use crate::cli::{ArtifactSigningSubmitArgs, GlobalOpts};
use anyhow::{Result, anyhow};
use psign_codesigning_rest::{
    CodesigningAuth, CodesigningSubmitParams, submit_codesign_hash_blocking,
};
pub fn artifact_signing_submit_command(
    args: &ArtifactSigningSubmitArgs,
    global: &GlobalOpts,
) -> Result<CommandOutput> {
    validate_submit_args(args)?;

    let digest = std::fs::read(&args.digest_file)
        .map_err(|e| anyhow!("read digest file {}: {e}", args.digest_file.display()))?;
    if digest.is_empty() {
        return Err(anyhow!("digest file is empty"));
    }

    let auth = build_auth(args)?;
    let params = CodesigningSubmitParams {
        region: args.region.clone(),
        account_name: args.account_name.clone(),
        profile_name: args.profile_name.clone(),
        digest,
        signature_algorithm: args.signature_algorithm.clone(),
        api_version: args.api_version.clone(),
        correlation_id: args.correlation_id.clone(),
        authority: args.authority.clone(),
        auth,
        endpoint_base_url: None,
    };

    let debug = |msg: &str| {
        if global.debug {
            eprintln!("[debug] {msg}");
        }
    };
    let final_json = submit_codesign_hash_blocking(&params, debug)?;
    let out = serde_json::to_string_pretty(&final_json)?;
    Ok(CommandOutput::ok(format!("{out}\n")))
}

fn build_auth(args: &ArtifactSigningSubmitArgs) -> Result<CodesigningAuth> {
    let has_tok = args
        .access_token
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    if args.managed_identity {
        return Ok(CodesigningAuth::ManagedIdentity);
    }
    if has_tok {
        return Ok(CodesigningAuth::Bearer(
            args.access_token.as_ref().unwrap().trim().to_string(),
        ));
    }
    Ok(CodesigningAuth::ClientCredentials {
        tenant_id: args.tenant_id.as_ref().unwrap().trim().to_string(),
        client_id: args.client_id.as_ref().unwrap().trim().to_string(),
        client_secret: args.client_secret.as_ref().unwrap().trim().to_string(),
    })
}

fn validate_submit_args(args: &ArtifactSigningSubmitArgs) -> Result<()> {
    let has_tok = args
        .access_token
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    let sp_count = (args
        .tenant_id
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false) as u8)
        + (args
            .client_id
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false) as u8)
        + (args
            .client_secret
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false) as u8);
    if args.managed_identity {
        if has_tok || sp_count != 0 {
            return Err(anyhow!(
                "use either --managed-identity or access token / client credentials, not multiple"
            ));
        }
        return Ok(());
    }
    if has_tok {
        if sp_count != 0 {
            return Err(anyhow!(
                "use either --access-token or client credentials tenant/id/secret, not both"
            ));
        }
        return Ok(());
    }
    if sp_count != 0 && sp_count != 3 {
        return Err(anyhow!(
            "client credentials require all of --tenant-id, --client-id, and --client-secret"
        ));
    }
    if sp_count == 0 {
        return Err(anyhow!(
            "choose authentication: --managed-identity, --access-token, or tenant/client-id/client-secret"
        ));
    }
    Ok(())
}
