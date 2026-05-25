//! Azure Code Signing **data-plane** REST client (`CertificateProfileOperations_Sign` LRO).
//!
//! Swagger: Azure REST API specs  
//! `specification/codesigning/data-plane/Azure.CodeSigning/preview/2023-06-15-preview/azure.codesigning.json`.

use crate::CommandOutput;
use crate::cli::{ArtifactSigningSubmitArgs, AzureCredentialType, GlobalOpts};
use anyhow::{Result, anyhow};
use psign_codesigning_rest::{
    CodesigningAuth, CodesigningAuthInput, CodesigningCredentialType, CodesigningSubmitParams,
    resolve_codesigning_auth, submit_codesign_hash_blocking,
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
        endpoint_base_url: args.endpoint_base_url.clone(),
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
    resolve_codesigning_auth(&CodesigningAuthInput {
        access_token: args.access_token.clone(),
        managed_identity: args.managed_identity,
        managed_identity_resource_id: args.managed_identity_resource_id.clone(),
        tenant_id: args.tenant_id.clone(),
        client_id: args.client_id.clone(),
        client_secret: args.client_secret.clone(),
        federated_token_file: args.federated_token_file.clone(),
        credential_type: args.credential_type.map(|value| match value {
            AzureCredentialType::Default => CodesigningCredentialType::Default,
            AzureCredentialType::ManagedIdentity => CodesigningCredentialType::ManagedIdentity,
            AzureCredentialType::AccessToken => CodesigningCredentialType::AccessToken,
            AzureCredentialType::ClientSecret => CodesigningCredentialType::ClientSecret,
            AzureCredentialType::WorkloadIdentity => CodesigningCredentialType::WorkloadIdentity,
        }),
        exclude_credentials: Vec::new(),
    })
}

fn validate_submit_args(args: &ArtifactSigningSubmitArgs) -> Result<()> {
    build_auth(args)?;
    Ok(())
}
