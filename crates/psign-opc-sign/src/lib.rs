//! Portable OPC package-signing primitives for VSIX and NuGet packages.
//!
//! This crate is intentionally separate from `psign-sip-digest`: VSIX and NuGet
//! package signing is ZIP/OPC/CMS based, not a Windows SIP digest path.

pub mod nuget;
pub mod opc;
pub mod vsix;
