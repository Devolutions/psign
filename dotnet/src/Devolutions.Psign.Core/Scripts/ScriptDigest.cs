using Devolutions.Psign.Core.Text;

namespace Devolutions.Psign.Core.Scripts;

/// <summary>
/// Script SIP dispatch (port of the script helpers in <c>psign-sip-digest/src/lib.rs</c>): WSH extensions go to
/// <see cref="WshScript"/>, everything else to <see cref="PsScript"/>.
/// </summary>
public static class ScriptDigest
{
    /// <summary>Verified script digest binding for PowerShell-class or WSH scripts (Rust <c>script_digest_report</c>).</summary>
    public static ScriptAuthenticodeDigestReport ScriptDigestReport(ReadOnlySpan<byte> raw, string ext)
    {
        var extL = RustText.ToAsciiLowercase(ext);
        return PsScript.IsWshExtension(extL)
            ? WshScript.WshDigestReport(raw, extL)
            : PsScript.PowerShellClassDigestReport(raw, extL);
    }

    /// <summary>Verify the script digest binding (Rust <c>verify_script_digest_consistency</c>).</summary>
    public static void VerifyScriptDigestConsistency(ReadOnlySpan<byte> raw, string ext) => ScriptDigestReport(raw, ext);
}
