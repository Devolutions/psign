using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cms;

namespace Devolutions.Psign.Core.Pe;

/// <summary>Result of PE digest consistency checks (Rust <c>PeDigestConsistencyResult</c>).</summary>
public sealed record PeDigestConsistencyResult(string RecomputedDigestHex, int MatchedAttributeCertificateIndex, int Pkcs7AuthenticodeEntries);

/// <summary>PE Authenticode digest and embedded-signature helpers (port of <c>pe_digest.rs</c> / <c>verify_pe.rs</c>).</summary>
public static class PeAuthenticode
{
    /// <summary>Authenticode image digest for <paramref name="image"/>.</summary>
    public static byte[] Digest(byte[] image, AuthenticodeHashKind kind) => PeFile.Parse(image).AuthenticodeDigest(kind);

    /// <summary>Lowercase hex SHA-256 Authenticode digest.</summary>
    public static string DigestSha256Hex(byte[] image) => Hex.Lower(Digest(image, AuthenticodeHashKind.Sha256));

    /// <summary>File ranges hashed by Authenticode.</summary>
    public static List<ByteRange> DigestFileRanges(byte[] image) => PeFile.Parse(image).AuthenticodeDigestRanges();

    /// <summary>
    /// Ensure every PKCS#7 Authenticode attribute certificate's indirect digest matches the recomputed image digest.
    /// </summary>
    public static PeDigestConsistencyResult VerifyDigestConsistency(byte[] image)
    {
        var result = VerifyDigestConsistencyStatus(image, out var status);
        return status switch
        {
            Status.Signed => result!,
            Status.NoCertificateTable => throw new PsignException("PE has no certificate table"),
            _ => throw new PsignException("no PKCS#7 Authenticode entries found in certificate table"),
        };
    }

    /// <summary>Same as <see cref="VerifyDigestConsistency"/> but returns <c>null</c> for unsigned images.</summary>
    public static PeDigestConsistencyResult? VerifyDigestConsistencyIfSigned(byte[] image) =>
        VerifyDigestConsistencyStatus(image, out _);

    private enum Status
    {
        NoCertificateTable,
        NoPkcs7Entries,
        Signed,
    }

    private static PeDigestConsistencyResult? VerifyDigestConsistencyStatus(byte[] image, out Status status)
    {
        PeEmbed.ValidateAttributeCertificateTableAlignment(image);
        var pe = PeFile.Parse(image);
        var certs = pe.AttributeCertificates();
        if (certs is null)
        {
            status = Status.NoCertificateTable;
            return null;
        }

        int count = 0;
        string lastHex = string.Empty;
        int lastIdx = 0;
        for (int idx = 0; idx < certs.Count; idx++)
        {
            var attr = certs[idx];
            if (attr.CertificateType != AttributeCertificate.WinCertTypePkcsSignedData)
            {
                continue;
            }

            AuthenticodeSignature sig;
            try
            {
                sig = AuthenticodeSignature.Parse(pe.CertificateData(attr));
            }
            catch (PsignException e)
            {
                throw new PsignException($"PKCS#7 Authenticode parse failed: {e.Message}", e);
            }

            var embedded = sig.Digest;
            count++;
            var kind = sig.IndirectData.HashKind
                ?? throw new PsignException($"unsupported Authenticode digest algorithm OID {sig.IndirectData.DigestAlgorithm.Oid}");
            if (embedded.Length != kind.DigestLength())
            {
                throw new PsignException(
                    $"Authenticode digest length {embedded.Length} does not match algorithm {kind.Name()} ({kind.DigestLength()} bytes)");
            }

            var computed = pe.AuthenticodeDigest(kind);
            if (!computed.AsSpan().SequenceEqual(embedded))
            {
                throw new PsignException(
                    $"Rust SIP digest mismatch for PKCS#7 entry {idx}: recomputed {Hex.Lower(computed)} vs embedded {Hex.Lower(embedded)}");
            }

            lastHex = Hex.Lower(computed);
            lastIdx = idx;
        }

        if (count == 0)
        {
            status = Status.NoPkcs7Entries;
            return null;
        }

        status = Status.Signed;
        return new PeDigestConsistencyResult(lastHex, lastIdx, count);
    }

    /// <summary>
    /// Embedded Authenticode digest (<c>SpcIndirectData.messageDigest.digest</c>) from a PKCS#7 blob, as the
    /// <c>authenticode</c> crate's <c>AuthenticodeSignature::digest</c> exposes it.
    /// </summary>
    public static byte[] EmbeddedIndirectDigest(ReadOnlySpan<byte> pkcs7) => AuthenticodeSignature.Parse(pkcs7).Digest;

    /// <summary>
    /// Invoke <paramref name="callback"/> for each <c>WIN_CERT_TYPE_PKCS_SIGNED_DATA</c> entry. Fails when there is no
    /// certificate table or no PKCS#7 entries.
    /// </summary>
    public static int ForEachPkcs7(byte[] image, Action<int, byte[]> callback)
    {
        var pe = PeFile.Parse(image);
        var certs = pe.AttributeCertificates() ?? throw new PsignException("PE has no certificate table");
        int count = 0;
        for (int idx = 0; idx < certs.Count; idx++)
        {
            if (certs[idx].CertificateType != AttributeCertificate.WinCertTypePkcsSignedData)
            {
                continue;
            }

            callback(idx, pe.CertificateData(certs[idx]).ToArray());
            count++;
        }

        if (count == 0)
        {
            throw new PsignException("no PKCS#7 Authenticode entries found in certificate table");
        }

        return count;
    }

    /// <summary>All PKCS#7 blobs in certificate-table order (empty when the table has none).</summary>
    public static List<byte[]> Pkcs7Blobs(byte[] image)
    {
        var pe = PeFile.Parse(image);
        var certs = pe.AttributeCertificates() ?? throw new PsignException("PE has no certificate table");
        return certs
            .Where(c => c.CertificateType == AttributeCertificate.WinCertTypePkcsSignedData)
            .Select(c => pe.CertificateData(c).ToArray())
            .ToList();
    }

    /// <summary>PKCS#7 bytes of the <paramref name="index"/>-th PKCS#7 attribute certificate (0 = first).</summary>
    public static byte[] NthPkcs7(byte[] image, int index)
    {
        var blobs = Pkcs7Blobs(image);
        if (index < 0 || index >= blobs.Count)
        {
            throw new PsignException(
                $"no PKCS#7 Authenticode entry at index {index} (fewer PKCS#7 rows in certificate table)");
        }

        return blobs[index];
    }

    /// <summary>First PKCS#7 blob.</summary>
    public static byte[] FirstPkcs7(byte[] image) => NthPkcs7(image, 0);

    /// <summary>Byte length of each PKCS#7 blob.</summary>
    public static List<int> Pkcs7ByteLengths(byte[] image) => Pkcs7Blobs(image).Select(b => b.Length).ToList();

    /// <summary>Decode <c>SpcIndirectDataContent</c> from the <paramref name="index"/>-th PKCS#7.</summary>
    public static SpcIndirectDataContent SpcIndirectDataAt(byte[] image, int index)
    {
        var sd = CmsSignedData.Parse(NthPkcs7(image, index));
        return SpcIndirectDataContent.FromSignedData(sd);
    }
}
