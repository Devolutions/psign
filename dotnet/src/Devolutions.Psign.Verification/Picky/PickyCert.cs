using System.Formats.Asn1;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.X509;

namespace Devolutions.Psign.Verification.Picky;

/// <summary><c>picky::x509::certificate::CertType</c>.</summary>
internal enum PickyCertType
{
    Root,
    Intermediate,
    Leaf,
    Unknown,
}

/// <summary>
/// picky <c>CertError</c> / <c>AuthenticodeError</c> surfaced as an exception whose message is the Rust <c>Display</c>
/// text. <see cref="ExpiredSubjectId"/> is set for <c>InvalidCertificate { source: CertificateExpired }</c>.
/// </summary>
internal sealed class PickyException : PsignException
{
    public PickyException(string message, string? expiredSubjectId = null)
        : base(message)
    {
        ExpiredSubjectId = expiredSubjectId;
    }

    public string? ExpiredSubjectId { get; }
}

/// <summary>Validity check mode for <see cref="PickyCert.Verify"/> (picky <c>CertValidator</c> strictness).</summary>
internal sealed class PickyValidatorOptions
{
    public DateTimeOffset? Now { get; init; }

    public bool RequireNotBefore { get; init; } = true;

    public bool RequireNotAfter { get; init; } = true;

    public bool RequireChainCheck { get; init; } = true;

    public bool ChainShouldContainRoot { get; init; } = true;
}

/// <summary>Port of the subset of <c>picky::x509::certificate::Cert</c> used by portable trust.</summary>
internal static class PickyCert
{
    /// <summary><c>subject_name().to_string()</c>.</summary>
    public static string SubjectDisplay(CertificateInfo c) => PickyFormat.NameDisplay(c.Subject);

    /// <summary><c>issuer_name().to_string()</c>.</summary>
    public static string IssuerDisplay(CertificateInfo c) => PickyFormat.NameDisplay(c.Issuer);

    /// <summary>Structural <c>subject_name() == issuer_name()</c>.</summary>
    public static bool IsSelfIssued(CertificateInfo c) => c.Subject.AsSpan().SequenceEqual(c.Issuer);

    /// <summary><c>BasicConstraints</c> presence, <c>cA</c> (null when omitted) and <c>pathLenConstraint</c>.</summary>
    public static (bool Present, bool? Ca, int? PathLen) BasicConstraints(CertificateInfo c)
    {
        var ext = c.GetExtension(Oids.BasicConstraints);
        if (ext is null)
        {
            return (false, null, null);
        }

        try
        {
            var r = new AsnReader(ext.Value, AsnEncodingRules.BER).ReadSequence();
            bool? ca = null;
            int? pathLen = null;
            if (r.HasData && r.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
            {
                ca = r.ReadBoolean();
            }

            if (r.HasData && r.TryReadInt32(out int len))
            {
                pathLen = len;
            }

            return (true, ca, pathLen);
        }
        catch (AsnContentException)
        {
            return (true, null, null);
        }
    }

    /// <summary><c>Cert::ty()</c>.</summary>
    public static PickyCertType Ty(CertificateInfo c)
    {
        var (_, ca, _) = BasicConstraints(c);
        return ca switch
        {
            true => IsSelfIssued(c) ? PickyCertType.Root : PickyCertType.Intermediate,
            false => PickyCertType.Leaf,
            null => PickyCertType.Unknown,
        };
    }

    /// <summary>True when the certificate carries an EKU extension containing <paramref name="oid"/>.</summary>
    public static bool EkuContains(CertificateInfo c, string oid) => c.ExtendedKeyUsages?.Contains(oid) == true;

    /// <summary>True when the certificate carries an EKU extension.</summary>
    public static bool HasEkuExtension(CertificateInfo c) => c.GetExtension(Oids.ExtendedKeyUsage) is not null;

    private static void VerifyValidity(CertificateInfo cert, PickyValidatorOptions o)
    {
        if (o.Now is not { } now)
        {
            return;
        }

        var nb = PickyFormat.Truncate(cert.NotBefore);
        var na = PickyFormat.Truncate(cert.NotAfter);
        string id = SubjectDisplay(cert);
        if (nb > now && o.RequireNotBefore)
        {
            throw new PickyException(
                $"invalid certificate '{id}': certificate is not yet valid (not before: {PickyFormat.Date(nb)}, now: {PickyFormat.Date(now)})");
        }

        if (na < now && o.RequireNotAfter)
        {
            throw new PickyException(
                $"invalid certificate '{id}': certificate expired (not after: {PickyFormat.Date(na)}, now: {PickyFormat.Date(now)})",
                id);
        }
    }

    /// <summary><c>Cert::is_parent_of</c>.</summary>
    public static void IsParentOf(CertificateInfo parent, CertificateInfo other)
    {
        var otherAki = other.GetExtension(Oids.AuthorityKeyIdentifier) is not null ? other.AuthorityKeyIdentifier : null;
        if (otherAki is not null)
        {
            if (parent.GetExtension(Oids.SubjectKeyIdentifier) is null || parent.SubjectKeyIdentifier is not { } parentSki)
            {
                throw new PickyException(
                    $"invalid certificate '{SubjectDisplay(parent)}': extension not found: subject key identifier");
            }

            if (!parentSki.AsSpan().SequenceEqual(otherAki))
            {
                throw new PickyException(
                    $"invalid certificate '{SubjectDisplay(other)}': CA chain error: authority key id doesn't match (expected: {Convert.ToBase64String(otherAki)}, got: {Convert.ToBase64String(parentSki)})");
            }
        }

        if (!other.Issuer.AsSpan().SequenceEqual(parent.Subject))
        {
            throw new PickyException(
                $"invalid certificate '{SubjectDisplay(other)}': CA chain error: issuer name doesn't match (expected: {IssuerDisplay(other)}, got: {SubjectDisplay(parent)})");
        }
    }

    /// <summary>
    /// <c>Cert::verifier().chain(..).exact_date(..).verify()</c>. Throws <see cref="PickyException"/> with picky's
    /// <c>CertError</c> display text.
    /// </summary>
    public static void Verify(CertificateInfo cert, IEnumerable<CertificateInfo> chain, PickyValidatorOptions o)
    {
        if ((o.RequireNotAfter || o.RequireNotBefore) && o.Now is null)
        {
            throw new PickyException("missing required builder argument `now`");
        }

        VerifyValidity(cert, o);
        if (!o.RequireChainCheck)
        {
            return;
        }

        var current = cert;
        int n = 0;
        foreach (var parent in chain)
        {
            var (_, ca, pathLen) = BasicConstraints(parent);
            if (ca != true)
            {
                throw new PickyException($"CA chain error: issuer certificate '{SubjectDisplay(parent)}' is not a CA");
            }

            if (pathLen is { } pl && pl < n)
            {
                throw new PickyException(
                    $"CA chain error: chain depth doesn't satisfy basic constraints extension: certificate '{SubjectDisplay(parent)}' has pathlen of {pl}");
            }

            VerifyValidity(parent, o);
            IsParentOf(parent, current);

            var err = PickySignature.Verify(current.SignatureAlgorithm.Oid, parent.SubjectPublicKeyInfo, current.TbsCertificate, current.Signature);
            if (err is not null)
            {
                if (err.StartsWith("unsupported algorithm", StringComparison.Ordinal) && !err.Contains("hash algorithm can't", StringComparison.Ordinal))
                {
                    throw new PickyException($"signature error: {err}");
                }

                throw new PickyException($"invalid certificate '{SubjectDisplay(current)}': signature error: {err}");
            }

            current = parent;
            n++;
        }

        if (o.ChainShouldContainRoot && Ty(current) != PickyCertType.Root)
        {
            throw new PickyException("CA chain error: chain is missing a root certificate");
        }
    }

    /// <summary>Standard exact-date chain verification.</summary>
    public static void VerifyExact(CertificateInfo cert, IEnumerable<CertificateInfo> chain, DateTimeOffset instant) =>
        Verify(cert, chain, new PickyValidatorOptions { Now = PickyFormat.Truncate(instant) });
}
