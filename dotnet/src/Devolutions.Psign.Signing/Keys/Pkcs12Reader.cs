using System.Formats.Asn1;
using System.Security.Cryptography;
using Devolutions.Psign.Core;

namespace Devolutions.Psign.Signing.Keys;

/// <summary>A certificate bag read from a PKCS#12 archive.</summary>
internal sealed record Pkcs12CertEntry(byte[] Der, byte[]? LocalKeyId);

/// <summary>A (decrypted) key bag read from a PKCS#12 archive.</summary>
internal sealed record Pkcs12KeyEntry(PrivateKeyMaterial Key, byte[]? LocalKeyId);

/// <summary>
/// Managed PKCS#12 (RFC 7292) reader: verifies the password MAC, decrypts <c>EncryptedData</c> safe contents and shrouded
/// key bags (PBES2 AES / 3DES / DES, PKCS#12 PBE 3DES / RC2) and returns certificate and key bags in archive order,
/// including nested <c>SafeContents</c> bags (Rust <c>picky::pkcs12::Pfx::from_der</c> + <c>collect_pfx_bags</c>).
/// </summary>
internal static class Pkcs12Reader
{
    public static (List<Pkcs12CertEntry> Certs, List<Pkcs12KeyEntry> Keys) Read(byte[] pfx, string password)
    {
        try
        {
            return ReadCore(pfx, password);
        }
        catch (AsnContentException e)
        {
            throw new PsignException("malformed PKCS#12 (PFX) DER", e);
        }
    }

    private static (List<Pkcs12CertEntry>, List<Pkcs12KeyEntry>) ReadCore(byte[] pfx, string password)
    {
        var top = new AsnReader(pfx, AsnEncodingRules.BER);
        var pfxSeq = top.ReadSequence();
        var version = Pkcs12Crypto.ReadSmallInteger(pfxSeq);
        if (version != 3)
        {
            throw new PsignException($"unsupported PFX version {version} (expected 3)");
        }

        var authSafe = pfxSeq.ReadSequence();
        var contentType = authSafe.ReadObjectIdentifier();
        if (contentType != Pkcs12Oids.Data)
        {
            throw new PsignException($"unsupported PFX authSafe content type {contentType} (public-key integrity mode is not supported)");
        }

        var explicit0 = authSafe.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
        var authSafeContent = explicit0.ReadOctetString();

        if (pfxSeq.HasData)
        {
            VerifyMac(pfxSeq.ReadSequence(), password, authSafeContent);
        }

        var certs = new List<Pkcs12CertEntry>();
        var keys = new List<Pkcs12KeyEntry>();
        var contentInfos = new AsnReader(authSafeContent, AsnEncodingRules.BER).ReadSequence();
        while (contentInfos.HasData)
        {
            var ci = contentInfos.ReadSequence();
            var ciType = ci.ReadObjectIdentifier();
            byte[]? safeContents = null;
            switch (ciType)
            {
                case Pkcs12Oids.Data:
                    safeContents = ci.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)).ReadOctetString();
                    break;
                case Pkcs12Oids.EncryptedData:
                    {
                        var ed = ci.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)).ReadSequence();
                        _ = Pkcs12Crypto.ReadSmallInteger(ed);
                        var eci = ed.ReadSequence();
                        _ = eci.ReadObjectIdentifier();
                        var algId = eci.ReadEncodedValue();
                        if (!eci.HasData)
                        {
                            break;
                        }

                        var encrypted = eci.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
                        safeContents = Pkcs12Crypto.Decrypt(algId, password, encrypted);
                        break;
                    }

                default:
                    // Unknown (for example EnvelopedData) safe contents are skipped like picky's SafeContentsKind::Unknown.
                    break;
            }

            if (safeContents is not null)
            {
                ReadSafeContents(safeContents, password, certs, keys);
            }
        }

        return (certs, keys);
    }

    private static void VerifyMac(AsnReader macData, string password, byte[] authSafeContent)
    {
        var digestInfo = macData.ReadSequence();
        var alg = digestInfo.ReadSequence();
        var hash = Pkcs12Crypto.HashFromDigestOid(alg.ReadObjectIdentifier());
        var expected = digestInfo.ReadOctetString();
        var salt = macData.ReadOctetString();
        var iterations = macData.HasData ? (int)Pkcs12Crypto.ReadSmallInteger(macData) : 1;
        if (iterations <= 0)
        {
            throw new PsignException("PKCS#12 MAC iteration count must be positive");
        }

        var mac = Pkcs12Crypto.ComputeMac(hash, Pkcs12Crypto.BmpPassword(password), salt, iterations, authSafeContent);
        if (CryptographicOperations.FixedTimeEquals(mac, expected))
        {
            return;
        }

        if (password.Length == 0)
        {
            // Some producers MAC an empty password as zero-length bytes instead of a lone BMP NUL terminator.
            mac = Pkcs12Crypto.ComputeMac(hash, ReadOnlySpan<byte>.Empty, salt, iterations, authSafeContent);
            if (CryptographicOperations.FixedTimeEquals(mac, expected))
            {
                return;
            }
        }

        throw new PsignException("MAC validation failed (wrong password or corrupted data)");
    }

    private const int MaxSafeBagDepth = 16;

    private static void ReadSafeContents(byte[] der, string password, List<Pkcs12CertEntry> certs, List<Pkcs12KeyEntry> keys)
    {
        var bags = new AsnReader(der, AsnEncodingRules.BER).ReadSequence();
        while (bags.HasData)
        {
            ReadSafeBag(bags.ReadSequence(), password, certs, keys, depth: 0);
        }
    }

    private static void ReadSafeBag(AsnReader bag, string password, List<Pkcs12CertEntry> certs, List<Pkcs12KeyEntry> keys, int depth)
    {
        if (depth > MaxSafeBagDepth)
        {
            throw new PsignException("PKCS#12 SafeContents nesting depth exceeds limit");
        }
        var bagId = bag.ReadObjectIdentifier();
        var value = bag.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        byte[]? localKeyId = null;
        if (bag.HasData)
        {
            var attrs = bag.ReadSetOf(skipSortOrderValidation: true);
            while (attrs.HasData)
            {
                var attr = attrs.ReadSequence();
                var attrOid = attr.ReadObjectIdentifier();
                var values = attr.ReadSetOf(skipSortOrderValidation: true);
                if (attrOid == Pkcs12Oids.LocalKeyId && values.HasData && localKeyId is null)
                {
                    localKeyId = values.ReadOctetString();
                }
            }
        }

        switch (bagId)
        {
            case Pkcs12Oids.KeyBag:
                keys.Add(new Pkcs12KeyEntry(PrivateKeyMaterial.FromPkcs8Der(value.ReadEncodedValue().Span), localKeyId));
                break;
            case Pkcs12Oids.Pkcs8ShroudedKeyBag:
                {
                    var epki = value.ReadSequence();
                    var algId = epki.ReadEncodedValue();
                    var encrypted = epki.ReadOctetString();
                    var plain = Pkcs12Crypto.Decrypt(algId, password, encrypted);
                    keys.Add(new Pkcs12KeyEntry(PrivateKeyMaterial.FromPkcs8Der(plain), localKeyId));
                    break;
                }

            case Pkcs12Oids.CertBag:
                {
                    var certBag = value.ReadSequence();
                    var certId = certBag.ReadObjectIdentifier();
                    if (certId != Pkcs12Oids.X509Certificate)
                    {
                        break;
                    }

                    var certValue = certBag.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)).ReadOctetString();
                    certs.Add(new Pkcs12CertEntry(certValue, localKeyId));
                    break;
                }

            case Pkcs12Oids.SafeContentsBag:
                {
                    var nested = value.ReadSequence();
                    while (nested.HasData)
                    {
                        ReadSafeBag(nested.ReadSequence(), password, certs, keys, depth + 1);
                    }

                    break;
                }

            default:
                // CRL / secret / unknown bags are ignored.
                break;
        }
    }
}
