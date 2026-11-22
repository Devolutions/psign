using System.Formats.Asn1;
using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.X509;

namespace Devolutions.Psign.Signing.Keys;

/// <summary>
/// Parsed signer identity and accompanying certificate chain extracted from a PKCS#12 (<c>.pfx</c>) archive
/// (Rust <c>pkcs12::ParsedPfxIdentity</c>).
/// </summary>
/// <param name="SignerCertificateDer">Certificate matched to an included private key.</param>
/// <param name="PrivateKey">Matched private key (canonical PKCS#8).</param>
/// <param name="ChainCertificatesDer">Every other (distinct) certificate in archive order.</param>
public sealed record ParsedPfxIdentity(byte[] SignerCertificateDer, PrivateKeyMaterial PrivateKey, IReadOnlyList<byte[]> ChainCertificatesDer)
{
    /// <summary>PKCS#8 PEM private key text with trailing newline (Rust <c>private_key_pem</c>).</summary>
    public string PrivateKeyPem => PrivateKey.ToPkcs8Pem();

    /// <summary>Parsed signer certificate.</summary>
    public CertificateInfo SignerCertificate => CertificateInfo.Parse(SignerCertificateDer);

    /// <summary>Parsed chain certificates.</summary>
    public IReadOnlyList<CertificateInfo> ChainCertificates => ChainCertificatesDer.Select(d => CertificateInfo.Parse(d)).ToList();
}

/// <summary>PKCS#12 signer identity extraction (port of Rust <c>psign-authenticode-trust/src/pkcs12.rs</c>).</summary>
public static class Pkcs12Identity
{
    /// <summary>
    /// Parse a PKCS#12 archive into its matched signer certificate, PKCS#8 private key, and any additional issuer / root
    /// certificates (Rust <c>parse_pfx_identity</c>). A certificate whose <c>localKeyId</c> matches a key (and whose public
    /// key equals the key's) is preferred; otherwise the first certificate / key pair with matching public keys wins.
    /// </summary>
    public static ParsedPfxIdentity Parse(byte[] pfx, string password)
    {
        var (certs, keys) = Pkcs12Reader.Read(pfx, password);
        if (certs.Count == 0)
        {
            throw new PsignException("PFX did not contain an X.509 certificate");
        }

        if (keys.Count == 0)
        {
            throw new PsignException("PFX did not contain a private key");
        }

        var matched = FindMatchingPair(certs, keys)
            ?? throw new PsignException("PFX did not contain a certificate matching an included private key");
        var signerDer = certs[matched.Cert].Der;
        var key = keys[matched.Key].Key;

        var seen = new HashSet<string>(StringComparer.Ordinal) { Convert.ToBase64String(signerDer) };
        var chain = new List<byte[]>();
        foreach (var entry in certs)
        {
            if (seen.Add(Convert.ToBase64String(entry.Der)))
            {
                chain.Add(entry.Der);
            }
        }

        return new ParsedPfxIdentity(signerDer, key, chain);
    }

    /// <summary>Rust <c>key_matches_cert</c>: throw unless <paramref name="key"/> matches <paramref name="certDer"/>.</summary>
    public static void EnsureKeyMatchesCertificate(byte[] certDer, PrivateKeyMaterial key)
    {
        CertificateInfo cert;
        try
        {
            cert = CertificateInfo.Parse(certDer);
        }
        catch (Exception e) when (e is PsignException or AsnContentException or CryptographicException)
        {
            throw new PsignException("parse certificate for key matching", e);
        }

        key.EnsureMatchesCertificate(cert);
    }

    private static (int Cert, int Key)? FindMatchingPair(List<Pkcs12CertEntry> certs, List<Pkcs12KeyEntry> keys)
    {
        var parsed = certs.Select(c => CertificateInfo.TryParse(c.Der)).ToList();
        for (var ci = 0; ci < certs.Count; ci++)
        {
            if (certs[ci].LocalKeyId is not { } certId || parsed[ci] is not { } cert)
            {
                continue;
            }

            for (var ki = 0; ki < keys.Count; ki++)
            {
                if (keys[ki].LocalKeyId is { } keyId && keyId.AsSpan().SequenceEqual(certId) && keys[ki].Key.MatchesCertificate(cert))
                {
                    return (ci, ki);
                }
            }
        }

        for (var ci = 0; ci < certs.Count; ci++)
        {
            if (parsed[ci] is not { } cert)
            {
                continue;
            }

            for (var ki = 0; ki < keys.Count; ki++)
            {
                if (keys[ki].Key.MatchesCertificate(cert))
                {
                    return (ci, ki);
                }
            }
        }

        return null;
    }
}

/// <summary>
/// PKCS#12 writer matching Rust <c>test_pki::encode_pfx_der</c> (picky): certificates in a PBES2-encrypted
/// <c>SafeContents</c> (leaf first, with <c>localKeyId</c>), the private key as a PBES2 shrouded key bag in a plain
/// <c>SafeContents</c>, and an HMAC-SHA256 integrity MAC (20-byte salt, 1 iteration).
/// </summary>
internal static class Pkcs12Writer
{
    public static byte[] Encode(byte[] leafCertDer, PrivateKeyMaterial key, IEnumerable<byte[]> chainCertsDer, byte[] localKeyId, string password)
    {
        // Certificate SafeContents.
        var certBags = new AsnWriter(AsnEncodingRules.DER);
        using (certBags.PushSequence())
        {
            WriteCertBag(certBags, leafCertDer, localKeyId);
            foreach (var chain in chainCertsDer)
            {
                WriteCertBag(certBags, chain, null);
            }
        }

        var (certAlg, certCipher) = Pkcs12Crypto.EncryptPbes2Aes256(password, certBags.Encode());

        // Key SafeContents.
        var (keyAlg, keyCipher) = Pkcs12Crypto.EncryptPbes2Aes256(password, key.Pkcs8Der);
        var keyBags = new AsnWriter(AsnEncodingRules.DER);
        using (keyBags.PushSequence())
        {
            using (keyBags.PushSequence())
            {
                keyBags.WriteObjectIdentifier(Pkcs12Oids.Pkcs8ShroudedKeyBag);
                using (keyBags.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                {
                    using (keyBags.PushSequence())
                    {
                        keyBags.WriteEncodedValue(keyAlg);
                        keyBags.WriteOctetString(keyCipher);
                    }
                }

                WriteLocalKeyIdAttributes(keyBags, localKeyId);
            }
        }

        // AuthenticatedSafe.
        var authSafe = new AsnWriter(AsnEncodingRules.DER);
        using (authSafe.PushSequence())
        {
            using (authSafe.PushSequence())
            {
                authSafe.WriteObjectIdentifier(Pkcs12Oids.EncryptedData);
                using (authSafe.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                {
                    using (authSafe.PushSequence())
                    {
                        authSafe.WriteInteger(0);
                        using (authSafe.PushSequence())
                        {
                            authSafe.WriteObjectIdentifier(Pkcs12Oids.Data);
                            authSafe.WriteEncodedValue(certAlg);
                            authSafe.WriteOctetString(certCipher, new Asn1Tag(TagClass.ContextSpecific, 0));
                        }
                    }
                }
            }

            using (authSafe.PushSequence())
            {
                authSafe.WriteObjectIdentifier(Pkcs12Oids.Data);
                using (authSafe.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                {
                    authSafe.WriteOctetString(keyBags.Encode());
                }
            }
        }

        var authSafeDer = authSafe.Encode();
        var macSalt = RandomNumberGenerator.GetBytes(20);
        const int macIterations = 1;
        var mac = Pkcs12Crypto.ComputeMac(HashAlgorithmName.SHA256, Pkcs12Crypto.BmpPassword(password), macSalt, macIterations, authSafeDer);

        var pfx = new AsnWriter(AsnEncodingRules.DER);
        using (pfx.PushSequence())
        {
            pfx.WriteInteger(3);
            using (pfx.PushSequence())
            {
                pfx.WriteObjectIdentifier(Pkcs12Oids.Data);
                using (pfx.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                {
                    pfx.WriteOctetString(authSafeDer);
                }
            }

            using (pfx.PushSequence())
            {
                using (pfx.PushSequence())
                {
                    using (pfx.PushSequence())
                    {
                        pfx.WriteObjectIdentifier(Pkcs12Oids.Sha256);
                        pfx.WriteNull();
                    }

                    pfx.WriteOctetString(mac);
                }

                pfx.WriteOctetString(macSalt);
                pfx.WriteInteger(macIterations);
            }
        }

        return pfx.Encode();
    }

    private static void WriteCertBag(AsnWriter w, byte[] certDer, byte[]? localKeyId)
    {
        using (w.PushSequence())
        {
            w.WriteObjectIdentifier(Pkcs12Oids.CertBag);
            using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                using (w.PushSequence())
                {
                    w.WriteObjectIdentifier(Pkcs12Oids.X509Certificate);
                    using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    {
                        w.WriteOctetString(certDer);
                    }
                }
            }

            if (localKeyId is not null)
            {
                WriteLocalKeyIdAttributes(w, localKeyId);
            }
        }
    }

    private static void WriteLocalKeyIdAttributes(AsnWriter w, byte[] localKeyId)
    {
        using (w.PushSetOf())
        {
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier(Pkcs12Oids.LocalKeyId);
                using (w.PushSetOf())
                {
                    w.WriteOctetString(localKeyId);
                }
            }
        }
    }
}
