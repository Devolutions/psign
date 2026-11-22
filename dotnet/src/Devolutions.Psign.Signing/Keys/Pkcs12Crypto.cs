using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;
using Devolutions.Psign.Core;

namespace Devolutions.Psign.Signing.Keys;

/// <summary>PKCS#12 (RFC 7292) OIDs.</summary>
internal static class Pkcs12Oids
{
    public const string Data = "1.2.840.113549.1.7.1";
    public const string EncryptedData = "1.2.840.113549.1.7.6";

    public const string KeyBag = "1.2.840.113549.1.12.10.1.1";
    public const string Pkcs8ShroudedKeyBag = "1.2.840.113549.1.12.10.1.2";
    public const string CertBag = "1.2.840.113549.1.12.10.1.3";
    public const string SafeContentsBag = "1.2.840.113549.1.12.10.1.6";

    public const string X509Certificate = "1.2.840.113549.1.9.22.1";
    public const string LocalKeyId = "1.2.840.113549.1.9.21";
    public const string FriendlyName = "1.2.840.113549.1.9.20";

    public const string PbeSha1Rc4128 = "1.2.840.113549.1.12.1.1";
    public const string PbeSha1Rc440 = "1.2.840.113549.1.12.1.2";
    public const string PbeSha13Des = "1.2.840.113549.1.12.1.3";
    public const string PbeSha12Des = "1.2.840.113549.1.12.1.4";
    public const string PbeSha1Rc2128 = "1.2.840.113549.1.12.1.5";
    public const string PbeSha1Rc240 = "1.2.840.113549.1.12.1.6";

    public const string Pbes2 = "1.2.840.113549.1.5.13";
    public const string Pbkdf2 = "1.2.840.113549.1.5.12";

    public const string HmacSha1 = "1.2.840.113549.2.7";
    public const string HmacSha256 = "1.2.840.113549.2.9";
    public const string HmacSha384 = "1.2.840.113549.2.10";
    public const string HmacSha512 = "1.2.840.113549.2.11";

    public const string Aes128Cbc = "2.16.840.1.101.3.4.1.2";
    public const string Aes192Cbc = "2.16.840.1.101.3.4.1.22";
    public const string Aes256Cbc = "2.16.840.1.101.3.4.1.42";
    public const string DesEde3Cbc = "1.2.840.113549.3.7";
    public const string DesCbc = "1.3.14.3.2.7";

    public const string Sha1 = "1.3.14.3.2.26";
    public const string Sha256 = "2.16.840.1.101.3.4.2.1";
    public const string Sha384 = "2.16.840.1.101.3.4.2.2";
    public const string Sha512 = "2.16.840.1.101.3.4.2.3";
}

/// <summary>PKCS#12 key derivation (RFC 7292 appendix B), PBES1 / PBES2 decryption and PBES2 encryption.</summary>
internal static class Pkcs12Crypto
{
    public const byte KeyMaterial = 1;
    public const byte IvMaterial = 2;
    public const byte MacMaterial = 3;

    /// <summary>PKCS#12 password representation: BMPString (UTF-16BE) plus a two-byte NUL terminator.</summary>
    public static byte[] BmpPassword(string password)
    {
        var bytes = Encoding.BigEndianUnicode.GetBytes(password);
        var result = new byte[bytes.Length + 2];
        bytes.CopyTo(result, 0);
        return result;
    }

    /// <summary>PBES2 password representation: UTF-8.</summary>
    public static byte[] Utf8Password(string password) => Encoding.UTF8.GetBytes(password);

    public static HashAlgorithmName HashFromDigestOid(string oid) => oid switch
    {
        Pkcs12Oids.Sha1 => HashAlgorithmName.SHA1,
        Pkcs12Oids.Sha256 => HashAlgorithmName.SHA256,
        Pkcs12Oids.Sha384 => HashAlgorithmName.SHA384,
        Pkcs12Oids.Sha512 => HashAlgorithmName.SHA512,
        _ => throw new PsignException($"unsupported PKCS#12 MAC digest algorithm {oid}"),
    };

    public static string DigestOid(HashAlgorithmName hash) =>
        hash == HashAlgorithmName.SHA1 ? Pkcs12Oids.Sha1
        : hash == HashAlgorithmName.SHA256 ? Pkcs12Oids.Sha256
        : hash == HashAlgorithmName.SHA384 ? Pkcs12Oids.Sha384
        : hash == HashAlgorithmName.SHA512 ? Pkcs12Oids.Sha512
        : throw new PsignException($"unsupported hash {hash}");

    private static (int U, int V) HashSizes(HashAlgorithmName hash) =>
        hash == HashAlgorithmName.SHA1 ? (20, 64)
        : hash == HashAlgorithmName.SHA256 ? (32, 64)
        : hash == HashAlgorithmName.SHA384 ? (48, 128)
        : hash == HashAlgorithmName.SHA512 ? (64, 128)
        : throw new PsignException($"unsupported PKCS#12 KDF hash {hash}");

    private static byte[] HashData(HashAlgorithmName hash, ReadOnlySpan<byte> data) =>
        hash == HashAlgorithmName.SHA1 ? SHA1.HashData(data)
        : hash == HashAlgorithmName.SHA256 ? SHA256.HashData(data)
        : hash == HashAlgorithmName.SHA384 ? SHA384.HashData(data)
        : SHA512.HashData(data);

    /// <summary>RFC 7292 appendix B.2 key derivation.</summary>
    public static byte[] Derive(HashAlgorithmName hash, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations, byte id, int length)
    {
        var (u, v) = HashSizes(hash);
        var d = new byte[v];
        Array.Fill(d, id);
        var sLen = salt.Length == 0 ? 0 : v * ((salt.Length + v - 1) / v);
        var pLen = password.Length == 0 ? 0 : v * ((password.Length + v - 1) / v);
        var i = new byte[sLen + pLen];
        for (var k = 0; k < sLen; k++)
        {
            i[k] = salt[k % salt.Length];
        }

        for (var k = 0; k < pLen; k++)
        {
            i[sLen + k] = password[k % password.Length];
        }

        var result = new byte[length];
        var produced = 0;
        var buf = new byte[v + i.Length];
        var b = new byte[v];
        while (produced < length)
        {
            d.CopyTo(buf, 0);
            i.CopyTo(buf, v);
            var a = HashData(hash, buf);
            for (var r = 1; r < iterations; r++)
            {
                a = HashData(hash, a);
            }

            var take = Math.Min(u, length - produced);
            Array.Copy(a, 0, result, produced, take);
            produced += take;
            if (produced >= length)
            {
                break;
            }

            for (var k = 0; k < v; k++)
            {
                b[k] = a[k % u];
            }

            for (var j = 0; j < i.Length; j += v)
            {
                var carry = 1;
                for (var k = v - 1; k >= 0; k--)
                {
                    var sum = i[j + k] + b[k] + carry;
                    i[j + k] = (byte)sum;
                    carry = sum >> 8;
                }
            }
        }

        return result;
    }

    /// <summary>PKCS#12 MAC (HMAC keyed with the PKCS#12 KDF, ID 3).</summary>
    public static byte[] ComputeMac(HashAlgorithmName hash, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations, ReadOnlySpan<byte> data)
    {
        var (u, _) = HashSizes(hash);
        var key = Derive(hash, password, salt, iterations, MacMaterial, u);
        return hash == HashAlgorithmName.SHA1 ? HMACSHA1.HashData(key, data)
            : hash == HashAlgorithmName.SHA256 ? HMACSHA256.HashData(key, data)
            : hash == HashAlgorithmName.SHA384 ? HMACSHA384.HashData(key, data)
            : HMACSHA512.HashData(key, data);
    }

    /// <summary>Decrypt <paramref name="ciphertext"/> encrypted with the PBE <c>AlgorithmIdentifier</c> <paramref name="algId"/>.</summary>
    public static byte[] Decrypt(ReadOnlyMemory<byte> algId, string password, byte[] ciphertext)
    {
        var alg = new AsnReader(algId, AsnEncodingRules.BER).ReadSequence();
        var oid = alg.ReadObjectIdentifier();
        switch (oid)
        {
            case Pkcs12Oids.PbeSha13Des:
            case Pkcs12Oids.PbeSha12Des:
            case Pkcs12Oids.PbeSha1Rc2128:
            case Pkcs12Oids.PbeSha1Rc240:
                {
                    var p = alg.ReadSequence();
                    var salt = p.ReadOctetString();
                    var iterations = (int)ReadSmallInteger(p);
                    var pwd = BmpPassword(password);
                    var keyLen = oid switch
                    {
                        Pkcs12Oids.PbeSha13Des => 24,
                        Pkcs12Oids.PbeSha12Des => 16,
                        Pkcs12Oids.PbeSha1Rc2128 => 16,
                        _ => 5,
                    };
                    var key = Derive(HashAlgorithmName.SHA1, pwd, salt, iterations, KeyMaterial, keyLen);
                    var iv = Derive(HashAlgorithmName.SHA1, pwd, salt, iterations, IvMaterial, 8);
                    using SymmetricAlgorithm cipher = oid is Pkcs12Oids.PbeSha13Des or Pkcs12Oids.PbeSha12Des ? TripleDES.Create() : CreateRc2(keyLen);
                    return DecryptCbc(cipher, key, iv, ciphertext);
                }

            case Pkcs12Oids.Pbes2:
                {
                    var p = alg.ReadSequence();
                    var kdf = p.ReadSequence();
                    var kdfOid = kdf.ReadObjectIdentifier();
                    if (kdfOid != Pkcs12Oids.Pbkdf2)
                    {
                        throw new PsignException($"unsupported PBES2 key derivation function {kdfOid}");
                    }

                    var kp = kdf.ReadSequence();
                    var salt = kp.ReadOctetString();
                    var iterations = (int)ReadSmallInteger(kp);
                    int? keyLength = null;
                    var prf = HashAlgorithmName.SHA1;
                    if (kp.HasData && kp.PeekTag().HasSameClassAndValue(Asn1Tag.Integer))
                    {
                        keyLength = (int)ReadSmallInteger(kp);
                    }

                    if (kp.HasData)
                    {
                        var prfSeq = kp.ReadSequence();
                        prf = prfSeq.ReadObjectIdentifier() switch
                        {
                            Pkcs12Oids.HmacSha1 => HashAlgorithmName.SHA1,
                            Pkcs12Oids.HmacSha256 => HashAlgorithmName.SHA256,
                            Pkcs12Oids.HmacSha384 => HashAlgorithmName.SHA384,
                            Pkcs12Oids.HmacSha512 => HashAlgorithmName.SHA512,
                            var other => throw new PsignException($"unsupported PBKDF2 PRF {other}"),
                        };
                    }

                    var enc = p.ReadSequence();
                    var encOid = enc.ReadObjectIdentifier();
                    var iv = enc.ReadOctetString();
                    var (cipherKeyLen, factory) = encOid switch
                    {
                        Pkcs12Oids.Aes128Cbc => (16, (Func<SymmetricAlgorithm>)Aes.Create),
                        Pkcs12Oids.Aes192Cbc => (24, Aes.Create),
                        Pkcs12Oids.Aes256Cbc => (32, Aes.Create),
                        Pkcs12Oids.DesEde3Cbc => (24, TripleDES.Create),
                        Pkcs12Oids.DesCbc => (8, DES.Create),
                        _ => throw new PsignException($"unsupported PBES2 encryption scheme {encOid}"),
                    };
                    var key = Rfc2898DeriveBytes.Pbkdf2(Utf8Password(password), salt, iterations, prf, keyLength ?? cipherKeyLen);
                    using var cipher = factory();
                    return DecryptCbc(cipher, key, iv, ciphertext);
                }

            case Pkcs12Oids.PbeSha1Rc4128:
            case Pkcs12Oids.PbeSha1Rc440:
                throw new PsignException($"unsupported PKCS#12 encryption algorithm {oid} (RC4)");
            default:
                throw new PsignException($"unsupported PKCS#12 encryption algorithm {oid}");
        }
    }

    /// <summary>
    /// Encrypt with PBES2 (PBKDF2-HMAC-SHA256, AES-256-CBC) like <c>picky</c> <c>Pkcs12Encryption::new_pbes2</c>
    /// (8-byte salt, 16-byte IV, 2048 iterations, no <c>keyLength</c>). Returns (AlgorithmIdentifier DER, ciphertext).
    /// </summary>
    public static (byte[] AlgorithmIdentifier, byte[] Ciphertext) EncryptPbes2Aes256(string password, ReadOnlySpan<byte> plaintext, int iterations = 2048)
    {
        var iv = RandomNumberGenerator.GetBytes(16);
        var salt = RandomNumberGenerator.GetBytes(8);
        var key = Rfc2898DeriveBytes.Pbkdf2(Utf8Password(password), salt, iterations, HashAlgorithmName.SHA256, 32);
        byte[] ciphertext;
        using (var aes = Aes.Create())
        {
            aes.Key = key;
            ciphertext = aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
        }

        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            w.WriteObjectIdentifier(Pkcs12Oids.Pbes2);
            using (w.PushSequence())
            {
                using (w.PushSequence())
                {
                    w.WriteObjectIdentifier(Pkcs12Oids.Pbkdf2);
                    using (w.PushSequence())
                    {
                        w.WriteOctetString(salt);
                        w.WriteInteger(iterations);
                        using (w.PushSequence())
                        {
                            w.WriteObjectIdentifier(Pkcs12Oids.HmacSha256);
                            w.WriteNull();
                        }
                    }
                }

                using (w.PushSequence())
                {
                    w.WriteObjectIdentifier(Pkcs12Oids.Aes256Cbc);
                    w.WriteOctetString(iv);
                }
            }
        }

        return (w.Encode(), ciphertext);
    }

    public static long ReadSmallInteger(AsnReader reader)
    {
        if (!reader.TryReadInt64(out var value) || value < 0 || value > int.MaxValue)
        {
            throw new PsignException("PKCS#12 integer out of range");
        }

        return value;
    }

    private static SymmetricAlgorithm CreateRc2(int keyLength)
    {
#pragma warning disable CA5351 // RC2 is required to read legacy PKCS#12 files
        var rc2 = RC2.Create();
#pragma warning restore CA5351
        rc2.KeySize = keyLength * 8;
        return rc2;
    }

    private static byte[] DecryptCbc(SymmetricAlgorithm cipher, byte[] key, byte[] iv, byte[] ciphertext)
    {
        cipher.Key = key;
        try
        {
            return cipher.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
        }
        catch (CryptographicException e)
        {
            throw new PsignException("PKCS#12 decryption failed (wrong password?)", e);
        }
    }
}
