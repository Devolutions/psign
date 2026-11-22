using System.Security.Cryptography;

namespace Devolutions.Psign.Core;

/// <summary>
/// Digest algorithms supported for Authenticode subject digests (Rust <c>PeAuthenticodeHashKind</c>).
/// </summary>
public enum AuthenticodeHashKind
{
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

/// <summary>Helpers for <see cref="AuthenticodeHashKind"/>.</summary>
public static class AuthenticodeHashKindExtensions
{
    /// <summary>Digest output size in bytes.</summary>
    public static int DigestLength(this AuthenticodeHashKind kind) => kind switch
    {
        AuthenticodeHashKind.Sha1 => 20,
        AuthenticodeHashKind.Sha256 => 32,
        AuthenticodeHashKind.Sha384 => 48,
        AuthenticodeHashKind.Sha512 => 64,
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    /// <summary>Digest algorithm OID (for example <c>2.16.840.1.101.3.4.2.1</c>).</summary>
    public static string Oid(this AuthenticodeHashKind kind) => kind switch
    {
        AuthenticodeHashKind.Sha1 => Oids.Sha1,
        AuthenticodeHashKind.Sha256 => Oids.Sha256,
        AuthenticodeHashKind.Sha384 => Oids.Sha384,
        AuthenticodeHashKind.Sha512 => Oids.Sha512,
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    /// <summary>RSA PKCS#1 v1.5 signature algorithm OID for this digest (for example <c>sha256WithRSAEncryption</c>).</summary>
    public static string RsaSignatureOid(this AuthenticodeHashKind kind) => kind switch
    {
        AuthenticodeHashKind.Sha1 => Oids.Sha1WithRsa,
        AuthenticodeHashKind.Sha256 => Oids.Sha256WithRsa,
        AuthenticodeHashKind.Sha384 => Oids.Sha384WithRsa,
        AuthenticodeHashKind.Sha512 => Oids.Sha512WithRsa,
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    /// <summary>.NET hash algorithm name.</summary>
    public static HashAlgorithmName HashAlgorithmName(this AuthenticodeHashKind kind) => kind switch
    {
        AuthenticodeHashKind.Sha1 => System.Security.Cryptography.HashAlgorithmName.SHA1,
        AuthenticodeHashKind.Sha256 => System.Security.Cryptography.HashAlgorithmName.SHA256,
        AuthenticodeHashKind.Sha384 => System.Security.Cryptography.HashAlgorithmName.SHA384,
        AuthenticodeHashKind.Sha512 => System.Security.Cryptography.HashAlgorithmName.SHA512,
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    /// <summary>Lowercase display name (<c>sha1</c>, <c>sha256</c>, ...).</summary>
    public static string Name(this AuthenticodeHashKind kind) => kind switch
    {
        AuthenticodeHashKind.Sha1 => "sha1",
        AuthenticodeHashKind.Sha256 => "sha256",
        AuthenticodeHashKind.Sha384 => "sha384",
        AuthenticodeHashKind.Sha512 => "sha512",
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    /// <summary>Create an incremental hasher.</summary>
    public static IncrementalHash CreateHasher(this AuthenticodeHashKind kind) =>
        IncrementalHash.CreateHash(kind.HashAlgorithmName());

    /// <summary>One-shot digest.</summary>
    public static byte[] Hash(this AuthenticodeHashKind kind, ReadOnlySpan<byte> data) => kind switch
    {
        AuthenticodeHashKind.Sha1 => SHA1.HashData(data),
        AuthenticodeHashKind.Sha256 => SHA256.HashData(data),
        AuthenticodeHashKind.Sha384 => SHA384.HashData(data),
        AuthenticodeHashKind.Sha512 => SHA512.HashData(data),
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };
}

/// <summary>Parsing helpers for <see cref="AuthenticodeHashKind"/>.</summary>
public static class AuthenticodeHashKinds
{
    /// <summary>Infer the algorithm from a digest length (20/32/48/64).</summary>
    public static AuthenticodeHashKind FromDigestLength(int length) => length switch
    {
        20 => AuthenticodeHashKind.Sha1,
        32 => AuthenticodeHashKind.Sha256,
        48 => AuthenticodeHashKind.Sha384,
        64 => AuthenticodeHashKind.Sha512,
        _ => throw new PsignException(
            $"unsupported Authenticode digest length {length} bytes (expected 20/32/48/64)"),
    };

    /// <summary>Map a digest algorithm OID to a hash kind, or <c>null</c> when unsupported.</summary>
    public static AuthenticodeHashKind? FromOid(string oid) => oid switch
    {
        Oids.Sha1 => AuthenticodeHashKind.Sha1,
        Oids.Sha256 => AuthenticodeHashKind.Sha256,
        Oids.Sha384 => AuthenticodeHashKind.Sha384,
        Oids.Sha512 => AuthenticodeHashKind.Sha512,
        _ => null,
    };

    /// <summary>Parse a case-insensitive algorithm name (<c>sha1</c>, <c>sha256</c>, <c>SHA-256</c>, ...).</summary>
    public static AuthenticodeHashKind Parse(string name)
    {
        return TryParse(name, out var kind)
            ? kind
            : throw new PsignException($"unsupported digest algorithm '{name}' (expected sha1, sha256, sha384, or sha512)");
    }

    /// <summary>Try to parse an algorithm name.</summary>
    public static bool TryParse(string? name, out AuthenticodeHashKind kind)
    {
        switch (name?.Trim().Replace("-", string.Empty, StringComparison.Ordinal).ToLowerInvariant())
        {
            case "sha1":
                kind = AuthenticodeHashKind.Sha1;
                return true;
            case "sha256":
                kind = AuthenticodeHashKind.Sha256;
                return true;
            case "sha384":
                kind = AuthenticodeHashKind.Sha384;
                return true;
            case "sha512":
                kind = AuthenticodeHashKind.Sha512;
                return true;
            default:
                kind = default;
                return false;
        }
    }
}
