using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Json;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Internal;
using Devolutions.Psign.Signing.Keys;
using Devolutions.Psign.Signing.Pki;

namespace Devolutions.Psign.Signing.CertStore;

/// <summary>Store selection (Rust <c>CertStoreSelectionArgs</c>): base directory override, scope, and store name.</summary>
public sealed record CertStoreSelection(string? CertStoreDir = null, bool MachineStore = false, string StoreName = "MY");

/// <summary>A resolved store directory (<c>{base}/{CurrentUser|LocalMachine}/{store}</c>).</summary>
public sealed record CertStoreLocation(string Scope, string StoreName, string StoreDir)
{
    /// <summary><c>{store}/{THUMBPRINT}.der</c>.</summary>
    public string CertPath(string thumbprint) => Path.Combine(StoreDir, thumbprint + ".der");

    /// <summary><c>{store}/{THUMBPRINT}.key</c> (PEM unencrypted PKCS#8).</summary>
    public string KeyPath(string thumbprint) => Path.Combine(StoreDir, thumbprint + ".key");
}

/// <summary>Signing identity resolved from the portable store (Rust <c>cert_store::SigningIdentity</c>).</summary>
public sealed record CertStoreSigningIdentity(
    string ThumbprintSha1,
    string Scope,
    string StoreName,
    string StoreDir,
    string CertPath,
    string KeyPath,
    byte[] CertDer,
    PrivateKeyMaterial Key)
{
    /// <summary>Canonical PKCS#8 PEM bytes (Rust <c>key_pem</c>).</summary>
    public byte[] KeyPem => Encoding.ASCII.GetBytes(Key.ToPkcs8Pem());

    /// <summary>Signer identity (no chain certificates) for portable signing.</summary>
    public SignerIdentity ToSignerIdentity() => SignerIdentity.FromKey(CertificateInfo.Parse(CertDer), [], Key);
}

/// <summary>Certificate details reported by <c>list</c> / <c>print</c> (Rust <c>CertificateDetails</c>).</summary>
public sealed record CertificateDetails(
    string ThumbprintSha1,
    string Subject,
    string Issuer,
    string NotBefore,
    string NotAfter,
    string Path,
    bool HasPrivateKey,
    string? KeyPath)
{
    public JsonObject ToJsonObject() => new()
    {
        ["thumbprint_sha1"] = ThumbprintSha1,
        ["subject"] = Subject,
        ["issuer"] = Issuer,
        ["not_before"] = NotBefore,
        ["not_after"] = NotAfter,
        ["path"] = Path,
        ["has_private_key"] = HasPrivateKey,
        ["key_path"] = KeyPath,
    };

    /// <summary>Pretty JSON plus trailing newline (CLI <c>--json</c> output).</summary>
    public string ToJson() => RustJson.Pretty(ToJsonObject()) + "\n";

    /// <summary>Text output of <c>cert-store print</c>.</summary>
    public string Format() =>
        $"Certificate\nthumbprint_sha1={ThumbprintSha1}\nsubject={Subject}\nissuer={Issuer}\nnot_before={NotBefore}\nnot_after={NotAfter}\nhas_private_key={Bool(HasPrivateKey)}\npath={Path}\n";

    internal static string Bool(bool value) => value ? "true" : "false";
}

/// <summary>Result of <c>import</c> / <c>import-pfx</c> (Rust <c>ImportReport</c>).</summary>
public sealed record CertStoreImportReport(string ThumbprintSha1, string Scope, string Store, string Path, bool Imported, string? KeyPath, bool KeyImported)
{
    /// <summary>Text output (Rust <c>format_import_report</c>).</summary>
    public string Format()
    {
        var sb = new StringBuilder();
        sb.Append(Imported ? "Imported" : "Certificate already present").Append(" certificate\n");
        sb.Append("thumbprint_sha1=").Append(ThumbprintSha1).Append('\n');
        sb.Append("store=").Append(Scope).Append('\\').Append(Store).Append('\n');
        sb.Append("path=").Append(Path).Append('\n');
        if (KeyPath is not null)
        {
            sb.Append(KeyImported ? "Imported" : "Private key already present").Append(" private key\n");
            sb.Append("key_path=").Append(KeyPath).Append('\n');
        }

        return sb.ToString();
    }
}

/// <summary>Result of <c>list</c> (Rust <c>ListReport</c>).</summary>
public sealed record CertStoreListReport(string Scope, string Store, string Path, IReadOnlyList<CertificateDetails> Certificates)
{
    public JsonObject ToJsonObject() => new()
    {
        ["scope"] = Scope,
        ["store"] = Store,
        ["path"] = Path,
        ["certificates"] = new JsonArray(Certificates.Select(c => (JsonNode)c.ToJsonObject()).ToArray()),
    };

    /// <summary>Pretty JSON plus trailing newline (CLI <c>--json</c> output).</summary>
    public string ToJson() => RustJson.Pretty(ToJsonObject()) + "\n";

    /// <summary>Text output (Rust <c>format_list_report</c>).</summary>
    public string Format()
    {
        var sb = new StringBuilder();
        sb.Append("Store: ").Append(Scope).Append('\\').Append(Store).Append('\n');
        sb.Append("Path: ").Append(Path).Append('\n');
        if (Certificates.Count == 0)
        {
            sb.Append("No certificates found\n");
            return sb.ToString();
        }

        foreach (var c in Certificates)
        {
            sb.Append(c.ThumbprintSha1).Append('\n');
            sb.Append("  subject=").Append(c.Subject).Append('\n');
            sb.Append("  issuer=").Append(c.Issuer).Append('\n');
            sb.Append("  not_before=").Append(c.NotBefore).Append('\n');
            sb.Append("  not_after=").Append(c.NotAfter).Append('\n');
            sb.Append("  has_private_key=").Append(CertificateDetails.Bool(c.HasPrivateKey)).Append('\n');
            sb.Append("  path=").Append(c.Path).Append('\n');
        }

        return sb.ToString();
    }
}

/// <summary>
/// Portable file-backed certificate store (port of Rust <c>src/cert_store.rs</c>). Layout shared with the Rust tool:
/// <c>{base}/{CurrentUser|LocalMachine}/{Store}/{SHA1}.der</c> (DER certificate) and <c>{SHA1}.key</c> (PEM unencrypted
/// PKCS#8). The base directory is <c>--cert-store-dir</c>, else <c>PSIGN_CERT_STORE</c>, else <c>~/.psign/cert-store</c>.
/// </summary>
public sealed class PortableCertStore
{
    /// <summary>Environment variable overriding the base directory.</summary>
    public const string EnvCertStore = "PSIGN_CERT_STORE";

    private readonly Func<string, string?> _environment;

    public PortableCertStore(Func<string, string?>? environment = null)
    {
        _environment = environment ?? Environment.GetEnvironmentVariable;
    }

    /// <summary>Resolve the store base directory (Rust <c>resolve_base_dir</c>).</summary>
    public string ResolveBaseDir(string? explicitDir)
    {
        if (explicitDir is not null)
        {
            return explicitDir;
        }

        if (_environment(EnvCertStore) is { Length: > 0 } env)
        {
            return env;
        }

        return Path.Combine(HomeDir(), ".psign", "cert-store");
    }

    private string HomeDir()
    {
        if (_environment("HOME") is { Length: > 0 } home)
        {
            return home;
        }

        if (_environment("USERPROFILE") is { Length: > 0 } profile)
        {
            return profile;
        }

        if (_environment("HOMEDRIVE") is { Length: > 0 } drive && _environment("HOMEPATH") is { Length: > 0 } homePath)
        {
            return Path.Combine(drive, homePath);
        }

        throw new PsignException($"cannot resolve default cert-store path: set {EnvCertStore} or --cert-store-dir");
    }

    /// <summary>Resolve <paramref name="selection"/> to a store directory (Rust <c>resolve_location</c>).</summary>
    public CertStoreLocation ResolveLocation(CertStoreSelection selection)
    {
        var baseDir = ResolveBaseDir(selection.CertStoreDir);
        var scope = selection.MachineStore ? "LocalMachine" : "CurrentUser";
        var storeName = NormalizeStoreName(selection.StoreName);
        return new CertStoreLocation(scope, storeName, Path.Combine(baseDir, scope, storeName));
    }

    /// <summary>Canonicalize well-known store names and reject path separators (Rust <c>normalize_store_name</c>).</summary>
    public static string NormalizeStoreName(string input)
    {
        var trimmed = input.Trim();
        if (trimmed.Length == 0)
        {
            throw new PsignException("certificate store name must not be empty");
        }

        if (trimmed.IndexOfAny(['/', '\\', '\0']) >= 0)
        {
            throw new PsignException("certificate store name must not contain path separators");
        }

        return trimmed.ToLowerInvariant() switch
        {
            "my" => "MY",
            "root" => "Root",
            "ca" => "CA",
            "trust" => "Trust",
            "disallowed" => "Disallowed",
            _ => trimmed,
        };
    }

    /// <summary>Normalize a SHA-1 thumbprint (colons / whitespace removed, upper-case) (Rust <c>normalize_sha1_hex</c>).</summary>
    public static string NormalizeSha1Hex(string input)
    {
        var clean = new string(input.Where(c => c != ':' && !IsAsciiWhitespace(c)).ToArray());
        if (clean.Length != 40)
        {
            throw new PsignException("SHA1 thumbprint must be 40 hex characters");
        }

        if (!clean.All(char.IsAsciiHexDigit))
        {
            throw new PsignException("SHA1 thumbprint contains invalid hex");
        }

        return clean.ToUpperInvariant();
    }

    /// <summary>Upper-case SHA-1 thumbprint of DER bytes.</summary>
    public static string Sha1ThumbprintUpper(byte[] der) => Hex.Upper(SHA1.HashData(der));

    /// <summary>Resolve a signing certificate and key by thumbprint (Rust <c>resolve_signing_identity</c>).</summary>
    public CertStoreSigningIdentity ResolveSigningIdentity(string? certStoreDir, bool machineStore, string storeName, string sha1)
    {
        var loc = ResolveLocation(new CertStoreSelection(certStoreDir, machineStore, storeName));
        var thumbprint = NormalizeSha1Hex(sha1);
        var certPath = loc.CertPath(thumbprint);
        var keyPath = loc.KeyPath(thumbprint);
        byte[] certDer;
        try
        {
            certDer = ReadExistingCert(certPath);
        }
        catch (PsignException e)
        {
            throw new PsignException($"resolve signing certificate SHA1 {thumbprint} in {loc.Scope}\\{loc.StoreName}", e);
        }

        var cert = ParseX509(certDer, certPath);
        string keyText;
        try
        {
            keyText = File.ReadAllText(keyPath);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"resolve private key for SHA1 {thumbprint} in {loc.Scope}\\{loc.StoreName}", IoErrorText.Inner(e));
        }

        PrivateKeyMaterial key;
        try
        {
            key = PrivateKeyMaterial.FromPkcs8Pem(keyText);
        }
        catch (PsignException e)
        {
            throw new PsignException($"parse private key '{keyPath}'; expected PEM unencrypted PKCS#8 (BEGIN PRIVATE KEY)", e);
        }

        key.EnsureMatchesCertificate(cert);
        return new CertStoreSigningIdentity(thumbprint, loc.Scope, loc.StoreName, loc.StoreDir, certPath, keyPath, certDer, key);
    }

    /// <summary>Import a DER / PEM certificate and optional PKCS#8 PEM key (Rust <c>import_cert</c>).</summary>
    public CertStoreImportReport Import(CertStoreSelection selection, string certPath, string? keyPath = null)
    {
        var loc = ResolveLocation(selection);
        var der = LoadCertDer(certPath);
        var thumbprint = Sha1ThumbprintUpper(der);
        var path = loc.CertPath(thumbprint);
        CreateStoreDir(loc);
        var imported = WriteCertIfNeeded(path, der);
        string? storedKeyPath = null;
        var keyImported = false;
        if (keyPath is not null)
        {
            var key = PrivateKeyLoader.LoadPkcs8KeyPemFile(keyPath);
            Pkcs12Identity.EnsureKeyMatchesCertificate(der, key);
            storedKeyPath = loc.KeyPath(thumbprint);
            keyImported = WriteKeyIfNeeded(storedKeyPath, Encoding.ASCII.GetBytes(key.ToPkcs8Pem()));
        }

        return new CertStoreImportReport(thumbprint, loc.Scope, loc.StoreName, path, imported, storedKeyPath, keyImported);
    }

    /// <summary>Import the signer certificate and key from a PFX (Rust <c>import_pfx</c>).</summary>
    public CertStoreImportReport ImportPfx(CertStoreSelection selection, string pfxPath, string password)
    {
        var loc = ResolveLocation(selection);
        byte[] pfx;
        try
        {
            pfx = File.ReadAllBytes(pfxPath);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"read PFX '{pfxPath}'", IoErrorText.Inner(e));
        }

        ParsedPfxIdentity parsed;
        try
        {
            parsed = Pkcs12Identity.Parse(pfx, password);
        }
        catch (PsignException e)
        {
            throw new PsignException($"parse PFX '{pfxPath}'", e);
        }

        var der = parsed.SignerCertificateDer;
        var thumbprint = Sha1ThumbprintUpper(der);
        var path = loc.CertPath(thumbprint);
        CreateStoreDir(loc);
        var imported = WriteCertIfNeeded(path, der);
        var keyPath = loc.KeyPath(thumbprint);
        var keyImported = WriteKeyIfNeeded(keyPath, Encoding.ASCII.GetBytes(parsed.PrivateKeyPem));
        return new CertStoreImportReport(thumbprint, loc.Scope, loc.StoreName, path, imported, keyPath, keyImported);
    }

    /// <summary>List certificates (sorted by thumbprint) (Rust <c>list_certs</c>).</summary>
    public CertStoreListReport List(CertStoreSelection selection)
    {
        var loc = ResolveLocation(selection);
        var certificates = new List<CertificateDetails>();
        if (Directory.Exists(loc.StoreDir))
        {
            IEnumerable<string> entries;
            try
            {
                entries = Directory.EnumerateFiles(loc.StoreDir).ToList();
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                throw new PsignException($"read cert store '{loc.StoreDir}'", IoErrorText.Inner(e));
            }

            foreach (var path in entries)
            {
                if (System.IO.Path.GetExtension(path) != ".der")
                {
                    continue;
                }

                byte[] der;
                try
                {
                    der = File.ReadAllBytes(path);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    throw new PsignException($"read certificate '{path}'", IoErrorText.Inner(e));
                }

                certificates.Add(DetailsFromDerPath(loc, der, path));
            }
        }

        certificates.Sort((a, b) => string.CompareOrdinal(a.ThumbprintSha1, b.ThumbprintSha1));
        return new CertStoreListReport(loc.Scope, loc.StoreName, loc.StoreDir, certificates);
    }

    /// <summary>Show one certificate (Rust <c>print_cert</c>).</summary>
    public CertificateDetails Print(CertStoreSelection selection, string sha1)
    {
        var loc = ResolveLocation(selection);
        var thumbprint = NormalizeSha1Hex(sha1);
        var path = loc.CertPath(thumbprint);
        return DetailsFromDerPath(loc, ReadExistingCert(path), path);
    }

    /// <summary>Export a certificate (and optionally its key); returns the CLI text output (Rust <c>export_cert</c>).</summary>
    public string Export(CertStoreSelection selection, string sha1, string outPath, bool withKey = false, string? keyOut = null, bool force = false)
    {
        var loc = ResolveLocation(selection);
        var thumbprint = NormalizeSha1Hex(sha1);
        var path = loc.CertPath(thumbprint);
        var der = ReadExistingCert(path);
        ParseX509(der, path);
        var keyPath = loc.KeyPath(thumbprint);
        if (withKey && !File.Exists(keyPath))
        {
            throw new PsignException($"private key for SHA1 thumbprint {thumbprint} was not found in {loc.Scope}\\{loc.StoreName}");
        }

        string? keyOutPath = null;
        if (withKey)
        {
            keyOutPath = keyOut ?? throw new PsignException("--key-out is required when exporting with --with-key");
        }

        if (PathExists(outPath) && !force)
        {
            throw new PsignException($"output file '{outPath}' already exists; use --force to replace it");
        }

        if (keyOutPath is not null && PathExists(keyOutPath) && !force)
        {
            throw new PsignException($"key output file '{keyOutPath}' already exists; use --force to replace it");
        }

        WriteFile(outPath, der, $"write exported certificate '{outPath}'");
        var output = new StringBuilder($"Exported certificate\nthumbprint_sha1={thumbprint}\npath={path}\nout={outPath}\n");
        if (keyOutPath is not null)
        {
            var keyPem = ReadExistingKey(keyPath);
            WriteFile(keyOutPath, keyPem, $"write exported private key '{keyOutPath}'");
            output.Append("key_path=").Append(keyPath).Append("\nkey_out=").Append(keyOutPath).Append('\n');
        }

        return output.ToString();
    }

    /// <summary>Remove a certificate and its key; returns the CLI text output (Rust <c>remove_cert</c>).</summary>
    public string Remove(CertStoreSelection selection, string sha1)
    {
        var loc = ResolveLocation(selection);
        var thumbprint = NormalizeSha1Hex(sha1);
        var path = loc.CertPath(thumbprint);
        if (!File.Exists(path))
        {
            throw new PsignException($"certificate with SHA1 thumbprint {thumbprint} was not found in {loc.Scope}\\{loc.StoreName}");
        }

        DeleteFile(path, $"remove certificate '{path}'");
        var keyPath = loc.KeyPath(thumbprint);
        var keyRemoved = false;
        if (File.Exists(keyPath))
        {
            DeleteFile(keyPath, $"remove private key '{keyPath}'");
            keyRemoved = true;
        }

        return $"Removed certificate\nthumbprint_sha1={thumbprint}\nstore={loc.Scope}\\{loc.StoreName}\npath={path}\nkey_removed={CertificateDetails.Bool(keyRemoved)}\n";
    }

    private static CertificateDetails DetailsFromDerPath(CertStoreLocation loc, byte[] der, string path)
    {
        var cert = ParseX509(der, path);
        var thumbprint = Sha1ThumbprintUpper(der);
        var keyPath = loc.KeyPath(thumbprint);
        var hasPrivateKey = File.Exists(keyPath);
        return new CertificateDetails(
            thumbprint,
            DistinguishedName.FormatRfc4514(cert.Subject),
            DistinguishedName.FormatRfc4514(cert.Issuer),
            Asn1Time.Rfc3339(cert.NotBefore),
            Asn1Time.Rfc3339(cert.NotAfter),
            path,
            hasPrivateKey,
            hasPrivateKey ? keyPath : null);
    }

    private static CertificateInfo ParseX509(byte[] der, string path)
    {
        try
        {
            return CertificateInfo.Parse(der);
        }
        catch (PsignException e)
        {
            throw new PsignException($"parse X.509 certificate '{path}'", e);
        }
    }

    private static byte[] LoadCertDer(string path)
    {
        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"read certificate '{path}'", IoErrorText.Inner(e));
        }

        byte[] der;
        try
        {
            der = CertificateLoader.PemOrDerToDer(bytes);
        }
        catch (PsignException e)
        {
            throw new PsignException($"parse certificate '{path}'", e);
        }

        ParseX509(der, path);
        return der;
    }

    private static byte[] ReadExistingCert(string path)
    {
        if (!PathExists(path))
        {
            throw new PsignException($"certificate '{path}' was not found");
        }

        try
        {
            return File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"read certificate '{path}'", IoErrorText.Inner(e));
        }
    }

    private static byte[] ReadExistingKey(string path)
    {
        if (!PathExists(path))
        {
            throw new PsignException($"private key '{path}' was not found");
        }

        try
        {
            return File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"read private key '{path}'", IoErrorText.Inner(e));
        }
    }

    private static void CreateStoreDir(CertStoreLocation loc)
    {
        try
        {
            Directory.CreateDirectory(loc.StoreDir);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"create cert store '{loc.StoreDir}'", IoErrorText.Inner(e));
        }
    }

    private static bool WriteCertIfNeeded(string path, byte[] der)
    {
        if (PathExists(path))
        {
            return false;
        }

        WriteFile(path, der, $"write certificate '{path}'");
        return true;
    }

    private static bool WriteKeyIfNeeded(string path, byte[] keyPem)
    {
        if (PathExists(path))
        {
            return false;
        }

        WritePrivateKeyFile(path, keyPem);
        return true;
    }

    private static void WritePrivateKeyFile(string path, byte[] bytes)
    {
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            using var fs = new FileStream(path, options);
            fs.Write(bytes);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"write private key '{path}'", IoErrorText.Inner(e));
        }
    }

    private static void WriteFile(string path, byte[] bytes, string context)
    {
        try
        {
            File.WriteAllBytes(path, bytes);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException(context, IoErrorText.Inner(e));
        }
    }

    private static void DeleteFile(string path, string context)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException(context, IoErrorText.Inner(e));
        }
    }

    private static bool PathExists(string path) => File.Exists(path) || Directory.Exists(path);

    private static bool IsAsciiWhitespace(char c) => c is ' ' or '\t' or '\n' or '\f' or '\r';
}
