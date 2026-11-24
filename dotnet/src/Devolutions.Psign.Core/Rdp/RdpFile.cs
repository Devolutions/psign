using System.Buffers.Binary;
using System.Text;
using Devolutions.Psign.Core.Text;

namespace Devolutions.Psign.Core.Rdp;

/// <summary>RDP setting value type (Rust <c>RdpValueKind</c>).</summary>
public enum RdpValueKind
{
    /// <summary><c>i</c>.</summary>
    Integer,

    /// <summary><c>s</c>.</summary>
    String,

    /// <summary><c>b</c>.</summary>
    Binary,
}

/// <summary>One <c>name:type:value</c> line of an <c>.rdp</c> file (Rust <c>RdpRecord</c>).</summary>
public sealed record RdpRecord(string Name, RdpValueKind Kind, string Value)
{
    /// <summary>String-typed record.</summary>
    public static RdpRecord String(string name, string value) => new(name, RdpValueKind.String, value);
}

/// <summary>Records ready for signing plus the computed <c>SignScope</c> and secure-settings blob (Rust <c>PreparedRdpSignature</c>).</summary>
public sealed record PreparedRdpSignature(List<RdpRecord> Records, string SignScope, byte[] SecureBlob);

/// <summary>
/// Portable RDP file signing primitives (port of <c>psign-sip-digest/src/rdp.rs</c>): text decoding, record parsing,
/// <c>SignScope</c> computation, the UTF-16LE secure-settings blob that is signed, and the serialized <c>Signature</c>
/// record format.
/// </summary>
public static class RdpFile
{
    /// <summary>Serialized signature header version (<c>0x00010001</c>).</summary>
    public const uint SignatureVersion = 0x0001_0001;

    /// <summary>Serialized signature type for certificate signatures.</summary>
    public const uint CertSignatureType = 1;

    /// <summary>Settings covered by <c>SignScope</c>, in native order, with whether each is required.</summary>
    public static IReadOnlyList<(string Name, bool Required)> SensitiveSettings { get; } =
    [
        ("Full Address", true),
        ("Alternate Full Address", false),
        ("PCB", false),
        ("Use Redirection Server Name", false),
        ("Server Port", false),
        ("Negotiate Security Layer", false),
        ("EnableCredSspSupport", false),
        ("DisableConnectionSharing", false),
        ("AutoReconnection Enabled", false),
        ("GatewayHostname", false),
        ("GatewayUsageMethod", false),
        ("GatewayProfileUsageMethod", false),
        ("GatewayCredentialsSource", false),
        ("Support URL", false),
        ("PromptCredentialOnce", false),
        ("Require pre-authentication", false),
        ("Pre-authentication server address", false),
        ("Alternate Shell", false),
        ("Shell Working Directory", false),
        ("RemoteApplicationProgram", false),
        ("RemoteApplicationExpandWorkingdir", false),
        ("RemoteApplicationMode", false),
        ("RemoteApplicationGuid", false),
        ("RemoteApplicationName", false),
        ("RemoteApplicationIcon", false),
        ("RemoteApplicationFile", false),
        ("RemoteApplicationFileExtensions", false),
        ("RemoteApplicationCmdLine", false),
        ("RemoteApplicationExpandCmdLine", false),
        ("Prompt For Credentials", false),
        ("Authentication Level", false),
        ("AudioMode", false),
        ("RedirectDrives", false),
        ("RedirectPrinters", false),
        ("RedirectCOMPorts", false),
        ("RedirectSmartCards", false),
        ("RedirectPOSDevices", false),
        ("RedirectClipboard", false),
        ("DevicesToRedirect", false),
        ("DrivesToRedirect", false),
        ("LoadBalanceInfo", false),
        ("RedirectDirectX", false),
        ("RDGIsKDCProxy", false),
        ("KDCProxyName", false),
        ("EnableRdsAadAuth", false),
        ("RedirectWebAuthn", false),
        ("RedirectTextProcessing", false),
        ("allowed security protocols", false),
    ];

    /// <summary>
    /// Decode <c>.rdp</c> bytes: UTF-16 with BOM, BOM-less UTF-16 (detected by NUL density), UTF-8 (leading BOMs
    /// stripped), or lossy UTF-8 (Rust <c>decode_rdp_text</c>).
    /// </summary>
    public static string DecodeRdpText(ReadOnlySpan<byte> bytes)
    {
        if (bytes.StartsWith((ReadOnlySpan<byte>)[0xFF, 0xFE]))
        {
            return RustText.FromUtf16Lossy(RustText.Utf16LeUnits(bytes[2..]));
        }

        if (bytes.StartsWith((ReadOnlySpan<byte>)[0xFE, 0xFF]))
        {
            return RustText.FromUtf16Lossy(RustText.Utf16BeUnits(bytes[2..]));
        }

        var bomless = DecodeBomlessUtf16(bytes);
        if (bomless is not null)
        {
            return bomless;
        }

        var strict = RustText.TryFromUtf8(bytes);
        var text = strict ?? RustText.FromUtf8Lossy(bytes);
        return text.TrimStart('\uFEFF');
    }

    private static string? DecodeBomlessUtf16(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 4 || bytes.Length % 2 != 0)
        {
            return null;
        }

        int pairs = bytes.Length / 2;
        int evenNuls = 0;
        int oddNuls = 0;
        for (int i = 0; i < bytes.Length; i++)
        {
            if (bytes[i] == 0)
            {
                if (i % 2 == 0)
                {
                    evenNuls++;
                }
                else
                {
                    oddNuls++;
                }
            }
        }

        if (oddNuls * 2 >= pairs)
        {
            return RustText.FromUtf16Lossy(RustText.Utf16LeUnits(bytes));
        }

        if (evenNuls * 2 >= pairs)
        {
            return RustText.FromUtf16Lossy(RustText.Utf16BeUnits(bytes));
        }

        return null;
    }

    /// <summary>Encode text as native <c>mstsc</c> output: UTF-16LE with a BOM (Rust <c>encode_native_unicode</c>).</summary>
    public static byte[] EncodeNativeUnicode(string text)
    {
        var result = new byte[2 + (text.Length * 2)];
        result[0] = 0xFF;
        result[1] = 0xFE;
        RustText.Utf16LeBytes(text).CopyTo(result, 2);
        return result;
    }

    /// <summary>Parse all well-formed records; malformed lines are skipped (Rust <c>parse_records</c>).</summary>
    public static List<RdpRecord> ParseRecords(string text)
    {
        var records = new List<RdpRecord>();
        foreach (var line in RustText.Lines(text))
        {
            if (ParseLine(line) is { } record)
            {
                records.Add(record);
            }
        }

        return records;
    }

    /// <summary>
    /// Remove existing <c>SignScope</c> / <c>Signature</c>, add <c>Alternate Full Address</c> when missing, compute
    /// <c>SignScope</c> over the present sensitive settings, and build the secure-settings blob (Rust
    /// <c>prepare_for_signature</c>).
    /// </summary>
    public static PreparedRdpSignature PrepareForSignature(IEnumerable<RdpRecord> input)
    {
        var records = input.ToList();
        RemoveRecord(records, "SignScope");
        RemoveRecord(records, "Signature");

        var full = FindRecord(records, "Full Address");
        if (full is null || full.Value.Length == 0)
        {
            throw new PsignException("RDP file is missing required Full Address setting");
        }

        if (FindRecord(records, "Alternate Full Address") is null)
        {
            InsertOrReplace(records, RdpRecord.String("Alternate Full Address", full.Value));
        }

        var scopeNames = new List<string>();
        foreach (var (name, required) in SensitiveSettings)
        {
            var record = FindRecord(records, name);
            if (record is null)
            {
                if (required)
                {
                    throw new PsignException($"RDP file is missing required {name} setting");
                }

                continue;
            }

            if (required && record.Value.Length == 0)
            {
                throw new PsignException($"RDP file has an empty required {name} setting");
            }

            scopeNames.Add(name);
        }

        var signScope = string.Join(",", scopeNames);
        InsertOrReplace(records, RdpRecord.String("SignScope", signScope));
        var secureBlob = SecureSettingsBlob(records, signScope);
        return new PreparedRdpSignature(records, signScope, secureBlob);
    }

    /// <summary>Insert or replace the <c>Signature</c> record with the serialized PKCS#7 (Rust <c>apply_pkcs7_signature</c>).</summary>
    public static void ApplyPkcs7Signature(List<RdpRecord> records, ReadOnlySpan<byte> pkcs7)
    {
        var encoded = Base64Standard.Encode(SerializeSignature(pkcs7));
        InsertOrReplace(records, RdpRecord.String("Signature", encoded));
    }

    /// <summary>Render records as <c>name:t:value\r\n</c> lines (Rust <c>records_to_text</c>).</summary>
    public static string RecordsToText(IEnumerable<RdpRecord> records)
    {
        var sb = new StringBuilder();
        foreach (var record in records)
        {
            sb.Append(RecordToLine(record));
        }

        return sb.ToString();
    }

    /// <summary>Native serialized signature: version, type, length (all LE <c>u32</c>) + PKCS#7 (Rust <c>serialize_signature</c>).</summary>
    public static byte[] SerializeSignature(ReadOnlySpan<byte> pkcs7)
    {
        var result = new byte[12 + pkcs7.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(0, 4), SignatureVersion);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4, 4), CertSignatureType);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8, 4), (uint)pkcs7.Length);
        pkcs7.CopyTo(result.AsSpan(12));
        return result;
    }

    /// <summary>Decode a <c>Signature</c> record value to PKCS#7 DER (Rust <c>signature_pkcs7_from_base64</c>).</summary>
    public static byte[] SignaturePkcs7FromBase64(string value)
    {
        byte[] serialized;
        try
        {
            serialized = Base64Standard.Decode(value.Trim());
        }
        catch (FormatException e)
        {
            throw new PsignException("decode RDP Signature base64", e);
        }

        return SignaturePkcs7FromSerialized(serialized);
    }

    /// <summary>PKCS#7 DER from the <c>Signature</c> record (Rust <c>signature_record_pkcs7</c>).</summary>
    public static byte[] SignatureRecordPkcs7(IEnumerable<RdpRecord> records)
    {
        var record = FindRecord(records, "Signature")
            ?? throw new PsignException("RDP file does not contain a Signature record");
        return SignaturePkcs7FromBase64(record.Value);
    }

    /// <summary>Validate the 12-byte header and return the PKCS#7 payload (Rust <c>signature_pkcs7_from_serialized</c>).</summary>
    public static byte[] SignaturePkcs7FromSerialized(ReadOnlySpan<byte> serialized)
    {
        if (serialized.Length < 12)
        {
            throw new PsignException("RDP Signature payload is shorter than 12-byte header");
        }

        uint version = BinaryPrimitives.ReadUInt32LittleEndian(serialized[..4]);
        uint signatureType = BinaryPrimitives.ReadUInt32LittleEndian(serialized[4..8]);
        uint len = BinaryPrimitives.ReadUInt32LittleEndian(serialized[8..12]);
        if (version != SignatureVersion)
        {
            throw new PsignException($"unsupported RDP Signature version 0x{version:x8}");
        }

        if (signatureType != CertSignatureType)
        {
            throw new PsignException($"unsupported RDP Signature type {signatureType}");
        }

        if ((ulong)(serialized.Length - 12) != len)
        {
            throw new PsignException(
                $"RDP Signature length header says {len} byte(s), payload has {serialized.Length - 12}");
        }

        return serialized[12..].ToArray();
    }

    /// <summary>
    /// UTF-16LE (NUL-terminated) concatenation of the <c>SignScope</c> fields' lines followed by the <c>SignScope</c>
    /// line itself (Rust <c>secure_settings_blob</c>).
    /// </summary>
    public static byte[] SecureSettingsBlob(IReadOnlyList<RdpRecord> records, string signScope)
    {
        var text = new StringBuilder();
        foreach (var name in signScope.Split(','))
        {
            if (name.Length == 0)
            {
                continue;
            }

            var record = FindRecord(records, name)
                ?? throw new PsignException($"field '{name}' in SignScope was not found in RDP file");
            text.Append(RecordToLine(record));
        }

        var scope = FindRecord(records, "SignScope")
            ?? throw new PsignException("SignScope field was not found in RDP file");
        text.Append(RecordToLine(scope));
        text.Append('\0');
        return RustText.Utf16LeBytes(text.ToString());
    }

    /// <summary>Parse one line (Rust <c>parse_line</c>), or <c>null</c> when malformed.</summary>
    public static RdpRecord? ParseLine(string line)
    {
        var trimmed = line.TrimStart(' ', '\t');
        if (trimmed.Length == 0)
        {
            return null;
        }

        int colon = trimmed.IndexOf(':');
        if (colon < 0)
        {
            return null;
        }

        var name = trimmed[..colon];
        var rest = trimmed[(colon + 1)..].TrimStart(' ', '\t');
        if (rest.Length == 0)
        {
            return null;
        }

        RdpValueKind kind;
        switch (RustText.ToAsciiLower(rest[0]))
        {
            case 'i':
                kind = RdpValueKind.Integer;
                break;
            case 's':
                kind = RdpValueKind.String;
                break;
            case 'b':
                kind = RdpValueKind.Binary;
                break;
            default:
                return null;
        }

        rest = rest[1..].TrimStart(' ', '\t');
        if (!rest.StartsWith(':'))
        {
            return null;
        }

        var value = rest[1..].TrimStart(' ', '\t');
        return new RdpRecord(name.TrimEnd(' ', '\t'), kind, value.TrimEnd('\r', '\n'));
    }

    /// <summary>Render one record as <c>name:t:value\r\n</c>.</summary>
    public static string RecordToLine(RdpRecord record) => $"{record.Name}:{KindChar(record.Kind)}:{record.Value}\r\n";

    private static char KindChar(RdpValueKind kind) => kind switch
    {
        RdpValueKind.Integer => 'i',
        RdpValueKind.String => 's',
        _ => 'b',
    };

    /// <summary>First record whose name matches ASCII case-insensitively.</summary>
    public static RdpRecord? FindRecord(IEnumerable<RdpRecord> records, string name) =>
        records.FirstOrDefault(r => RustText.EqualsIgnoreAsciiCase(r.Name, name));

    /// <summary>Replace the first record with the same (ASCII case-insensitive) name, or append.</summary>
    public static void InsertOrReplace(List<RdpRecord> records, RdpRecord record)
    {
        int i = records.FindIndex(r => RustText.EqualsIgnoreAsciiCase(r.Name, record.Name));
        if (i >= 0)
        {
            records[i] = record;
        }
        else
        {
            records.Add(record);
        }
    }

    /// <summary>Remove every record with the given (ASCII case-insensitive) name.</summary>
    public static void RemoveRecord(List<RdpRecord> records, string name) =>
        records.RemoveAll(r => RustText.EqualsIgnoreAsciiCase(r.Name, name));
}
