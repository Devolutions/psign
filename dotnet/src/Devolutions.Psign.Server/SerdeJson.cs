using System.Globalization;
using System.Text;
using Devolutions.Psign.Core;

namespace Devolutions.Psign.Server;

/// <summary>
/// <c>serde_json::from_slice::&lt;Value&gt;</c> emulation for the request bodies psign-server reads: the same grammar
/// (strict JSON, recursion limit 128, paired surrogate escapes, UTF-8 validated strings), duplicate keys resolved last
/// wins, and the same error messages with <c>at line L column C</c> positions.
/// </summary>
internal sealed class SerdeJson
{
    private readonly byte[] _s;
    private int _index;
    private int _remainingDepth = 128;

    private SerdeJson(byte[] s) => _s = s;

    /// <summary>Parse a JSON document; objects become <see cref="Dictionary{TKey,TValue}"/>, strings <see cref="string"/>.</summary>
    public static object? Parse(byte[] input)
    {
        var p = new SerdeJson(input);
        var value = p.ParseValue();
        if (p.ParseWhitespace() is not null)
        {
            throw p.PeekError("trailing characters");
        }

        return value;
    }

    /// <summary><c>value.get(key).and_then(Value::as_str)</c>.</summary>
    public static string? GetString(object? value, string key) =>
        value is Dictionary<string, object?> map && map.TryGetValue(key, out var v) ? v as string : null;

    private sealed class Number;

    private sealed class Null;

    private int? Peek() => _index < _s.Length ? _s[_index] : null;

    private int? ParseWhitespace()
    {
        while (_index < _s.Length)
        {
            switch (_s[_index])
            {
                case (byte)' ':
                case (byte)'\n':
                case (byte)'\t':
                case (byte)'\r':
                    _index++;
                    break;
                default:
                    return _s[_index];
            }
        }

        return null;
    }

    private (int Line, int Column) PositionOf(int i)
    {
        int startOfLine = 0;
        int line = 1;
        for (int k = 0; k < i; k++)
        {
            if (_s[k] == '\n')
            {
                startOfLine = k + 1;
                line++;
            }
        }

        return (line, i - startOfLine);
    }

    private PsignException Error(string code)
    {
        var (line, col) = PositionOf(_index);
        return new PsignException($"{code} at line {line} column {col}");
    }

    private PsignException PeekError(string code)
    {
        var (line, col) = PositionOf(Math.Min(_s.Length, _index + 1));
        return new PsignException($"{code} at line {line} column {col}");
    }

    private object? ParseValue()
    {
        var peek = ParseWhitespace() ?? throw PeekError("EOF while parsing a value");
        switch (peek)
        {
            case 'n':
                _index++;
                ParseIdent("ull");
                return new Null();
            case 't':
                _index++;
                ParseIdent("rue");
                return true;
            case 'f':
                _index++;
                ParseIdent("alse");
                return false;
            case '-':
                _index++;
                ParseInteger();
                return new Number();
            case >= '0' and <= '9':
                ParseInteger();
                return new Number();
            case '"':
                _index++;
                return ParseStr();
            case '[':
                return ParseSeq();
            case '{':
                return ParseMap();
            default:
                throw PeekError("expected value");
        }
    }

    private void ParseIdent(string ident)
    {
        foreach (var expected in ident)
        {
            if (_index >= _s.Length)
            {
                throw Error("EOF while parsing a value");
            }

            if (_s[_index++] != expected)
            {
                throw Error("expected ident");
            }
        }
    }

    private void EnterNested()
    {
        _remainingDepth--;
        if (_remainingDepth == 0)
        {
            throw PeekError("recursion limit exceeded");
        }
    }

    private List<object?> ParseSeq()
    {
        EnterNested();
        _index++;
        var list = new List<object?>();
        bool first = true;
        while (true)
        {
            var peek = ParseWhitespace() ?? throw PeekError("EOF while parsing a list");
            if (peek == ']')
            {
                break;
            }

            if (first)
            {
                first = false;
            }
            else if (peek == ',')
            {
                _index++;
                var next = ParseWhitespace();
                if (next == ']')
                {
                    throw PeekError("trailing comma");
                }

                if (next is null)
                {
                    throw PeekError("EOF while parsing a value");
                }
            }
            else
            {
                throw PeekError("expected `,` or `]`");
            }

            list.Add(ParseValue());
        }

        _remainingDepth++;
        // end_seq
        _index++;
        return list;
    }

    private Dictionary<string, object?> ParseMap()
    {
        EnterNested();
        _index++;
        var map = new Dictionary<string, object?>(StringComparer.Ordinal);
        bool first = true;
        while (true)
        {
            var peek = ParseWhitespace() ?? throw PeekError("EOF while parsing an object");
            if (peek == '}')
            {
                break;
            }

            if (first)
            {
                first = false;
                if (peek != '"')
                {
                    throw PeekError("key must be a string");
                }
            }
            else if (peek == ',')
            {
                _index++;
                var next = ParseWhitespace();
                if (next == '}')
                {
                    throw PeekError("trailing comma");
                }

                if (next is null)
                {
                    throw PeekError("EOF while parsing a value");
                }

                if (next != '"')
                {
                    throw PeekError("key must be a string");
                }
            }
            else
            {
                throw PeekError("expected `,` or `}`");
            }

            _index++;
            var key = ParseStr();
            var colon = ParseWhitespace();
            if (colon == ':')
            {
                _index++;
            }
            else if (colon is null)
            {
                throw PeekError("EOF while parsing an object");
            }
            else
            {
                throw PeekError("expected `:`");
            }

            map[key] = ParseValue();
        }

        _remainingDepth++;
        _index++;
        return map;
    }

    private void ParseInteger()
    {
        if (_index >= _s.Length)
        {
            throw Error("EOF while parsing a value");
        }

        int start = _index - (_index > 0 && _s[_index - 1] == '-' ? 1 : 0);
        byte next = _s[_index++];
        if (next == '0')
        {
            if (Peek() is >= '0' and <= '9')
            {
                throw PeekError("invalid number");
            }
        }
        else if (next is >= (byte)'1' and <= (byte)'9')
        {
            while (Peek() is >= '0' and <= '9')
            {
                _index++;
            }
        }
        else
        {
            throw Error("invalid number");
        }

        bool isFloat = false;
        if (Peek() == '.')
        {
            isFloat = true;
            _index++;
            int digits = 0;
            while (Peek() is >= '0' and <= '9')
            {
                _index++;
                digits++;
            }

            if (digits == 0)
            {
                throw Peek() is null ? PeekError("EOF while parsing a value") : PeekError("invalid number");
            }
        }

        if (Peek() is 'e' or 'E')
        {
            isFloat = true;
            _index++;
            if (Peek() is '+' or '-')
            {
                _index++;
            }

            if (_index >= _s.Length)
            {
                throw Error("EOF while parsing a value");
            }

            if (_s[_index++] is < (byte)'0' or > (byte)'9')
            {
                throw Error("invalid number");
            }

            while (Peek() is >= '0' and <= '9')
            {
                _index++;
            }
        }

        // Integers that overflow u64 / i64 and every float go through f64; infinite results are out of range.
        if (isFloat || _index - start > 18)
        {
            var text = Encoding.ASCII.GetString(_s, start, _index - start);
            if (double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && double.IsInfinity(d))
            {
                throw Error("number out of range");
            }
        }
    }

    private string ParseStr()
    {
        var scratch = new List<byte>();
        int start = _index;
        while (true)
        {
            while (_index < _s.Length && _s[_index] != '"' && _s[_index] != '\\' && _s[_index] >= 0x20)
            {
                _index++;
            }

            if (_index == _s.Length)
            {
                throw Error("EOF while parsing a string");
            }

            switch (_s[_index])
            {
                case (byte)'"':
                    scratch.AddRange(_s.AsSpan(start, _index - start));
                    _index++;
                    return AsStr(scratch.ToArray());
                case (byte)'\\':
                    scratch.AddRange(_s.AsSpan(start, _index - start));
                    _index++;
                    ParseEscape(scratch);
                    start = _index;
                    break;
                default:
                    _index++;
                    throw Error("control character (\\u0000-\\u001F) found while parsing a string");
            }
        }
    }

    private string AsStr(byte[] bytes)
    {
        try
        {
            return new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            throw Error("invalid unicode code point");
        }
    }

    private byte NextOrEof()
    {
        if (_index >= _s.Length)
        {
            throw Error("EOF while parsing a string");
        }

        return _s[_index++];
    }

    private void ParseEscape(List<byte> scratch)
    {
        byte ch = NextOrEof();
        switch (ch)
        {
            case (byte)'"': scratch.Add((byte)'"'); break;
            case (byte)'\\': scratch.Add((byte)'\\'); break;
            case (byte)'/': scratch.Add((byte)'/'); break;
            case (byte)'b': scratch.Add(0x08); break;
            case (byte)'f': scratch.Add(0x0c); break;
            case (byte)'n': scratch.Add((byte)'\n'); break;
            case (byte)'r': scratch.Add((byte)'\r'); break;
            case (byte)'t': scratch.Add((byte)'\t'); break;
            case (byte)'u': ParseUnicodeEscape(scratch); break;
            default: throw Error("invalid escape");
        }
    }

    private int DecodeHexEscape()
    {
        if (_s.Length - _index < 4)
        {
            _index = _s.Length;
            throw Error("EOF while parsing a string");
        }

        int v = 0;
        bool ok = true;
        for (int k = 0; k < 4; k++)
        {
            int d = HexVal(_s[_index + k]);
            ok &= d >= 0;
            v = (v << 4) | (d & 0xf);
        }

        _index += 4;
        if (!ok)
        {
            throw Error("invalid escape");
        }

        return v;
    }

    private static int HexVal(byte b) => b switch
    {
        >= (byte)'0' and <= (byte)'9' => b - '0',
        >= (byte)'a' and <= (byte)'f' => b - 'a' + 10,
        >= (byte)'A' and <= (byte)'F' => b - 'A' + 10,
        _ => -1,
    };

    private void ParseUnicodeEscape(List<byte> scratch)
    {
        int n = DecodeHexEscape();
        if (n is >= 0xDC00 and <= 0xDFFF)
        {
            throw Error("lone leading surrogate in hex escape");
        }

        if (n is < 0xD800 or > 0xDBFF)
        {
            PushCodepoint(n, scratch);
            return;
        }

        if (_index >= _s.Length)
        {
            throw Error("EOF while parsing a string");
        }

        if (_s[_index] != '\\')
        {
            _index++;
            throw Error("unexpected end of hex escape");
        }

        _index++;
        if (_index >= _s.Length)
        {
            throw Error("EOF while parsing a string");
        }

        if (_s[_index] != 'u')
        {
            _index++;
            throw Error("unexpected end of hex escape");
        }

        _index++;
        int n2 = DecodeHexEscape();
        if (n2 is < 0xDC00 or > 0xDFFF)
        {
            throw Error("lone leading surrogate in hex escape");
        }

        PushCodepoint((((n - 0xD800) << 10) | (n2 - 0xDC00)) + 0x10000, scratch);
    }

    private static void PushCodepoint(int cp, List<byte> scratch) =>
        scratch.AddRange(Encoding.UTF8.GetBytes(char.ConvertFromUtf32(cp)));
}
