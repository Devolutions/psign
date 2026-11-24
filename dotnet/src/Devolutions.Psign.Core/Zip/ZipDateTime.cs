namespace Devolutions.Psign.Core.Zip;

/// <summary>
/// MS-DOS ZIP timestamp (Rust <c>zip::DateTime</c> 0.6.6). The default value is 1980-01-01 00:00:00, the Rust
/// <c>FileOptions::default()</c> modification time.
/// </summary>
public readonly record struct ZipDateTime
{
    /// <summary>Create a timestamp without validation (Rust <c>DateTime::from_msdos</c> semantics).</summary>
    private ZipDateTime(int year, int month, int day, int hour, int minute, int second)
    {
        Year = year;
        Month = month;
        Day = day;
        Hour = hour;
        Minute = minute;
        Second = second;
    }

    /// <summary>1980-01-01 00:00:00 (Rust <c>zip::DateTime::default()</c>).</summary>
    public static ZipDateTime Default { get; } = new(1980, 1, 1, 0, 0, 0);

    public int Year { get; }

    public int Month { get; }

    public int Day { get; }

    public int Hour { get; }

    public int Minute { get; }

    public int Second { get; }

    /// <summary>Validated constructor (Rust <c>DateTime::from_date_and_time</c>); returns <c>null</c> when out of range.</summary>
    public static ZipDateTime? FromDateAndTime(int year, int month, int day, int hour, int minute, int second)
    {
        if (year >= 1980 && year <= 2107 && month >= 1 && month <= 12 && day >= 1 && day <= DateTime.DaysInMonth(year, month) && hour <= 23 && minute <= 59 && second <= 60
            && hour >= 0 && minute >= 0 && second >= 0)
        {
            return new ZipDateTime(year, month, day, hour, minute, second);
        }

        return null;
    }

    /// <summary>Decode MS-DOS date/time fields (Rust <c>DateTime::from_msdos</c>).</summary>
    public static ZipDateTime FromMsDos(ushort datePart, ushort timePart)
    {
        int seconds = (timePart & 0b0000_0000_0001_1111) << 1;
        int minutes = (timePart & 0b0000_0111_1110_0000) >> 5;
        int hours = (timePart & 0b1111_1000_0000_0000) >> 11;
        int days = datePart & 0b0000_0000_0001_1111;
        int months = (datePart & 0b0000_0001_1110_0000) >> 5;
        int years = (datePart & 0b1111_1110_0000_0000) >> 9;
        return new ZipDateTime(years + 1980, months, days, hours, minutes, seconds);
    }

    /// <summary>MS-DOS date field.</summary>
    public ushort DatePart => (ushort)((Day & 0x1F) | ((Month & 0x0F) << 5) | (Math.Clamp(Year - 1980, 0, 127) << 9));

    /// <summary>MS-DOS time field.</summary>
    public ushort TimePart => (ushort)(((Second >> 1) & 0x1F) | ((Minute & 0x3F) << 5) | ((Hour & 0x1F) << 11));

    /// <summary>Sort key (year, month, day, hour, minute, second).</summary>
    public long SortKey => ((((((long)Year * 100) + Month) * 100 + Day) * 100 + Hour) * 100 + Minute) * 100 + Second;

    /// <summary>
    /// Local wall-clock time as a ZIP timestamp (Rust <c>opc::current_zip_datetime</c>).
    /// </summary>
    public static ZipDateTime FromDateTime(DateTime local)
    {
        int year = local.Year;
        if (year < 1980 || year > 2107)
        {
            throw new PsignException($"local time year {year} is outside the ZIP DOS timestamp range");
        }

        return FromDateAndTime(year, local.Month, local.Day, local.Hour, local.Minute, local.Second)
            ?? throw new PsignException("local time could not be represented as a ZIP DOS timestamp");
    }

    public override string ToString() => $"{Year:D4}-{Month:D2}-{Day:D2} {Hour:D2}:{Minute:D2}:{Second:D2}";
}
