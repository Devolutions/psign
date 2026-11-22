using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Zip;
using Devolutions.Psign.Signing.Code;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>Port of the unit tests in Rust <c>src/code.rs</c> plus pattern / path helper coverage.</summary>
public class CodePatternsTests
{
    [Fact]
    public void BraceExpansionSupportsNestedListsAndRanges()
    {
        Assert.Equal(
            [
                "lib/net6.0/file01.dll",
                "lib/net6.0/file02.dll",
                "lib/net8.0/file01.dll",
                "lib/net8.0/file02.dll",
                "lib/tools/file01.dll",
                "lib/tools/file02.dll",
            ],
            CodePatterns.ExpandBraces("lib/{net{6,8}.0,tools}/file{01..02}.dll"));
    }

    [Fact]
    public void BraceRangesCountDownAndPadWithSign()
    {
        Assert.Equal(["3", "2", "1"], CodePatterns.ExpandBraces("{3..1}"));
        Assert.Equal(["-01", "000", "001"], CodePatterns.ExpandBraces("{-01..1}"));
        Assert.Equal(["a..b"], CodePatterns.ExpandBraces("{a..b}"));
    }

    [Fact]
    public void UnmatchedBracesAreRejected()
    {
        Assert.Equal("unmatched opening brace in pattern: a{b", Assert.Throws<PsignException>(() => CodePatterns.ExpandBraces("a{b")).Message);
        Assert.Equal("unmatched closing brace in pattern: a}b", Assert.Throws<PsignException>(() => CodePatterns.ExpandBraces("a}b")).Message);
    }

    [Fact]
    public void GlobstarCrossesDirectoriesButStarDoesNot()
    {
        Assert.True(CodePatterns.GlobMatch("**/*.dll", "lib/net8.0/a.dll"));
        Assert.True(CodePatterns.GlobMatch("**/*.dll", "a.dll"));
        Assert.False(CodePatterns.GlobMatch("*.dll", "lib/net8.0/a.dll"));
        Assert.True(CodePatterns.GlobMatch("lib/net?.0/*.dll", "lib/net8.0/a.dll"));
        Assert.True(CodePatterns.GlobMatch("LIB/*.DLL", "lib/a.dll"));
        Assert.False(CodePatterns.GlobMatch("lib/?", "lib/ab"));
    }

    [Fact]
    public void RejectsTraversalPatterns()
    {
        Assert.Throws<PsignException>(() => CodePatterns.PatternRules("../secret.dll"));
        Assert.Throws<PsignException>(() => CodePatterns.PatternRules("safe/../../secret.dll"));
        Assert.Equal("empty pattern", Assert.Throws<PsignException>(() => CodePatterns.PatternRules("!")).Message);
        Assert.Equal("trailing escape", Assert.Throws<PsignException>(() => CodePatterns.PatternRules("a\\")).Message);
    }

    [Fact]
    public void NegationAndEscapedBang()
    {
        var exclude = Assert.Single(CodePatterns.PatternRules("!lib/a.dll"));
        Assert.False(exclude.Include);
        Assert.Equal("lib/a.dll", exclude.Pattern);
        var literal = Assert.Single(CodePatterns.PatternRules("\\!bang.dll"));
        Assert.True(literal.Include);
        Assert.Equal("!bang.dll", literal.Pattern);
    }

    [Fact]
    public void FormatDetectionAndSignerFamilies()
    {
        Assert.Equal(CodeFormat.Pe, CodeFormats.Detect("a/b/App.EXE"));
        Assert.Equal(CodeFormat.Winmd, CodeFormats.Detect("x.winmd"));
        Assert.Equal(CodeFormat.EncryptedMsix, CodeFormats.Detect("x.emsixbundle"));
        Assert.Equal(CodeFormat.Unknown, CodeFormats.Detect(".nupkg"));
        Assert.Equal(CodeFormat.Unknown, CodeFormats.Detect("plain.app"));
        Assert.Equal(CodeFormat.BusinessCentralApp, CodeFormats.Detect("plain.app", "NAVX\0"u8, true));
        Assert.Equal(CodeFormat.Pe, CodeFormats.Detect("outer.vsix!lib/net8.0/a.dll"));
        Assert.Equal("click-once-application", CodeFormat.ClickOnceApplication.KebabName());
        Assert.Equal("msix-bundle", CodeFormat.MsixBundle.KebabName());
        Assert.Equal("clickonce-manifest", CodeFormat.Deploy.SignerName());
        Assert.Equal("container-only", CodeFormat.Zip.SignerName());
        Assert.True(CodeFormat.AppxUpload.IsContainer());
        Assert.False(CodeFormat.EncryptedMsix.IsContainer());
    }

    [Fact]
    public void RepackZipReplacesAndAppendsEntries()
    {
        var input = TestZip(("lib/net8.0/a.dll", "old"u8.ToArray(), null), ("content/readme.txt", "text"u8.ToArray(), null));
        var output = CodeZip.RepackWithUpdates(
            input,
            [
                new ZipEntryUpdate("lib/net8.0/a.dll", "new"u8.ToArray(), ZipCrateWriter.Deflated),
                new ZipEntryUpdate(".signature.p7s", "cms"u8.ToArray(), ZipCrateWriter.Stored),
            ]);
        var archive = ZipCrateArchive.Open(output);
        Assert.Equal("new"u8.ToArray(), archive.Read(archive.RequireByName("lib/net8.0/a.dll")));
        Assert.Equal("cms"u8.ToArray(), archive.Read(archive.RequireByName(".signature.p7s")));
        Assert.Equal(ZipCrateWriter.Stored, archive.RequireByName(".signature.p7s").CompressionMethod);
    }

    [Fact]
    public void RepackZipPreservesUnchangedEntryTimestampsAndStampsUpdates()
    {
        var originalA = ZipDateTime.FromDateAndTime(2001, 2, 3, 4, 5, 6)!.Value;
        var originalReadme = ZipDateTime.FromDateAndTime(2002, 3, 4, 5, 6, 8)!.Value;
        var input = TestZip(("lib/net8.0/a.dll", "old"u8.ToArray(), originalA), ("content/readme.txt", "text"u8.ToArray(), originalReadme));
        var output = CodeZip.RepackWithUpdates(
            input,
            [
                new ZipEntryUpdate("lib/net8.0/a.dll", "new"u8.ToArray(), ZipCrateWriter.Deflated),
                new ZipEntryUpdate(".signature.p7s", "cms"u8.ToArray(), ZipCrateWriter.Stored),
            ]);
        var archive = ZipCrateArchive.Open(output);
        Assert.Equal(originalReadme, archive.RequireByName("content/readme.txt").LastModified);
        var updated = archive.RequireByName("lib/net8.0/a.dll").LastModified;
        Assert.NotEqual(originalA, updated);
        Assert.NotEqual(ZipDateTime.Default, updated);
        Assert.NotEqual(ZipDateTime.Default, archive.RequireByName(".signature.p7s").LastModified);
    }

    [Fact]
    public void RepackZipRejectsUnsafeUpdatePath()
    {
        var input = TestZip(("file.txt", "text"u8.ToArray(), null));
        var err = Assert.Throws<PsignException>(() => CodeZip.RepackWithUpdates(input, [new ZipEntryUpdate("../evil.txt", "evil"u8.ToArray(), ZipCrateWriter.Deflated)]));
        Assert.Contains("unsafe ZIP entry path", err.Message);
    }

    [Fact]
    public void RepackZipRejectsDuplicateUpdates()
    {
        var input = TestZip(("file.txt", "text"u8.ToArray(), null));
        var err = Assert.Throws<PsignException>(() => CodeZip.RepackWithUpdates(
            input,
            [new ZipEntryUpdate("a", [1], ZipCrateWriter.Stored), new ZipEntryUpdate("a", [2], ZipCrateWriter.Stored)]));
        Assert.Equal("duplicate ZIP update entry: a", err.Message);
    }

    [Fact]
    public void RepackZipAppendsPendingUpdatesInNameOrder()
    {
        var input = TestZip(("file.txt", "text"u8.ToArray(), null));
        var output = CodeZip.RepackWithUpdates(
            input,
            [new ZipEntryUpdate("z.txt", [1], ZipCrateWriter.Stored), new ZipEntryUpdate("b.txt", [2], ZipCrateWriter.Stored)]);
        Assert.Equal(["file.txt", "b.txt", "z.txt"], ZipCrateArchive.Open(output).Entries.Select(e => e.Name));
    }

    private static byte[] TestZip(params (string Name, byte[] Data, ZipDateTime? Modified)[] entries)
    {
        var writer = new ZipCrateWriter();
        foreach (var (name, data, modified) in entries)
        {
            writer.StartFile(name, data, ZipCrateWriter.Deflated, modified);
        }

        return writer.Finish();
    }
}
