using Devolutions.Psign.Core;
using Devolutions.Psign.Core.AppInstaller;
using Devolutions.Psign.Core.BusinessCentral;
using Xunit;

namespace Devolutions.Psign.Tests.Core;

public class AppInstallerDescriptorTests
{
    private static string Sample => AppInstallerDescriptor.ReadText(Fixtures.Path("generated-unsigned/appinstaller/sample.appinstaller"));

    [Fact]
    public void InfoReportsDescriptor()
    {
        var info = AppInstallerDescriptor.Parse(Sample);
        Assert.Equal("AppInstaller", info.Root);
        Assert.Equal("http://schemas.microsoft.com/appx/appinstaller/2018", info.Namespace);
        Assert.True(info.HasMainPackage);
        Assert.False(info.HasMainBundle);
        Assert.Equal("CN=Test Code Signing Certificate", info.Publisher);
    }

    [Fact]
    public void SetPublisherUpdatesDescriptorMetadata()
    {
        string publisher = "CN=Updated Publisher, O=Example & Co";
        string xml = AppInstallerDescriptor.UpdatePublisher(Sample, publisher);
        Assert.Contains("Publisher=\"CN=Updated Publisher, O=Example &amp; Co\"", xml);
        Assert.Equal(publisher, AppInstallerDescriptor.Parse(xml).Publisher);
    }

    [Fact]
    public void SetPublisherUpdatesPrefixedMainPackage()
    {
        string descriptor = "<AppInstaller xmlns=\"http://schemas.microsoft.com/appx/appinstaller/2021\" xmlns:pkg=\"urn:example\" Version=\"1.0.0.0\" Uri=\"https://example.invalid/app.appinstaller\"><pkg:MainPackage Name=\"Example.App\" Publisher=\"CN=Old\" Version=\"1.0.0.0\" ProcessorArchitecture=\"x64\" Uri=\"https://example.invalid/app.msix\"/></AppInstaller>";
        string xml = AppInstallerDescriptor.UpdatePublisher(descriptor, "CN=Updated Publisher");
        Assert.Contains("<pkg:MainPackage", xml);
        Assert.Contains("Publisher=\"CN=Updated Publisher\"", xml);
        var info = AppInstallerDescriptor.Parse(xml);
        Assert.True(info.HasMainPackage);
        Assert.Equal("CN=Updated Publisher", info.Publisher);
    }

    [Fact]
    public void SetPublisherRejectsInvalidInput()
    {
        Assert.Contains("cannot be empty", Assert.Throws<PsignException>(() => AppInstallerDescriptor.UpdatePublisher(Sample, "")).Message);
        Assert.Contains("does not contain MainPackage", Assert.Throws<PsignException>(() => AppInstallerDescriptor.UpdatePublisher("<AppInstaller></AppInstaller>", "CN=x")).Message);
        Assert.Contains("not found", Assert.Throws<PsignException>(() => AppInstallerDescriptor.Parse("<Other/>")).Message);
    }

    [Fact]
    public void SetPublisherInsertsMissingAttributeOnBundle()
    {
        string xml = AppInstallerDescriptor.UpdatePublisher("<AppInstaller><MainBundle Name=\"x\" /></AppInstaller>", "CN=New");
        Assert.Equal("<AppInstaller><MainBundle Name=\"x\"  Publisher=\"CN=New\"/></AppInstaller>", xml);
    }

    [Fact]
    public void BusinessCentralAppInfoDetectsNavxHeader()
    {
        var valid = BusinessCentralApp.Inspect("NAVX\0fixture"u8);
        Assert.True(valid.IsNavx);
        Assert.Equal("NAVX", valid.Header);
        var invalid = BusinessCentralApp.Inspect("not-navx"u8);
        Assert.False(invalid.IsNavx);
        Assert.Equal("-", invalid.Header);
        Assert.Equal(8ul, invalid.Len);
    }

    // ---------------------------------------------------------------- differential vs Rust

    [SkippableFact]
    public void InfoAndSetPublisherMatchRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        foreach (var rel in new[] { "generated-unsigned/appinstaller/sample.appinstaller", "msix-edge-cases/unsigned/bundle-bom.appinstaller" })
        {
            var path = Fixtures.Path(rel);
            var info = AppInstallerDescriptor.Parse(AppInstallerDescriptor.ReadText(path));
            string expected = $"root={info.Root}\nnamespace={info.Namespace ?? "-"}\nmain_package={(info.HasMainPackage ? "yes" : "no")}\nmain_bundle={(info.HasMainBundle ? "yes" : "no")}\npublisher={info.Publisher ?? "-"}\ncompanion_signature=-\ncompanion_signature_len=-\n";
            Assert.Equal(expected, RustTool.RunOk("portable", "appinstaller-info", path).Replace("\r\n", "\n"));

            var rustOut = dir.File("rust.appinstaller");
            RustTool.RunOk("portable", "appinstaller-set-publisher", path, "--publisher", "CN=Updated <Publisher>, O=\"A&B\"", "--output", rustOut);
            Assert.Equal(
                File.ReadAllBytes(rustOut),
                System.Text.Encoding.UTF8.GetBytes(AppInstallerDescriptor.UpdatePublisher(AppInstallerDescriptor.ReadText(path), "CN=Updated <Publisher>, O=\"A&B\"")));
        }
    }

    [SkippableFact]
    public void BusinessCentralInfoMatchesRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var path = dir.File("valid.app");
        File.WriteAllBytes(path, "NAVX\0fixture"u8.ToArray());
        var info = BusinessCentralApp.InspectPath(path);
        string expected = $"business_central_app={(info.IsNavx ? "yes" : "no")}\nheader={info.Header}\nlen={info.Len}\n";
        Assert.Equal(expected, RustTool.RunOk("portable", "business-central-app-info", path).Replace("\r\n", "\n"));
    }
}
