using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Signing.Cms;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

public class Pkcs7BuilderParityTests
{
    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("sha384")]
    [InlineData("sha512")]
    public void PeSignatureMatchesRustByteForByte(string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var unsigned = Fixtures.Path("generated-unsigned/pe/" + Directory.GetFiles(Fixtures.Path("generated-unsigned/pe")).Select(Path.GetFileName).First(f => f!.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)));
        var rustOut = dir.File("rust.exe");
        RustTool.RunOk("portable", "sign-pe", "--cert", signer.CertPath, "--key", signer.KeyPath, "--digest", digest, "--output", rustOut, unsigned);

        var kind = AuthenticodeHashKinds.Parse(digest);
        var image = PeEmbed.PrepareForAuthenticodeSigning(File.ReadAllBytes(unsigned));
        var indirect = SpcIndirectDataContent.ForPe(kind, PeAuthenticode.Digest(image, kind));
        var pkcs7 = Pkcs7Builder.CreateAuthenticode(indirect, kind, signer.Info, [], signer.Key);
        var signed = PeEmbed.AppendPkcs7Certificate(image, pkcs7);

        Assert.Equal(File.ReadAllBytes(rustOut), signed);
    }
}
