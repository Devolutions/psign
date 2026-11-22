using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Xml;
using Xunit;

namespace Devolutions.Psign.Tests.Core;

public class XmlC14nTests
{
    private static string C14n(string xml, C14nMode mode) =>
        Encoding.UTF8.GetString(XmlC14n.Canonicalize(XmlC14n.ParseDocument(Encoding.UTF8.GetBytes(xml)), mode));

    [Fact]
    public void InclusiveRendersInheritedNamespacesOnApex()
    {
        var doc = XmlC14n.ParseDocument(Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?><a:Root xmlns:a=\"urn:a\" xmlns=\"urn:d\"><Child  z=\"1\" a:y=\"2\" b=\"&amp;&#x9;\"/></a:Root>"));
        var child = doc.ChildElements.First();
        Assert.Equal(
            "<Child xmlns=\"urn:d\" xmlns:a=\"urn:a\" b=\"&amp;&#x9;\" z=\"1\" a:y=\"2\"></Child>",
            Encoding.UTF8.GetString(XmlC14n.Canonicalize(child, C14nMode.Inclusive)));
        Assert.Equal(
            "<Child xmlns=\"urn:d\" xmlns:a=\"urn:a\" b=\"&amp;&#x9;\" z=\"1\" a:y=\"2\"></Child>",
            Encoding.UTF8.GetString(XmlC14n.Canonicalize(child, C14nMode.Exclusive)));
    }

    [Fact]
    public void ExclusiveOmitsUnusedNamespaces()
    {
        Assert.Equal("<r><u:x xmlns:u=\"urn:u\"></u:x></r>", C14n("<r xmlns:u=\"urn:u\" xmlns:v=\"urn:v\"><u:x/></r>", C14nMode.Exclusive));
        Assert.Equal("<r xmlns:u=\"urn:u\" xmlns:v=\"urn:v\"><u:x></u:x></r>", C14n("<r xmlns:u=\"urn:u\" xmlns:v=\"urn:v\"><u:x/></r>", C14nMode.Inclusive));
    }

    [Fact]
    public void TextAndLineEndingsAreNormalized()
    {
        Assert.Equal("<r>a\nb &lt; &gt; &#xD;</r>", C14n("<r>a\r\nb &lt; &gt; &#xD;</r>", C14nMode.Inclusive));
    }

    [Fact]
    public void RejectsDoctype()
    {
        Assert.Throws<PsignException>(() => XmlC14n.ParseDocument(Encoding.UTF8.GetBytes("<!DOCTYPE r [<!ENTITY e \"x\">]><r>&e;</r>")));
    }

    [Theory]
    [InlineData("<r><?pi x?></r>", "processing instructions")]
    [InlineData("<r/><s/>", "more than one document element")]
    [InlineData("<r>", "truncated")]
    [InlineData("x<r/>", "outside the document element")]
    [InlineData("<r>&unknown;</r>", "undefined XML entity")]
    [InlineData("", "no document element")]
    public void RejectsMalformedInput(string xml, string expected)
    {
        var e = Assert.Throws<PsignException>(() => XmlC14n.ParseDocument(Encoding.UTF8.GetBytes(xml)));
        Assert.Contains(expected, e.Message);
    }

    [Fact]
    public void AttributeValuesAreNormalizedBeforeUnescaping()
    {
        Assert.Equal("<r a=\"x y z&#x9;\"></r>", C14n("<r a=\"x\ty\r\nz&#9;\"/>", C14nMode.Inclusive));
        Assert.Equal("<r>a&lt;b</r>", C14n("<r><![CDATA[a<b]]></r>", C14nMode.Inclusive));
    }

    [Fact]
    public void DomHelpersResolveNamespaces()
    {
        var doc = XmlC14n.ParseDocument(Encoding.UTF8.GetBytes("﻿<?xml version=\"1.0\"?><!-- c --><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo Id=\"x\">t<ds:Reference/>u</ds:SignedInfo></ds:Signature>"));
        Assert.True(doc.Is("http://www.w3.org/2000/09/xmldsig#", "Signature"));
        var si = doc.Child("http://www.w3.org/2000/09/xmldsig#", "SignedInfo")!;
        Assert.Equal("x", si.Attr("Id"));
        Assert.Equal("tu", si.Text());
        var found = new List<XmlC14nElement>();
        doc.FindAll(e => e.LocalName == "Reference", found);
        Assert.Single(found);
        Assert.Equal(XmlC14nMode("http://www.w3.org/2001/10/xml-exc-c14n#"), C14nMode.Exclusive);
    }

    private static C14nMode? XmlC14nMode(string uri) => XmlC14n.ModeFromUri(uri);

    [Fact]
    public void CanonicalizesVsixSignatureObjectLikeTheTemplate()
    {
        // The VSIX template writes Object/SignedInfo directly in canonical form; canonicalizing the embedded document
        // form must reproduce the exact octets that were digested.
        var zip = PackageTestUtil.ZipWith(
            ("[Content_Types].xml", PackageTestUtil.B("<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"txt\" ContentType=\"text/plain\"/></Types>")),
            ("a.txt", PackageTestUtil.B("a")));
        var template = Devolutions.Psign.Core.Vsix.VsixPackage.SignatureTemplate(zip, Devolutions.Psign.Core.Vsix.VsixHashAlgorithm.Sha256, Devolutions.Psign.Core.Vsix.VsixSigningTime.FromPackage);
        var xml = template.SignatureXmlBytes([1], null);
        var doc = XmlC14n.ParseDocument(xml);
        var signedInfo = doc.Child("http://www.w3.org/2000/09/xmldsig#", "SignedInfo")!;
        Assert.Equal(template.SignedInfo, XmlC14n.Canonicalize(signedInfo, C14nMode.Inclusive));
    }
}
