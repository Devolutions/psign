//! Minimal XML DOM + Canonical XML 1.0 (inclusive and exclusive, without comments) for XMLDSig.
//!
//! Scope: the signature parts and OPC relationship parts of signed packages (VSIX). DOCTYPE and
//! processing instructions inside the document element are rejected, so no DTD-defined defaults or
//! entities can influence canonicalization. Line endings and attribute values are normalized as an
//! XML 1.0 processor would before canonicalization.

use anyhow::{Context, Result, anyhow};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use std::collections::BTreeMap;

const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// Namespace prefix → URI (`""` is the default namespace).
pub(crate) type NsScope = BTreeMap<String, String>;

#[derive(Debug, Clone)]
pub(crate) struct Element {
    /// Qualified name as written (`prefix:local` or `local`).
    pub qname: String,
    /// Attributes as written, including `xmlns` declarations; values are normalized + unescaped.
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Node>,
    /// Namespaces in scope at this element (inherited + declared here).
    pub scope: NsScope,
}

#[derive(Debug, Clone)]
pub(crate) enum Node {
    Element(Element),
    Text(String),
}

fn split_qname(qname: &str) -> (&str, &str) {
    qname.split_once(':').unwrap_or(("", qname))
}

impl Element {
    pub fn local_name(&self) -> &str {
        split_qname(&self.qname).1
    }

    pub fn namespace(&self) -> &str {
        let prefix = split_qname(&self.qname).0;
        self.scope.get(prefix).map(String::as_str).unwrap_or("")
    }

    pub fn is(&self, ns: &str, local: &str) -> bool {
        self.local_name() == local && self.namespace() == ns
    }

    /// Unprefixed attribute value.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn child_elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            Node::Text(_) => None,
        })
    }

    pub fn child(&self, ns: &str, local: &str) -> Option<&Element> {
        self.child_elements().find(|e| e.is(ns, local))
    }

    pub fn children_named<'a>(
        &'a self,
        ns: &'a str,
        local: &'a str,
    ) -> impl Iterator<Item = &'a Element> + 'a {
        self.child_elements().filter(move |e| e.is(ns, local))
    }

    /// Concatenated text content of direct text children.
    pub fn text(&self) -> String {
        self.children
            .iter()
            .filter_map(|n| match n {
                Node::Text(t) => Some(t.as_str()),
                Node::Element(_) => None,
            })
            .collect()
    }

    /// Depth-first search including `self`.
    pub fn find_all<'a>(&'a self, pred: &dyn Fn(&Element) -> bool, out: &mut Vec<&'a Element>) {
        if pred(self) {
            out.push(self);
        }
        for child in self.child_elements() {
            child.find_all(pred, out);
        }
    }
}

fn normalize_newlines(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

fn start_element(e: &BytesStart<'_>, parent_scope: &NsScope) -> Result<Element> {
    let qname = std::str::from_utf8(e.name().as_ref())
        .context("XML element name is not UTF-8")?
        .to_string();
    let mut attrs = Vec::new();
    let mut scope = parent_scope.clone();
    for attr in e.attributes() {
        let attr = attr.map_err(|e| anyhow!("XML attribute: {e}"))?;
        let key = std::str::from_utf8(attr.key.as_ref())
            .context("XML attribute name is not UTF-8")?
            .to_string();
        let raw = std::str::from_utf8(&attr.value).context("XML attribute value is not UTF-8")?;
        // Attribute-value normalization: literal whitespace characters become spaces.
        let normalized = normalize_newlines(raw).replace(['\t', '\n'], " ");
        let value = quick_xml::escape::unescape(&normalized)
            .map_err(|e| anyhow!("XML attribute {key} value: {e}"))?
            .into_owned();
        if key == "xmlns" {
            scope.insert(String::new(), value.clone());
        } else if let Some(prefix) = key.strip_prefix("xmlns:") {
            scope.insert(prefix.to_string(), value.clone());
        }
        attrs.push((key, value));
    }
    scope.insert("xml".to_string(), XML_NS.to_string());
    Ok(Element {
        qname,
        attrs,
        children: Vec::new(),
        scope,
    })
}

fn push_text(stack: &mut [Element], text: &str) -> Result<()> {
    let Some(top) = stack.last_mut() else {
        if text.trim().is_empty() {
            return Ok(());
        }
        return Err(anyhow!("XML text outside the document element"));
    };
    if let Some(Node::Text(last)) = top.children.last_mut() {
        last.push_str(text);
    } else {
        top.children.push(Node::Text(text.to_string()));
    }
    Ok(())
}

/// Parse a UTF-8 XML document (optional BOM) into its document element.
pub(crate) fn parse_document(xml: &[u8]) -> Result<Element> {
    let xml = xml.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(xml);
    let text = std::str::from_utf8(xml).context("XML document is not UTF-8")?;
    let mut reader = Reader::from_str(text);
    reader.config_mut().expand_empty_elements = true;
    let mut stack: Vec<Element> = Vec::new();
    let mut root = None;
    loop {
        match reader
            .read_event()
            .map_err(|e| anyhow!("XML parse error at {}: {e}", reader.buffer_position()))?
        {
            Event::Start(e) => {
                if root.is_some() {
                    return Err(anyhow!("XML has more than one document element"));
                }
                let scope = stack.last().map(|p| p.scope.clone()).unwrap_or_default();
                stack.push(start_element(&e, &scope)?);
            }
            Event::End(_) => {
                let done = stack
                    .pop()
                    .ok_or_else(|| anyhow!("unbalanced XML end tag"))?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(Node::Element(done)),
                    None => root = Some(done),
                }
            }
            Event::Text(t) => {
                let raw = t.decode().map_err(|e| anyhow!("XML text: {e}"))?;
                push_text(&mut stack, &normalize_newlines(&raw))?;
            }
            Event::CData(c) => {
                let raw = c.decode().map_err(|e| anyhow!("XML CDATA: {e}"))?;
                push_text(&mut stack, &normalize_newlines(&raw))?;
            }
            Event::GeneralRef(r) => {
                let resolved = if r.is_char_ref() {
                    r.resolve_char_ref()
                        .map_err(|e| anyhow!("XML character reference: {e}"))?
                        .ok_or_else(|| anyhow!("invalid XML character reference"))?
                        .to_string()
                } else {
                    match r.decode().map_err(|e| anyhow!("XML entity: {e}"))?.as_ref() {
                        "amp" => "&".into(),
                        "lt" => "<".into(),
                        "gt" => ">".into(),
                        "quot" => "\"".into(),
                        "apos" => "'".into(),
                        other => return Err(anyhow!("undefined XML entity &{other};")),
                    }
                };
                push_text(&mut stack, &resolved)?;
            }
            Event::Comment(_) | Event::Decl(_) => {}
            Event::PI(_) if stack.is_empty() => {}
            Event::PI(_) => return Err(anyhow!("XML processing instructions are not supported")),
            Event::DocType(_) => return Err(anyhow!("XML DOCTYPE is not allowed")),
            Event::Empty(_) => unreachable!("expand_empty_elements is enabled"),
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return Err(anyhow!("XML document is truncated"));
    }
    root.ok_or_else(|| anyhow!("XML document has no document element"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum C14nMode {
    /// `http://www.w3.org/TR/2001/REC-xml-c14n-20010315`
    Inclusive,
    /// `http://www.w3.org/2001/10/xml-exc-c14n#` (no `InclusiveNamespaces` prefix list).
    Exclusive,
}

impl C14nMode {
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" => Some(Self::Inclusive),
            "http://www.w3.org/2001/10/xml-exc-c14n#" => Some(Self::Exclusive),
            _ => None,
        }
    }
}

fn escape_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn escape_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

/// Canonicalize `element` and its subtree as an XMLDSig node-set (the element is the apex; its
/// ancestors' namespaces are in `element.scope`).
pub(crate) fn canonicalize(element: &Element, mode: C14nMode) -> Vec<u8> {
    let mut out = String::new();
    write_element(element, mode, &NsScope::new(), &mut out);
    out.into_bytes()
}

fn write_element(e: &Element, mode: C14nMode, rendered: &NsScope, out: &mut String) {
    let lookup = |scope: &NsScope, prefix: &str| -> String {
        scope.get(prefix).cloned().unwrap_or_default()
    };

    // Namespace declarations to emit.
    let mut emit: Vec<(String, String)> = Vec::new();
    match mode {
        C14nMode::Inclusive => {
            for (prefix, uri) in &e.scope {
                if prefix == "xml" {
                    continue;
                }
                if lookup(rendered, prefix) != *uri {
                    emit.push((prefix.clone(), uri.clone()));
                }
            }
        }
        C14nMode::Exclusive => {
            let mut used: Vec<&str> = vec![split_qname(&e.qname).0];
            for (k, _) in &e.attrs {
                if k == "xmlns" || k.starts_with("xmlns:") {
                    continue;
                }
                let (prefix, _) = split_qname(k);
                if !prefix.is_empty() {
                    used.push(prefix);
                }
            }
            used.sort_unstable();
            used.dedup();
            for prefix in used {
                if prefix == "xml" {
                    continue;
                }
                let uri = lookup(&e.scope, prefix);
                if lookup(rendered, prefix) != uri {
                    emit.push((prefix.to_string(), uri));
                }
            }
        }
    }
    // `xmlns=""` only undoes a non-empty default rendered on an output ancestor.
    emit.retain(|(p, u)| !(p.is_empty() && u.is_empty() && lookup(rendered, "").is_empty()));
    emit.sort_by(|a, b| a.0.cmp(&b.0));

    let mut attrs: Vec<(String, String, &str, &str)> = e
        .attrs
        .iter()
        .filter(|(k, _)| k != "xmlns" && !k.starts_with("xmlns:"))
        .map(|(k, v)| {
            let (prefix, local) = split_qname(k);
            let ns = if prefix.is_empty() {
                String::new()
            } else {
                lookup(&e.scope, prefix)
            };
            (ns, local.to_string(), k.as_str(), v.as_str())
        })
        .collect();
    attrs.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));

    out.push('<');
    out.push_str(&e.qname);
    for (prefix, uri) in &emit {
        out.push_str(if prefix.is_empty() {
            " xmlns"
        } else {
            " xmlns:"
        });
        out.push_str(prefix);
        out.push_str("=\"");
        escape_attr(uri, out);
        out.push('"');
    }
    for (_, _, name, value) in &attrs {
        out.push(' ');
        out.push_str(name);
        out.push_str("=\"");
        escape_attr(value, out);
        out.push('"');
    }
    out.push('>');

    let mut child_rendered = rendered.clone();
    for (prefix, uri) in emit {
        child_rendered.insert(prefix, uri);
    }
    for child in &e.children {
        match child {
            Node::Text(t) => escape_text(t, out),
            Node::Element(c) => write_element(c, mode, &child_rendered, out),
        }
    }
    out.push_str("</");
    out.push_str(&e.qname);
    out.push('>');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c14n(xml: &str, mode: C14nMode) -> String {
        String::from_utf8(canonicalize(&parse_document(xml.as_bytes()).unwrap(), mode)).unwrap()
    }

    #[test]
    fn inclusive_renders_inherited_namespaces_on_apex() {
        let doc = parse_document(
            br#"<?xml version="1.0"?><a:Root xmlns:a="urn:a" xmlns="urn:d"><Child  z="1" a:y="2" b="&amp;&#x9;"/></a:Root>"#,
        )
        .unwrap();
        let child = doc.child_elements().next().unwrap();
        assert_eq!(
            String::from_utf8(canonicalize(child, C14nMode::Inclusive)).unwrap(),
            r#"<Child xmlns="urn:d" xmlns:a="urn:a" b="&amp;&#x9;" z="1" a:y="2"></Child>"#
        );
        assert_eq!(
            String::from_utf8(canonicalize(child, C14nMode::Exclusive)).unwrap(),
            r#"<Child xmlns="urn:d" xmlns:a="urn:a" b="&amp;&#x9;" z="1" a:y="2"></Child>"#
        );
    }

    #[test]
    fn exclusive_omits_unused_namespaces() {
        assert_eq!(
            c14n(
                r#"<r xmlns:u="urn:u" xmlns:v="urn:v"><u:x/></r>"#,
                C14nMode::Exclusive
            ),
            r#"<r><u:x xmlns:u="urn:u"></u:x></r>"#
        );
        assert_eq!(
            c14n(
                r#"<r xmlns:u="urn:u" xmlns:v="urn:v"><u:x/></r>"#,
                C14nMode::Inclusive
            ),
            r#"<r xmlns:u="urn:u" xmlns:v="urn:v"><u:x></u:x></r>"#
        );
    }

    #[test]
    fn text_and_line_endings_are_normalized() {
        assert_eq!(
            c14n("<r>a\r\nb &lt; &gt; &#xD;</r>", C14nMode::Inclusive),
            "<r>a\nb &lt; &gt; &#xD;</r>"
        );
    }

    #[test]
    fn rejects_doctype() {
        assert!(parse_document(b"<!DOCTYPE r [<!ENTITY e \"x\">]><r>&e;</r>").is_err());
    }
}
