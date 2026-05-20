use anyhow::{Context, Result};
use goblin::Object;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
struct BinaryNode {
    path: String,
    sha256: String,
    imports: Vec<String>,
}

#[derive(Debug, Serialize)]
struct BinaryManifest {
    root: String,
    nodes: Vec<BinaryNode>,
}

#[derive(Debug, Serialize)]
struct DependencyGraph {
    root: String,
    edges: BTreeMap<String, Vec<String>>,
}

fn read_sha256(path: &Path) -> Result<String> {
    let mut file =
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];

    loop {
        let read = file
            .read(&mut buf)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn pe_imports(path: &Path) -> Result<Vec<String>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut imports = Vec::new();

    if let Object::PE(pe) =
        Object::parse(&bytes).with_context(|| format!("failed to parse PE {}", path.display()))?
    {
        for library in pe.libraries {
            imports.push(library.to_ascii_lowercase());
        }
    }

    imports.sort();
    imports.dedup();
    Ok(imports)
}

fn candidate_paths(name: &str, parent: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();

    out.push(parent.join(name));
    out.push(PathBuf::from(r"C:\Windows\System32").join(name));

    if let Ok(path_var) = std::env::var("PATH") {
        for segment in path_var.split(';') {
            let seg = segment.trim();
            if !seg.is_empty() {
                out.push(PathBuf::from(seg).join(name));
            }
        }
    }

    out
}

fn resolve_binary(name: &str, parent: &Path) -> Option<PathBuf> {
    candidate_paths(name, parent)
        .into_iter()
        .find(|candidate| candidate.exists())
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let signtool = if args.next().as_deref() == Some("--signtool") {
        PathBuf::from(
            args.next()
                .context("missing value for --signtool argument")?,
        )
    } else {
        PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe")
    };

    let root = signtool
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", signtool.display()))?;

    let output_dir = PathBuf::from("parity-output");
    fs::create_dir_all(&output_dir).context("failed to create parity-output directory")?;

    let mut queue = VecDeque::from([root.clone()]);
    let mut visited = BTreeSet::new();
    let mut nodes = Vec::new();
    let mut edges: BTreeMap<String, Vec<String>> = BTreeMap::new();

    while let Some(current) = queue.pop_front() {
        let key = current.to_string_lossy().to_string();
        if visited.contains(&key) {
            continue;
        }
        visited.insert(key.clone());

        let imports = pe_imports(&current)?;
        let parent = current.parent().unwrap_or(Path::new("."));
        let mut resolved_children = Vec::new();

        for import in &imports {
            if let Some(resolved) = resolve_binary(import, parent) {
                let child_key = resolved.to_string_lossy().to_string();
                resolved_children.push(child_key.clone());
                if !visited.contains(&child_key) {
                    queue.push_back(resolved);
                }
            }
        }

        let sha256 = read_sha256(&current)?;
        nodes.push(BinaryNode {
            path: key.clone(),
            sha256,
            imports,
        });
        edges.insert(key, resolved_children);
    }

    nodes.sort_by(|a, b| a.path.cmp(&b.path));

    let manifest = BinaryManifest {
        root: root.to_string_lossy().to_string(),
        nodes,
    };
    let graph = DependencyGraph {
        root: root.to_string_lossy().to_string(),
        edges,
    };

    fs::write(
        output_dir.join("binary-manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )
    .context("failed to write binary-manifest.json")?;
    fs::write(
        output_dir.join("dependency-graph.json"),
        serde_json::to_string_pretty(&graph)?,
    )
    .context("failed to write dependency-graph.json")?;

    println!(
        "wrote {} nodes to parity-output/binary-manifest.json",
        manifest.nodes.len()
    );
    println!("wrote dependency graph to parity-output/dependency-graph.json");
    Ok(())
}
