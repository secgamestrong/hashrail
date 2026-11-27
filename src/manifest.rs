use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy)]
pub enum HashAlgorithm {
    Sha256,
    Blake3,
}

impl HashAlgorithm {
    fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Blake3 => "blake3",
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    algorithm: String,
    entries: Vec<Entry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<SignatureEnvelope>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    size: u64,
    hash: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureEnvelope {
    algorithm: String,
    public_key: String,
    signature: String,
}

#[derive(Serialize)]
struct SignableManifest<'a> {
    schema_version: u32,
    algorithm: &'a str,
    entries: &'a [Entry],
}

pub fn create(root: &Path, output: &Path, algorithm: HashAlgorithm, key_path: Option<&Path>) -> Result<bool, String> {
    let root = fs::canonicalize(root).map_err(|error| format!("open artifact directory: {error}"))?;
    if !root.is_dir() {
        return Err("artifact path must be a directory".into());
    }
    let output_absolute = absolute_lexical(output)?;
    let mut entries = Vec::new();
    for item in WalkDir::new(&root).follow_links(false).into_iter().filter_entry(|entry| {
        entry.file_name() != ".git"
    }) {
        let item = item.map_err(|error| format!("walk artifact directory: {error}"))?;
        if !item.file_type().is_file() {
            continue;
        }
        let path = item.path();
        if absolute_lexical(path)? == output_absolute {
            continue;
        }
        let relative = path.strip_prefix(&root).map_err(|_| "artifact escaped the selected root")?;
        let normalized = portable_relative(relative)?;
        let (size, hash) = hash_file(path, algorithm)
            .map_err(|error| format!("hash {}: {error}", path.display()))?;
        entries.push(Entry {
            path: normalized,
            size,
            hash,
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let mut manifest = Manifest {
        schema_version: SCHEMA_VERSION,
        algorithm: algorithm.name().to_string(),
        entries,
        signature: None,
    };
    if let Some(path) = key_path {
        let signing = read_signing_key(path)?;
        let payload = signable_bytes(&manifest)?;
        let signature = signing.sign(&payload);
        manifest.signature = Some(SignatureEnvelope {
            algorithm: "ed25519".into(),
            public_key: hex::encode(signing.verifying_key().to_bytes()),
            signature: BASE64.encode(signature.to_bytes()),
        });
    }
    let data = serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?;
    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|error| format!("create output directory: {error}"))?;
    }
    fs::write(output, [data, b"\n".to_vec()].concat())
        .map_err(|error| format!("write {}: {error}", output.display()))?;
    println!("wrote {} entries to {}", manifest.entries.len(), output.display());
    if manifest.signature.is_some() {
        println!("manifest signed with Ed25519");
    }
    Ok(false)
}

pub fn verify(path: &Path, root_path: &Path, public_key_path: Option<&Path>, allow_extra: bool) -> Result<bool, String> {
    let data = fs::read(path).map_err(|error| format!("read manifest: {error}"))?;
    let manifest: Manifest = serde_json::from_slice(&data).map_err(|error| format!("parse manifest: {error}"))?;
    if manifest.schema_version != SCHEMA_VERSION {
        return Err(format!("unsupported manifest schema version {}", manifest.schema_version));
    }
    if manifest.algorithm != "sha256" && manifest.algorithm != "blake3" {
        return Err(format!("unsupported hash algorithm {}", manifest.algorithm));
    }
    validate_manifest_paths(&manifest.entries)?;
    verify_signature(&manifest, public_key_path)?;
    let root = fs::canonicalize(root_path).map_err(|error| format!("open verification root: {error}"))?;
    if !root.is_dir() {
        return Err("verification root must be a directory".into());
    }
    let manifest_absolute = absolute_lexical(path)?;
    let expected: BTreeMap<&str, &Entry> = manifest.entries.iter().map(|entry| (entry.path.as_str(), entry)).collect();
    let mut actual_paths = BTreeSet::new();
    let mut failures = Vec::new();
    for item in WalkDir::new(&root).follow_links(false).filter_entry(|entry| {
        entry.file_name() != ".git"
    }) {
        let item = item.map_err(|error| format!("walk working directory: {error}"))?;
        if !item.file_type().is_file() || absolute_lexical(item.path())? == manifest_absolute {
            continue;
        }
        let relative = item.path().strip_prefix(&root).map_err(|_| "file escaped working directory")?;
        let name = portable_relative(relative)?;
        actual_paths.insert(name.clone());
        if let Some(entry) = expected.get(name.as_str()) {
            let algorithm = parse_algorithm(&manifest.algorithm)?;
            let (size, computed) = hash_file(item.path(), algorithm)
                .map_err(|error| format!("hash {}: {error}", item.path().display()))?;
            if computed != entry.hash || size != entry.size {
                failures.push(format!("{name}: content or size differs from manifest"));
            }
        } else if !allow_extra {
            failures.push(format!("{name}: unexpected file"));
        }
    }
    for name in expected.keys() {
        if !actual_paths.contains(*name) {
            failures.push(format!("{name}: missing file"));
        }
    }
    if failures.is_empty() {
        println!("verified {} files", expected.len());
        Ok(false)
    } else {
        for failure in &failures {
            println!("MISMATCH {failure}");
        }
        println!("verification failed: {} issue(s)", failures.len());
        Ok(true)
    }
}

pub fn keygen(private_path: &Path, public_path: &Path) -> Result<bool, String> {
    let key = SigningKey::generate(&mut OsRng);
    write_new_private(private_path, hex::encode(key.to_bytes()).as_bytes())?;
    write_new(public_path, hex::encode(key.verifying_key().to_bytes()).as_bytes())?;
    println!("wrote Ed25519 key pair; keep {} private", private_path.display());
    Ok(false)
}

fn write_new_private(path: &Path, content: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| format!("create private key {}: {error}", path.display()))?;
    file.write_all(content).map_err(|error| error.to_string())?;
    Ok(())
}

fn write_new(path: &Path, content: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(content).map_err(|error| error.to_string())?;
    Ok(())
}

fn read_signing_key(path: &Path) -> Result<SigningKey, String> {
    let raw = fs::read_to_string(path).map_err(|error| format!("read signing key: {error}"))?;
    let bytes = hex::decode(raw.trim()).map_err(|error| format!("signing key must be 64 hex characters: {error}"))?;
    let seed: [u8; 32] = bytes.try_into().map_err(|_| "signing key must decode to exactly 32 bytes")?;
    Ok(SigningKey::from_bytes(&seed))
}

fn verify_signature(manifest: &Manifest, public_key_path: Option<&Path>) -> Result<(), String> {
    match (&manifest.signature, public_key_path) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err("a public key was supplied but the manifest is unsigned".into()),
        (Some(_), None) => Err("manifest is signed; provide --public-key to verify its signature".into()),
        (Some(envelope), Some(path)) => {
            if envelope.algorithm != "ed25519" {
                return Err(format!("unsupported signature algorithm {}", envelope.algorithm));
            }
            let expected = read_public_key(path)?;
            let embedded = decode_fixed::<32>(&envelope.public_key, "embedded public key")?;
            if embedded != expected.to_bytes() {
                return Err("public key does not match the key recorded in the manifest".into());
            }
            let bytes = BASE64.decode(&envelope.signature).map_err(|error| format!("invalid signature encoding: {error}"))?;
            let signature = Signature::from_slice(&bytes).map_err(|error| format!("invalid signature: {error}"))?;
            let key = VerifyingKey::from_bytes(&expected).map_err(|error| format!("invalid public key: {error}"))?;
            key.verify(&signable_bytes(manifest)?, &signature).map_err(|_| "manifest signature verification failed".to_string())
        }
    }
}

fn read_public_key(path: &Path) -> Result<[u8; 32], String> {
    let raw = fs::read_to_string(path).map_err(|error| format!("read public key: {error}"))?;
    decode_fixed(raw.trim(), "public key")
}

fn decode_fixed<const N: usize>(raw: &str, label: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(raw).map_err(|error| format!("invalid {label}: {error}"))?;
    bytes.try_into().map_err(|_| format!("{label} must decode to exactly {N} bytes"))
}

fn signable_bytes(manifest: &Manifest) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&SignableManifest {
        schema_version: manifest.schema_version,
        algorithm: &manifest.algorithm,
        entries: &manifest.entries,
    }).map_err(|error| error.to_string())
}

fn validate_manifest_paths(entries: &[Entry]) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for entry in entries {
        let path = Path::new(&entry.path);
        if path.is_absolute() || path.components().any(|component| !matches!(component, Component::Normal(_))) {
            return Err(format!("unsafe manifest path {:?}", entry.path));
        }
        if !seen.insert(entry.path.as_str()) {
            return Err(format!("duplicate manifest path {:?}", entry.path));
        }
    }
    Ok(())
}

fn portable_relative(path: &Path) -> Result<String, String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            _ => return Err(format!("unsafe relative path {}", path.display())),
        }
    }
    Ok(parts.join("/"))
}

fn absolute_lexical(path: &Path) -> Result<PathBuf, String> {
    let base = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().map_err(|error| error.to_string())?
    };
    let mut out = base;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => { out.pop(); }
            Component::Normal(part) => out.push(part),
        }
    }
    Ok(out)
}

fn parse_algorithm(algorithm: &str) -> Result<HashAlgorithm, String> {
    match algorithm {
        "sha256" => Ok(HashAlgorithm::Sha256),
        "blake3" => Ok(HashAlgorithm::Blake3),
        other => Err(format!("unsupported hash algorithm {other}")),
    }
}

fn hash_file(path: &Path, algorithm: HashAlgorithm) -> Result<(u64, String), std::io::Error> {
    let mut file = File::open(path)?;
    let mut buffer = [0u8; 64 * 1024];
    let mut size = 0u64;
    let mut sha256 = Sha256::new();
    let mut blake3 = blake3::Hasher::new();
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size += count as u64;
        match algorithm {
            HashAlgorithm::Sha256 => { sha256.update(&buffer[..count]); }
            HashAlgorithm::Blake3 => { blake3.update(&buffer[..count]); }
        }
    }
    let hash = match algorithm {
        HashAlgorithm::Sha256 => hex::encode(sha256.finalize()),
        HashAlgorithm::Blake3 => blake3.finalize().to_hex().to_string(),
    };
    Ok((size, hash))
}
