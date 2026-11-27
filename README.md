# hashrail

hashrail is an offline-first Rust CLI for artifact integrity manifests and a small set of repository hygiene checks. It creates SHA-256 or BLAKE3 manifests, can sign the manifest payload with Ed25519, verifies file contents locally, and scans selected files for common credential patterns, mutable GitHub Action refs, and unpinned Docker base images.

The first public implementation focuses on reproducible local checks. It does not implement a GitHub App, a hosted merge gate, dependency provenance attestations, automatic secret revocation, or a guarantee that every secret format will be detected.

## Build

Requires Rust 1.75 or newer.

    cargo build --release

Cargo dependencies are downloaded from the Rust package registry on first build. hashrail itself makes no network requests when it runs.

## Artifact manifests

    hashrail manifest create ./dist --algorithm blake3 --out dist-manifest.json
    hashrail manifest verify dist-manifest.json --root ./dist

The manifest records relative file names, sizes, and hashes. Verification compares the manifest with files under --root (the current directory by default). Unexpected files are reported unless --allow-extra is supplied. Symbolic links are skipped during creation and are not followed during verification.

## Signed manifests

Generate a local Ed25519 key pair. The private key is written only if the destination does not already exist; protect it and keep it out of source control.

    hashrail keygen --private-key ./keys/release.private.hex --public-key ./keys/release.pub
    hashrail manifest create ./dist --out dist-manifest.json --signing-key ./keys/release.private.hex
    hashrail manifest verify dist-manifest.json --root ./dist --public-key ./keys/release.pub

The signing key is a 32-byte seed encoded as hexadecimal. The verifier checks that the supplied public key matches the key recorded in the manifest, then verifies the signature over the version, algorithm, and sorted file entries.

## Static checks

    hashrail scan .github Dockerfile src
    hashrail scan --base origin/main --format json

The scan checks AWS access-key identifiers, common GitHub and Slack token forms, private-key markers, high-entropy values assigned to credential-like fields, GitHub Actions refs that are not full commit SHAs, and Dockerfile base images that are not pinned by digest. Reported secret evidence is redacted. A finding makes the command exit with status 2.

This is a heuristic scanner. It can miss secrets and produce false positives; validate findings and use a dedicated secret-management and scanning program for production.

## Privacy

Manifest creation and verification read files from the selected local directory. Scan reports contain file names and line numbers but redact detected credential values. No files, hashes, or reports are uploaded by hashrail.

No license is included. Public visibility does not grant permission to reuse or redistribute this code.
