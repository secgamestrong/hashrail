mod manifest;
mod scan;

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "hashrail", version, about = "Offline artifact integrity and repository hygiene checks")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Manifest {
        #[command(subcommand)]
        command: ManifestCommand,
    },
    Scan(ScanArgs),
    Keygen(KeygenArgs),
}

#[derive(Subcommand)]
enum ManifestCommand {
    Create(CreateManifestArgs),
    Verify(VerifyManifestArgs),
}

#[derive(Args)]
struct CreateManifestArgs {
    #[arg(value_name = "PATH")]
    path: PathBuf,
    #[arg(long, default_value = "hashrail.json")]
    out: PathBuf,
    #[arg(long, value_enum, default_value = "sha256")]
    algorithm: Algorithm,
    #[arg(long)]
    signing_key: Option<PathBuf>,
}

#[derive(Args)]
struct VerifyManifestArgs {
    #[arg(value_name = "MANIFEST")]
    manifest: PathBuf,
    #[arg(long, default_value = ".", help = "Directory whose contents are checked against the manifest")]
    root: PathBuf,
    #[arg(long)]
    public_key: Option<PathBuf>,
    #[arg(long, help = "Ignore files that are not listed in the manifest")]
    allow_extra: bool,
}

#[derive(Args)]
struct ScanArgs {
    #[arg(value_name = "PATHS", required_unless_present = "base")]
    paths: Vec<PathBuf>,
    #[arg(long, help = "Scan changed files from BASE...HEAD instead of explicit paths")]
    base: Option<String>,
    #[arg(long, value_enum, default_value = "text")]
    format: OutputFormat,
}

#[derive(Args)]
struct KeygenArgs {
    #[arg(long, default_value = "hashrail-ed25519.key")]
    private_key: PathBuf,
    #[arg(long, default_value = "hashrail-ed25519.pub")]
    public_key: PathBuf,
}

#[derive(Clone, Copy, ValueEnum)]
enum Algorithm {
    Sha256,
    Blake3,
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Manifest { command } => match command {
            ManifestCommand::Create(args) => manifest::create(
                &args.path,
                &args.out,
                match args.algorithm {
                    Algorithm::Sha256 => manifest::HashAlgorithm::Sha256,
                    Algorithm::Blake3 => manifest::HashAlgorithm::Blake3,
                },
                args.signing_key.as_deref(),
            ),
            ManifestCommand::Verify(args) => manifest::verify(
                &args.manifest,
                &args.root,
                args.public_key.as_deref(),
                args.allow_extra,
            ),
        },
        Command::Scan(args) => scan::run(
            &args.paths,
            args.base.as_deref(),
            matches!(args.format, OutputFormat::Json),
        ),
        Command::Keygen(args) => manifest::keygen(&args.private_key, &args.public_key),
    };
    match result {
        Ok(findings) if findings => ExitCode::from(2),
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("hashrail: {error}");
            ExitCode::from(2)
        }
    }
}
