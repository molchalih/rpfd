//! Command-line frontend. Holds no archive knowledge: everything it does, it
//! does through `rpf-core`. See `docs/conventions.md` §1.

mod commands;
mod exit;
mod install;
mod serve;

use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};

use crate::exit::Code;

/// Read, edit and rebuild RAGE Package File archives.
#[derive(Debug, Parser)]
#[command(name = "rpf", version, about)]
struct Cli {
    /// Report as JSON, with stable field names.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

/// A path inside an archive addresses through nesting in one string:
/// `x64/vehicles.rpf/meringls63amg24.ytd`.
#[derive(Debug, Subcommand)]
enum Command {
    /// Summarise an archive.
    Info {
        /// The archive.
        archive: PathBuf,
    },
    /// List what is at a path inside an archive.
    Ls {
        /// The archive.
        archive: PathBuf,
        /// A path inside it. Defaults to the root.
        #[arg(default_value = "")]
        path: String,
        /// Descend into directories and nested archives.
        #[arg(short = 'R', long)]
        recursive: bool,
    },
    /// Write one entry's contents to standard output.
    Cat {
        /// The archive.
        archive: PathBuf,
        /// A path inside it.
        path: String,
    },
    /// Replace one entry and rebuild, cascading through nesting.
    Put {
        /// The archive.
        archive: PathBuf,
        /// A path inside it.
        path: String,
        /// The file to put there.
        from: PathBuf,
        /// Write even into a detected game installation.
        #[arg(long)]
        force: bool,
    },
    /// Write every entry to a tree, with a manifest beside it.
    Extract {
        /// The archive.
        archive: PathBuf,
        /// The directory to write into. Created if it does not exist.
        into: PathBuf,
    },
    /// Build an archive from a tree and its manifest.
    Pack {
        /// The directory holding the tree and its manifest.
        from: PathBuf,
        /// The archive to write.
        archive: PathBuf,
        /// Write even into a detected game installation.
        #[arg(long)]
        force: bool,
    },
    /// Serve JSON-RPC over standard input and output, one object per line.
    Serve {
        /// Required, and the only transport there is. Named so that adding
        /// another later does not change what this invocation means.
        #[arg(long)]
        stdio: bool,
    },
    /// Read every entry back and check it against what the archive says.
    Verify {
        /// The archive.
        archive: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let outcome = match cli.command {
        Command::Info { ref archive } => commands::info(archive, cli.json),
        Command::Ls {
            ref archive,
            ref path,
            recursive,
        } => commands::ls(archive, path, recursive, cli.json),
        Command::Cat {
            ref archive,
            ref path,
        } => commands::cat(archive, path),
        Command::Put {
            ref archive,
            ref path,
            ref from,
            force,
        } => commands::put(archive, path, from, force),
        Command::Extract {
            ref archive,
            ref into,
        } => commands::extract(archive, into, cli.json),
        Command::Pack {
            ref from,
            ref archive,
            force,
        } => commands::pack(from, archive, force, cli.json),
        Command::Serve { stdio } => {
            if stdio {
                serve::run()
            } else {
                Err(exit::Failure::Refused {
                    reason: "serve needs --stdio".to_owned(),
                })
            }
        }
        Command::Verify { ref archive } => commands::verify(archive, cli.json),
    };

    match outcome {
        Ok(()) => ExitCode::from(Code::Ok as u8),
        Err(failure) => {
            eprintln!("rpf: {failure}");
            ExitCode::from(failure.code() as u8)
        }
    }
}
