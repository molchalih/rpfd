//! Command-line frontend. Holds no archive knowledge: everything it does, it
//! does through `rpf-core`. See `docs/conventions.md` §1.

mod commands;
mod exit;
mod install;
mod separator;
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
    /// Summarise an archive, or one nested inside it.
    Info {
        /// The archive.
        archive: PathBuf,
        /// A nested archive inside it. Defaults to the archive itself.
        #[arg(default_value = "")]
        path: String,
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
        /// How the write is allowed to happen.
        #[command(flatten)]
        options: commands::WriteOptions,
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
        /// An extracted tree of this archive, whose manifest records what each
        /// entry's contents should be. Without it a stored entry's bytes are
        /// checked against nothing, because the archive declares nothing about
        /// them.
        #[arg(long, value_name = "TREE")]
        against: Option<PathBuf>,
    },
    /// Find the key material a game executable carries, and manage its cache.
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
}

/// What can be asked about key material.
///
/// **Nothing here prints a key.** DR-006 keeps extracted material off every
/// output path, so what is reported is offsets, lengths, digests and cache
/// paths — assume `--json` is piped into automation and pasted into a bug
/// report. DR-020.
#[derive(Debug, Subcommand)]
enum KeysCommand {
    /// Find the key material in a game executable, and cache what it found.
    Extract {
        /// The game executable.
        executable: PathBuf,
        /// Keep the material here rather than in the platform's configuration
        /// directory.
        #[arg(long, value_name = "DIR")]
        cache_dir: Option<PathBuf>,
    },
    /// Show where extracted key material is kept, and how much is there.
    Cache {
        /// Ask about this directory rather than the platform's.
        #[arg(long, value_name = "DIR")]
        cache_dir: Option<PathBuf>,
    },
    /// Remove every cached entry.
    Invalidate {
        /// Empty this directory rather than the platform's.
        #[arg(long, value_name = "DIR")]
        cache_dir: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let outcome = match cli.command {
        Command::Info {
            ref archive,
            ref path,
        } => commands::info(archive, path, cli.json),
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
            options,
        } => commands::put(archive, path, from, options, cli.json),
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
        Command::Verify {
            ref archive,
            ref against,
        } => commands::verify(archive, against.as_deref(), cli.json),
        Command::Keys { ref command } => match *command {
            KeysCommand::Extract {
                ref executable,
                ref cache_dir,
            } => commands::keys_extract(executable, cache_dir.as_deref(), cli.json),
            KeysCommand::Cache { ref cache_dir } => {
                commands::keys_cache(cache_dir.as_deref(), cli.json)
            }
            KeysCommand::Invalidate { ref cache_dir } => {
                commands::keys_invalidate(cache_dir.as_deref(), cli.json)
            }
        },
    };

    match outcome {
        Ok(()) => ExitCode::from(Code::Ok as u8),
        Err(failure) => {
            eprintln!("rpf: {}", separator::render(&failure));
            ExitCode::from(failure.code() as u8)
        }
    }
}
