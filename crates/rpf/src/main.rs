//! Command-line frontend. Holds no archive knowledge: everything it does, it
//! does through `rpf-core`.

mod advice;
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
    /// Keep extracted key material here rather than in the platform's
    /// configuration directory, and look for it here when opening an encrypted
    /// archive.
    ///
    /// Global, and it has to be: it is the one way to keep several game
    /// installs apart, and an archive command that could not name the cache
    /// would be unable to open what `rpf keys extract --cache-dir` had just
    /// found.
    #[arg(long, global = true, value_name = "DIR")]
    cache_dir: Option<PathBuf>,
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
        /// Which form of the entry to write: its own bytes, its XML view, or
        /// the XML view where there is one and the bytes where there is not.
        #[arg(long = "as", value_name = "VIEW", default_value = "raw")]
        view: commands::ViewArg,
    },
    /// Replace one entry, or create it, cascading through nesting.
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
    /// Remove an entry, rebuilding the archive without it.
    Rm {
        /// The archive.
        archive: PathBuf,
        /// A path inside it.
        path: String,
        /// Take a directory's children with it. Without this a directory that
        /// holds anything is refused.
        #[arg(short = 'r', long)]
        recursive: bool,
        /// How the change is allowed to happen.
        #[command(flatten)]
        options: commands::ChangeOptions,
    },
    /// Move an entry to another path in the same archive.
    Mv {
        /// The archive.
        archive: PathBuf,
        /// The path inside it to move.
        from: String,
        /// Where to move it, spelled the same way `from` is. A path the archive
        /// already holds is refused; remove it first.
        to: String,
        /// How the change is allowed to happen.
        #[command(flatten)]
        options: commands::ChangeOptions,
    },
    /// Add a directory, and whatever above it is missing.
    Mkdir {
        /// The archive.
        archive: PathBuf,
        /// A path inside it.
        path: String,
        /// How the change is allowed to happen.
        #[command(flatten)]
        options: commands::ChangeOptions,
    },
    /// Write every entry to a tree, with a manifest beside it.
    Extract {
        /// The archive.
        archive: PathBuf,
        /// The directory to write into. Created if it does not exist, and
        /// refused if it exists and holds anything.
        into: PathBuf,
        /// Write into a directory that already holds something, replacing what
        /// an entry names and leaving the rest.
        #[arg(long)]
        overwrite: bool,
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
    /// Find the key material a game source carries, and manage its cache.
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
}

/// What can be asked about key material.
///
/// Nothing here prints a key: what is reported is offsets, lengths, digests and
/// cache paths.
#[derive(Debug, Subcommand)]
enum KeysCommand {
    /// Find the key material in a game source, and cache what it found.
    ///
    /// The source is a game executable, or a memory image of one. An executable
    /// carries the AES key and the hash lookup table; only an image carries the
    /// NG expanded keys and decrypt tables.
    Extract {
        /// The game executable, or a memory image of one.
        #[arg(value_name = "SOURCE")]
        executable: PathBuf,
    },
    /// Show where extracted key material is kept, and how much is there.
    Cache,
    /// Remove every cached entry.
    Invalidate,
}

/// What `--overwrite`, or the wire's `overwrite`, means to an extraction, so
/// that the flag and the wire parameter cannot come to mean two things.
const fn existing(overwrite: bool) -> commands::Existing {
    if overwrite {
        commands::Existing::Overwrite
    } else {
        commands::Existing::Refuse
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let cache = cli.cache_dir.as_deref();

    let outcome = match cli.command {
        Command::Info {
            ref archive,
            ref path,
        } => commands::info(archive, path, cache, cli.json),
        Command::Ls {
            ref archive,
            ref path,
            recursive,
        } => commands::ls(archive, path, recursive, cache, cli.json),
        Command::Cat {
            ref archive,
            ref path,
            view,
        } => commands::cat(archive, path, view.into(), cache),
        Command::Put {
            ref archive,
            ref path,
            ref from,
            options,
        } => commands::put(archive, path, from, options, cache, cli.json),
        Command::Rm {
            ref archive,
            ref path,
            recursive,
            options,
        } => commands::remove(archive, path, recursive, options, cache, cli.json),
        Command::Mv {
            ref archive,
            ref from,
            ref to,
            options,
        } => commands::rename(archive, from, to, options, cache, cli.json),
        Command::Mkdir {
            ref archive,
            ref path,
            options,
        } => commands::make_directory(archive, path, options, cache, cli.json),
        Command::Extract {
            ref archive,
            ref into,
            overwrite,
        } => commands::extract(archive, into, existing(overwrite), cache, cli.json),
        Command::Pack {
            ref from,
            ref archive,
            force,
        } => commands::pack(from, archive, force, cache, cli.json),
        Command::Serve { stdio } => {
            if stdio {
                serve::run(cache)
            } else {
                Err(exit::Failure::Refused {
                    reason: "serve needs --stdio".to_owned(),
                })
            }
        }
        Command::Verify {
            ref archive,
            ref against,
        } => commands::verify(archive, against.as_deref(), cache, cli.json),
        Command::Keys { ref command } => match *command {
            KeysCommand::Extract { ref executable } => {
                commands::keys_extract(executable, cache, cli.json)
            }
            KeysCommand::Cache => commands::keys_cache(cache, cli.json),
            KeysCommand::Invalidate => commands::keys_invalidate(cache, cli.json),
        },
    };

    match outcome {
        Ok(()) => ExitCode::from(Code::Ok as u8),
        Err(failure) => {
            eprintln!("rpf: {}", advice::render(&failure));
            ExitCode::from(failure.code() as u8)
        }
    }
}
