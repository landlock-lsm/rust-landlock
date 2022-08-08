// This is an idiomatic Rust rewrite of a C example:
// https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/samples/landlock/sandboxer.c

use anyhow::{anyhow, bail};
use landlock::{
    Access, AccessFs, BitFlags, PathBeneath, PathFd, PathFdError, Ruleset, RulesetError,
    RulesetStatus, ABI,
};
use std::env;
use std::ffi::OsStr;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::CommandExt;
use std::process::Command;
use thiserror::Error;

const ENV_FS_RO_NAME: &str = "LL_FS_RO";
const ENV_FS_RW_NAME: &str = "LL_FS_RW";

#[derive(Debug, Error)]
enum PathEnvError<'a> {
    #[error(transparent)]
    Ruleset(#[from] RulesetError),
    #[error(transparent)]
    AddRuleIter(#[from] PathFdError),
    #[error("missing environment variable {0}")]
    MissingVar(&'a str),
}

struct PathEnv {
    paths: Vec<u8>,
    access: BitFlags<AccessFs>,
}

impl PathEnv {
    /// Create an object able to iterate PathBeneath rules
    ///
    /// # Arguments
    ///
    /// * `name`: String identifying an environment variable containing paths requested to be
    ///   allowed. Paths are separated with ":", e.g. "/bin:/lib:/usr:/proc". In case an empty
    ///   string is provided, NO restrictions are applied.
    /// * `access`: Set of access-rights allowed for each of the parsed paths.
    fn new<'a>(name: &'a str, access: BitFlags<AccessFs>) -> Result<Self, PathEnvError<'a>> {
        Ok(Self {
            paths: env::var_os(name)
                .ok_or(PathEnvError::MissingVar(name))?
                .into_vec(),
            access,
        })
    }

    fn iter(
        &self,
    ) -> impl Iterator<Item = Result<PathBeneath<PathFd>, PathEnvError<'static>>> + '_ {
        let is_empty = self.paths.is_empty();
        self.paths
            .split(|b| *b == b':')
            // Skips the first empty element from of an empty string.
            .skip_while(move |_| is_empty)
            .map(OsStr::from_bytes)
            .map(move |path| Ok(PathBeneath::new(PathFd::new(path)?, self.access)))
    }
}

fn main() -> Result<(), anyhow::Error> {
    let mut args = env::args_os();
    let program_name = args
        .next()
        .ok_or(anyhow!("Missing the sandboxer program name (i.e. argv[0])"))?;

    let cmd_name = args.next().ok_or_else(|| {
        let program_name = program_name.to_string_lossy();
        eprintln!(
            "usage: {}=\"...\" {}=\"...\" {} <cmd> [args]...\n",
            ENV_FS_RO_NAME, ENV_FS_RW_NAME, program_name
        );
        eprintln!("Launch a command in a restricted environment.\n");
        eprintln!("Environment variables containing paths, each separated by a colon:");
        eprintln!(
            "* {}: list of paths allowed to be used in a read-only way.",
            ENV_FS_RO_NAME
        );
        eprintln!(
            "* {}: list of paths allowed to be used in a read-write way.",
            ENV_FS_RW_NAME
        );
        eprintln!(
            "\nexample:\n\
                {}=\"/bin:/lib:/usr:/proc:/etc:/dev/urandom\" \
                {}=\"/dev/null:/dev/full:/dev/zero:/dev/pts:/tmp\" \
                {} bash -i\n",
            ENV_FS_RO_NAME, ENV_FS_RW_NAME, program_name
        );
        anyhow!("Missing command")
    })?;

    let abi = ABI::V2;
    let status = Ruleset::new()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        .add_rules(PathEnv::new(ENV_FS_RO_NAME, AccessFs::from_read(abi))?.iter())?
        .add_rules(PathEnv::new(ENV_FS_RW_NAME, AccessFs::from_all(abi))?.iter())?
        .restrict_self()
        .expect("Failed to enforce ruleset");

    if status.ruleset == RulesetStatus::NotEnforced {
        bail!("Landlock is not supported by the running kernel.");
    }

    Err(Command::new(cmd_name)
        .env_remove(ENV_FS_RO_NAME)
        .env_remove(ENV_FS_RW_NAME)
        .args(args)
        .exec()
        .into())
}
