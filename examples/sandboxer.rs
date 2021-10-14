use anyhow::{anyhow, bail};
use landlock::{
    make_bitflags, AccessFs, BitFlags, PathBeneath, Ruleset, RulesetCreated, RulesetStatus, ABI,
};
use std::env;
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::Command;

const ENV_FS_RO_NAME: &str = "LL_FS_RO";
const ENV_FS_RW_NAME: &str = "LL_FS_RW";

const ACCESS_FS_ROUGHLY_READ: BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    Execute | ReadFile | ReadDir});

const ACCESS_FS_ROUGHLY_WRITE: BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    WriteFile | RemoveDir | RemoveFile | MakeChar | MakeDir | MakeReg | MakeSock | MakeFifo |
        MakeBlock | MakeSym
});

trait RulesetCreatedExt {
    /// Populates a given ruleset with PathBeneath landlock rules
    ///
    /// # Arguments
    ///
    /// * `name`: String identifying an environment variable containing paths requested to be
    ///   allowed. Paths are separated with ":", e.g. "/bin:/lib:/usr:/proc". In case an empty
    ///   string is provided, NO restrictions are applied.
    /// * `access`: Set of access-rights allowed for each of the parsed paths.
    fn populate_with_env(
        self,
        name: &str,
        access: BitFlags<AccessFs>,
    ) -> Result<RulesetCreated, anyhow::Error>;
}

impl RulesetCreatedExt for RulesetCreated {
    fn populate_with_env(
        self,
        name: &str,
        access: BitFlags<AccessFs>,
    ) -> Result<RulesetCreated, anyhow::Error> {
        let paths = env::var_os(name).ok_or(anyhow!("Missing environment variable {}", name))?;
        if paths.len() == 0 {
            return Ok(self);
        }

        paths
            .into_vec()
            .split(|b| *b == b':')
            .try_fold(self, |ruleset, path| {
                let path = OsStr::from_bytes(path);
                match OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
                    .open(&path)
                {
                    Err(e) => {
                        bail!("Failed to open \"{}\": {}", path.to_string_lossy(), e);
                    }
                    Ok(parent) => Ok(ruleset
                        .add_rule(PathBeneath::new(&parent).allow_access(access))
                        .map_err(|e| {
                            anyhow!(
                                "Failed to update ruleset with \"{}\": {}",
                                path.to_string_lossy(),
                                e
                            )
                        })?),
                }
            })
    }
}

fn main() -> Result<(), anyhow::Error> {
    let args: Vec<_> = env::args_os().collect();

    let program_name = args.get(0).map(|s| s.to_string_lossy()).unwrap_or_default();

    if args.len() < 2 {
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
                {} bash -i",
            ENV_FS_RO_NAME, ENV_FS_RW_NAME, program_name
        );
        return Ok(());
    }

    let cmd_name = args.get(1).map(|s| s.to_string_lossy()).unwrap();

    let status = Ruleset::new()
        .handle_fs(ABI::V1)?
        .create()?
        .populate_with_env(ENV_FS_RO_NAME, ACCESS_FS_ROUGHLY_READ)?
        .populate_with_env(
            ENV_FS_RW_NAME,
            ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE,
        )?
        .restrict_self()
        .expect("Failed to enforce ruleset");

    if status.ruleset == RulesetStatus::NotEnforced {
        bail!("Landlock is not supported by the running kernel.");
    }

    Err(Command::new(cmd_name.to_string())
        .env_remove(ENV_FS_RO_NAME)
        .env_remove(ENV_FS_RW_NAME)
        .args(env::args().skip(2))
        .exec()
        .into())
}
