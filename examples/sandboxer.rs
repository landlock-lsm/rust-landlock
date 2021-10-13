use anyhow::{anyhow, bail};
use landlock::{
    make_bitflags, AccessFs, BitFlags, PathBeneath, Ruleset, RulesetCreated, RulesetStatus, ABI,
};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

const ENV_FS_RO_NAME: &str = "LL_FS_RO";
const ENV_FS_RW_NAME: &str = "LL_FS_RW";

const ACCESS_FS_ROUGHLY_READ: BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    Execute | ReadFile | ReadDir});

const ACCESS_FS_ROUGHLY_WRITE: BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    WriteFile | RemoveDir | RemoveFile | MakeChar | MakeDir | MakeReg | MakeSock | MakeFifo |
        MakeBlock | MakeSym
});

/// Populates a given ruleset with PathBeneath landlock rules
///
/// # Arguments
///
/// * `ruleset` - The ruleset to add the rules to. Note that due to the current
///   API, it is also returned at the end.
/// * `paths` - An OsString that contains the paths that are going to be
///   restricted. Paths are separated with ":", e.g. "/bin:/lib:/usr:/proc". In
///   case an empty string is provided, NO restrictions are applied.
/// * `access` - The set of restrictions to apply to each of the given paths.
///
fn populate_ruleset(
    ruleset: RulesetCreated,
    paths: OsString,
    access: BitFlags<AccessFs>,
) -> Result<RulesetCreated, anyhow::Error> {
    if paths.len() == 0 {
        return Ok(ruleset);
    }

    paths
        .into_vec()
        .split(|b| *b == b':')
        .try_fold(ruleset, |inner_ruleset, path| {
            let path: PathBuf = OsStr::from_bytes(path).to_owned().into();
            match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
                .open(&path)
            {
                Err(e) => {
                    bail!("Failed to open \"{}\": {}", path.to_string_lossy(), e);
                }
                Ok(parent) => Ok(inner_ruleset
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

    let fs_ro = env::var_os(ENV_FS_RO_NAME)
        .expect(&format!("Missing environment variable {}", ENV_FS_RO_NAME));
    let fs_rw = env::var_os(ENV_FS_RW_NAME)
        .expect(&format!("Missing environment variable {}", ENV_FS_RW_NAME));

    let cmd_name = args.get(1).map(|s| s.to_string_lossy()).unwrap();

    let ruleset = Ruleset::new().handle_fs(ABI::V1)?.create()?;
    let ruleset = populate_ruleset(ruleset, fs_ro, ACCESS_FS_ROUGHLY_READ)?;
    let status = populate_ruleset(
        ruleset,
        fs_rw,
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
