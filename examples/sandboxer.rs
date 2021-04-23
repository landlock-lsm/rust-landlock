use anyhow::{anyhow, bail};
use landlock::{AccessFs, Compat, ErrorThreshold, PathBeneath, Ruleset, RulesetAttr};
use nix::fcntl::{open, OFlag};
use nix::sys::stat::{fstat, Mode, SFlag};
use std::env;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

const ENV_FS_RO_NAME: &str = "LL_FS_RO";
const ENV_FS_RW_NAME: &str = "LL_FS_RW";

const ACCESS_FS_ROUGHLY_READ: AccessFs = AccessFs::from_bits_truncate(
    AccessFs::EXECUTE.bits() | AccessFs::READ_FILE.bits() | AccessFs::READ_DIR.bits(),
);

const ACCESS_FS_ROUGHLY_WRITE: AccessFs = AccessFs::from_bits_truncate(
    AccessFs::WRITE_FILE.bits()
        | AccessFs::REMOVE_DIR.bits()
        | AccessFs::REMOVE_FILE.bits()
        | AccessFs::MAKE_CHAR.bits()
        | AccessFs::MAKE_DIR.bits()
        | AccessFs::MAKE_REG.bits()
        | AccessFs::MAKE_SOCK.bits()
        | AccessFs::MAKE_FIFO.bits()
        | AccessFs::MAKE_BLOCK.bits()
        | AccessFs::MAKE_SYM.bits(),
);

const ACCESS_FILE: AccessFs = AccessFs::from_bits_truncate(
    AccessFs::READ_FILE.bits() | AccessFs::WRITE_FILE.bits() | AccessFs::EXECUTE.bits(),
);

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
    ruleset: Compat<Ruleset>,
    paths: OsString,
    access: AccessFs,
) -> Result<Compat<Ruleset>, anyhow::Error> {
    if paths.len() == 0 {
        return Ok(ruleset);
    }

    paths
        .into_vec()
        .split(|b| *b == b':')
        .try_fold(ruleset, |inner_ruleset, path| {
            let path: PathBuf = OsStr::from_bytes(path).to_owned().into();
            match open(&path, OFlag::O_PATH | OFlag::O_CLOEXEC, Mode::empty()) {
                Err(e) => {
                    bail!("Failed to open \"{}\": {}", path.to_string_lossy(), e);
                }
                Ok(parent) => match fstat(parent) {
                    Ok(stat) => {
                        let actual_access =
                            if (stat.st_mode & SFlag::S_IFMT.bits()) != SFlag::S_IFDIR.bits() {
                                access & ACCESS_FILE
                            } else {
                                access
                            };

                        Ok(inner_ruleset
                            .add_rule(PathBeneath::new(&parent).allow_access(actual_access))
                            .into_result(ErrorThreshold::Runtime)
                            .map_err(|e| {
                                anyhow!(
                                    "Failed to update ruleset with \"{}\": {}",
                                    path.to_string_lossy(),
                                    e
                                )
                            })?)
                    }
                    Err(e) => {
                        bail!("Failed to stat \"{}\": {}", path.to_string_lossy(), e);
                    }
                },
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

    let ruleset = RulesetAttr::new()
        .handle_fs(AccessFs::all())
        .create()
        .into_result(ErrorThreshold::PartiallyCompatible)?;
    let ruleset = populate_ruleset(ruleset, fs_ro, ACCESS_FS_ROUGHLY_READ)?;
    populate_ruleset(
        ruleset,
        fs_rw,
        ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE,
    )?
    .set_no_new_privs(true)
    .restrict_self()
    .into_result()
    .expect("Failed to enforce ruleset");

    Err(Command::new(cmd_name.to_string())
        .env_remove(ENV_FS_RO_NAME)
        .env_remove(ENV_FS_RW_NAME)
        .args(env::args().skip(2))
        .exec()
        .into())
}
