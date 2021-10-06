use anyhow::{anyhow, bail};
use landlock::{
    make_bitflags, AccessFs, BitFlags, Compat, Compatibility, ErrorThreshold, PathBeneath,
    RulesetCreated, RulesetInit, ABI,
};
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

const ACCESS_FS_ROUGHLY_READ: BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    Execute | ReadFile | ReadDir});

const ACCESS_FS_ROUGHLY_WRITE: BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    WriteFile | RemoveDir | RemoveFile | MakeChar | MakeDir | MakeReg | MakeSock | MakeFifo |
        MakeBlock | MakeSym
});

const ACCESS_FILE: BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    ReadFile | WriteFile | Execute
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
    compat: &Compatibility,
    ruleset: Compat<RulesetCreated>,
    paths: OsString,
    access: BitFlags<AccessFs>,
) -> Result<Compat<RulesetCreated>, anyhow::Error> {
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
                            .set_error_threshold(ErrorThreshold::PartiallyCompatible)
                            .add_rule(
                                PathBeneath::new(&compat, &parent)?.allow_access(actual_access)?,
                            )
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

    let compat = Compatibility::new()?;
    let ruleset = RulesetInit::new(&compat)?
        .set_error_threshold(ErrorThreshold::PartiallyCompatible)
        .handle_fs(ABI::V1)?
        .create()?;
    let ruleset = populate_ruleset(&compat, ruleset, fs_ro, ACCESS_FS_ROUGHLY_READ)?;
    populate_ruleset(
        &compat,
        ruleset,
        fs_rw,
        ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE,
    )?
    .set_no_new_privs(true)?
    .restrict_self()
    .expect("Failed to enforce ruleset");

    Err(Command::new(cmd_name.to_string())
        .env_remove(ENV_FS_RO_NAME)
        .env_remove(ENV_FS_RW_NAME)
        .args(env::args().skip(2))
        .exec()
        .into())
}
