// This is an idiomatic Rust rewrite of a C example:
// https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/samples/landlock/sandboxer.c

use anyhow::{anyhow, bail, Context};
use landlock::{
    Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};
use std::env;
use std::ffi::OsStr;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::CommandExt;
use std::process::Command;

const ENV_FS_RO_NAME: &str = "LL_FS_RO";
const ENV_FS_RW_NAME: &str = "LL_FS_RW";
const ENV_TCP_BIND_NAME: &str = "LL_TCP_BIND";
const ENV_TCP_CONNECT_NAME: &str = "LL_TCP_CONNECT";

struct PathEnv {
    paths: Vec<u8>,
    access: AccessFs,
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
    fn new<'a>(name: &'a str, access: AccessFs) -> anyhow::Result<Self> {
        Ok(Self {
            paths: env::var_os(name)
                .ok_or(anyhow!("missing environment variable {name}"))?
                .into_vec(),
            access,
        })
    }

    fn iter(&self) -> impl Iterator<Item = anyhow::Result<PathBeneath<PathFd>>> + '_ {
        let is_empty = self.paths.is_empty();
        self.paths
            .split(|b| *b == b':')
            // Skips the first empty element from of an empty string.
            .skip_while(move |_| is_empty)
            .map(OsStr::from_bytes)
            .map(move |path| Ok(PathBeneath::new(PathFd::new(path)?, self.access)))
    }
}

struct PortEnv {
    ports: Vec<u8>,
    access: AccessNet,
}

impl PortEnv {
    fn new<'a>(name: &'a str, access: AccessNet) -> anyhow::Result<Self> {
        Ok(Self {
            ports: env::var_os(name).unwrap_or_default().into_vec(),
            access,
        })
    }

    fn iter(&self) -> impl Iterator<Item = anyhow::Result<NetPort>> + '_ {
        let is_empty = self.ports.is_empty();
        self.ports
            .split(|b| *b == b':')
            // Skips the first empty element of an empty string.
            .skip_while(move |_| is_empty)
            .map(OsStr::from_bytes)
            .map(|port| {
                let port = port
                    .to_str()
                    .context("failed to convert port string")?
                    .parse::<u16>()
                    .context("failed to convert port to 16-bit integer")?;
                Ok(NetPort::new(port, self.access))
            })
    }
}

fn main() -> anyhow::Result<()> {
    let mut args = env::args_os();
    let program_name = args
        .next()
        .context("Missing the sandboxer program name (i.e. argv[0])")?;

    let cmd_name = args.next().ok_or_else(|| {
        let program_name = program_name.to_string_lossy();
        eprintln!(
            "usage: {ENV_FS_RO_NAME}=\"...\" {ENV_FS_RW_NAME}=\"...\" {program_name} <cmd> [args]...\n"
        );
        eprintln!("Launch a command in a restricted environment.\n");
        eprintln!("Environment variables containing paths and ports, each separated by a colon:");
        eprintln!("* {ENV_FS_RO_NAME}: list of paths allowed to be used in a read-only way.");
        eprintln!("* {ENV_FS_RW_NAME}: list of paths allowed to be used in a read-write way.");
        eprintln!("Environment variables containing ports are optional and could be skipped.");
        eprintln!("* {ENV_TCP_BIND_NAME}: list of ports allowed to bind (server).");
        eprintln!("* {ENV_TCP_CONNECT_NAME}: list of ports allowed to connect (client).");
        eprintln!(
            "\nexample:\n\
                {ENV_FS_RO_NAME}=\"/bin:/lib:/usr:/proc:/etc:/dev/urandom\" \
                {ENV_FS_RW_NAME}=\"/dev/null:/dev/full:/dev/zero:/dev/pts:/tmp\" \
                {ENV_TCP_BIND_NAME}=\"9418\" \
                {ENV_TCP_CONNECT_NAME}=\"80:443\" \
                {program_name} bash -i\n"
        );
        anyhow!("Missing command")
    })?;

    let abi = ABI::V5;
    let mut ruleset = Ruleset::default().handle_access(AccessFs::from_all(abi))?;
    let ruleset_ref = &mut ruleset;

    if env::var_os(ENV_TCP_BIND_NAME).is_some() {
        ruleset_ref.handle_access(AccessNet::BindTcp)?;
    }
    if env::var_os(ENV_TCP_CONNECT_NAME).is_some() {
        ruleset_ref.handle_access(AccessNet::ConnectTcp)?;
    }
    let status = ruleset
        .create()?
        .add_rules(PathEnv::new(ENV_FS_RO_NAME, AccessFs::from_read(abi))?.iter())?
        .add_rules(PathEnv::new(ENV_FS_RW_NAME, AccessFs::from_all(abi))?.iter())?
        .add_rules(PortEnv::new(ENV_TCP_BIND_NAME, AccessNet::BindTcp)?.iter())?
        .add_rules(PortEnv::new(ENV_TCP_CONNECT_NAME, AccessNet::ConnectTcp)?.iter())?
        .restrict_self()
        .expect("Failed to enforce ruleset");

    if status.ruleset == RulesetStatus::NotEnforced {
        bail!("Landlock is not supported by the running kernel.");
    }

    Err(Command::new(cmd_name)
        .env_remove(ENV_FS_RO_NAME)
        .env_remove(ENV_FS_RW_NAME)
        .env_remove(ENV_TCP_BIND_NAME)
        .env_remove(ENV_TCP_CONNECT_NAME)
        .args(args)
        .exec()
        .into())
}
