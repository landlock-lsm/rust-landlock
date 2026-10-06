// SPDX-License-Identifier: Apache-2.0 OR MIT

// This is an idiomatic Rust rewrite of a C example:
// https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/samples/landlock/sandboxer.c

use anyhow::{anyhow, bail, Context};
use landlock::{
    path_beneath_rules, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible,
    LandlockStatus, NetPort, PathBeneath, PathFd, Rule, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus, Scope, ABI,
};
use std::env;
use std::ffi::OsStr;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::CommandExt;
use std::process::Command;

const ENV_FS_RO_NAME: &str = "LL_FS_RO";
const ENV_FS_RW_NAME: &str = "LL_FS_RW";
const ENV_FS_QUIET_NAME: &str = "LL_FS_QUIET";
const ENV_TCP_BIND_NAME: &str = "LL_TCP_BIND";
const ENV_TCP_CONNECT_NAME: &str = "LL_TCP_CONNECT";
const ENV_UDP_BIND_NAME: &str = "LL_UDP_BIND";
const ENV_UDP_CONNECT_SEND_NAME: &str = "LL_UDP_CONNECT_SEND";
const ENV_NET_QUIET_NAME: &str = "LL_NET_QUIET";
const ENV_SCOPED_NAME: &str = "LL_SCOPED";
const ENV_QUIET_ACCESS_NAME: &str = "LL_QUIET_ACCESS";
const ENV_FORCE_LOG_NAME: &str = "LL_FORCE_LOG";

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
    fn new<'a>(name: &'a str, access: BitFlags<AccessFs>) -> anyhow::Result<Self> {
        Ok(Self {
            paths: env::var_os(name)
                .ok_or(anyhow!("missing environment variable {name}"))?
                .into_vec(),
            access,
        })
    }

    fn iter(&self) -> impl Iterator<Item = anyhow::Result<PathBeneath<PathFd>>> + '_ {
        let is_empty = self.paths.is_empty();
        path_beneath_rules(
            self.paths
                .split(|b| *b == b':')
                // Skips the first empty element of an empty string.
                .skip_while(move |_| is_empty)
                .map(OsStr::from_bytes),
            self.access,
        )
        .map(|r| Ok(r?))
    }
}

struct PortEnv {
    ports: Vec<u8>,
    access: BitFlags<AccessNet>,
}

impl PortEnv {
    fn new<A>(name: &str, access: A) -> anyhow::Result<Self>
    where
        A: Into<BitFlags<AccessNet>>,
    {
        Ok(Self {
            ports: env::var_os(name).unwrap_or_default().into_vec(),
            access: access.into(),
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

#[derive(Default)]
struct QuietAccess {
    fs: BitFlags<AccessFs>,
    net: BitFlags<AccessNet>,
    scoped: BitFlags<Scope>,
}

impl QuietAccess {
    fn from_env(
        abi: ABI,
        handled_net: BitFlags<AccessNet>,
        scoped: BitFlags<Scope>,
    ) -> anyhow::Result<Self> {
        let mut quiet = Self::default();
        let Some(value) = env::var_os(ENV_QUIET_ACCESS_NAME) else {
            return Ok(quiet);
        };
        let handled_fs = AccessFs::from_all(abi);
        let read_fs = AccessFs::from_read(abi);
        let write_fs = handled_fs & !read_fs;
        for access in value.to_string_lossy().split(':').filter(|v| !v.is_empty()) {
            match access {
                "all" => {
                    quiet.fs = handled_fs;
                    quiet.net = handled_net;
                    quiet.scoped = scoped;
                }
                "read" => quiet.fs |= read_fs,
                "write" => quiet.fs |= write_fs,
                "tcp_bind" => quiet.net |= AccessNet::BindTcp,
                "tcp_connect" => quiet.net |= AccessNet::ConnectTcp,
                "udp_bind" => quiet.net |= AccessNet::BindUdp,
                "udp_connect" => quiet.net |= AccessNet::ConnectSendUdp,
                "abstract_unix_socket" => quiet.scoped |= Scope::AbstractUnixSocket,
                "signal" => quiet.scoped |= Scope::Signal,
                _ => bail!("Unknown quiet access \"{access}\""),
            }
        }
        quiet.fs &= handled_fs;
        quiet.net &= handled_net;
        quiet.scoped &= scoped;
        Ok(quiet)
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
            "usage: {ENV_FS_RO_NAME}=\"...\" {ENV_FS_RW_NAME}=\"...\" [other environment variables] {program_name} <cmd> [args]...\n"
        );
        eprintln!("Execute the given command in a restricted environment.");
        eprintln!("Multi-valued settings (lists of ports, paths, scopes) are colon-delimited.\n");
        eprintln!("Mandatory settings:");
        eprintln!("* {ENV_FS_RO_NAME}: paths allowed to be used in a read-only way");
        eprintln!("* {ENV_FS_RW_NAME}: paths allowed to be used in a read-write way\n");
        eprintln!("Optional settings (when not set, their associated access check is always allowed, which is different from an empty string which means an empty list):");
        eprintln!("* {ENV_TCP_BIND_NAME}: ports allowed to bind (server)");
        eprintln!("* {ENV_TCP_CONNECT_NAME}: ports allowed to connect (client)");
        eprintln!("* {ENV_UDP_BIND_NAME}: local UDP ports allowed to bind (server: prepare to receive on port / client: set as source port)");
        eprintln!("  (0 = any ephemeral port)");
        eprintln!("* {ENV_UDP_CONNECT_SEND_NAME}: remote UDP ports allowed to connect or send to (client: use as destination port / server: receive only from it)");
        eprintln!("  (if {ENV_UDP_BIND_NAME} is set, it must grant a local source port)");
        eprintln!("* {ENV_SCOPED_NAME}: actions denied on the outside of the Landlock domain:");
        eprintln!("  - \"a\" to restrict opening abstract unix sockets");
        eprintln!("  - \"s\" to restrict sending signals");
        eprintln!(
            "\nA sandboxer should not log denied access requests to avoid spamming logs, \
            but to test audit we can set {ENV_FORCE_LOG_NAME}=1"
        );
        eprintln!("{ENV_FS_QUIET_NAME} and {ENV_NET_QUIET_NAME} can list denied paths or network ports that should not trigger audit logging.");
        eprintln!("{ENV_QUIET_ACCESS_NAME} selects which accesses should be quieted and is required when either quiet object list is set:");
        eprintln!("  - \"all\" to quiet all of the accesses below");
        eprintln!("  - \"read\" to quiet all file/directory read accesses");
        eprintln!("  - \"write\" to quiet all file/directory write accesses");
        eprintln!("  - \"tcp_bind\" to quiet TCP bind denials");
        eprintln!("  - \"tcp_connect\" to quiet TCP connect denials");
        eprintln!("  - \"udp_bind\" to quiet UDP bind denials");
        eprintln!("  - \"udp_connect\" to quiet UDP connect/send denials");
        eprintln!("  - \"abstract_unix_socket\" to quiet abstract UNIX socket denials");
        eprintln!("  - \"signal\" to quiet signal denials\n");
        eprintln!(
            "Example:\n\
                {ENV_FS_RO_NAME}=\"${{PATH}}:/lib:/usr:/proc:/etc:/dev/urandom\" \
                {ENV_FS_RW_NAME}=\"/dev/null:/dev/full:/dev/zero:/dev/pts:/tmp\" \
                {ENV_TCP_BIND_NAME}=\"9418\" \
                {ENV_TCP_CONNECT_NAME}=\"80:443\" \
                {ENV_UDP_BIND_NAME}=\"0\" \
                {ENV_UDP_CONNECT_SEND_NAME}=\"53\" \
                {ENV_SCOPED_NAME}=\"a:s\" \
                {program_name} bash -i\n"
        );
        anyhow!("Missing command")
    })?;

    let abi = ABI::V10;
    let mut ruleset = Ruleset::default().handle_access(AccessFs::from_all(abi))?;
    let ruleset_ref = &mut ruleset;
    let mut handled_net = BitFlags::<AccessNet>::EMPTY;

    if env::var_os(ENV_TCP_BIND_NAME).is_some() {
        handled_net |= AccessNet::BindTcp;
        ruleset_ref.handle_access(AccessNet::BindTcp)?;
    }
    if env::var_os(ENV_TCP_CONNECT_NAME).is_some() {
        handled_net |= AccessNet::ConnectTcp;
        ruleset_ref.handle_access(AccessNet::ConnectTcp)?;
    }
    if env::var_os(ENV_UDP_BIND_NAME).is_some() {
        handled_net |= AccessNet::BindUdp;
        ruleset_ref.handle_access(AccessNet::BindUdp)?;
    }
    if env::var_os(ENV_UDP_CONNECT_SEND_NAME).is_some() {
        handled_net |= AccessNet::ConnectSendUdp;
        ruleset_ref.handle_access(AccessNet::ConnectSendUdp)?;
    }

    let mut scoped_access = BitFlags::<Scope>::EMPTY;
    if let Some(scoped) = env::var_os(ENV_SCOPED_NAME) {
        let mut abstract_scoping = false;
        let mut signal_scoping = false;
        let scopes = scoped.to_string_lossy();
        let is_empty = scopes.is_empty();
        for scope in scopes.split(':').skip_while(move |_| is_empty) {
            match scope {
                "a" => {
                    if abstract_scoping {
                        bail!("Duplicate scope 'a'");
                    }
                    scoped_access |= Scope::AbstractUnixSocket;
                    ruleset_ref.scope(Scope::AbstractUnixSocket)?;
                    abstract_scoping = true;
                }
                "s" => {
                    if signal_scoping {
                        bail!("Duplicate scope 's'");
                    }
                    scoped_access |= Scope::Signal;
                    ruleset_ref.scope(Scope::Signal)?;
                    signal_scoping = true;
                }
                _ => bail!("Unknown scope \"{scope}\""),
            }
        }
    }

    if (env::var_os(ENV_FS_QUIET_NAME).is_some() || env::var_os(ENV_NET_QUIET_NAME).is_some())
        && env::var_os(ENV_QUIET_ACCESS_NAME).is_none()
    {
        bail!(
            "{ENV_QUIET_ACCESS_NAME} must be set (e.g. to \"all\") when \
             {ENV_FS_QUIET_NAME} or {ENV_NET_QUIET_NAME} is used"
        );
    }
    let quiet = QuietAccess::from_env(abi, handled_net, scoped_access)?;
    if env::var_os(ENV_QUIET_ACCESS_NAME).is_some()
        && quiet.fs.is_empty()
        && quiet.net.is_empty()
        && quiet.scoped.is_empty()
    {
        // The kernel sample rejects any quiet setting before ABI v10, even when
        // intersecting it with the configured accesses produces empty masks.
        Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::Execute)?
            .quiet_access(AccessFs::Execute)?;
    }
    ruleset_ref.set_compatibility(CompatLevel::HardRequirement);
    if !quiet.fs.is_empty() {
        ruleset_ref.quiet_access(quiet.fs)?;
    }
    if !quiet.net.is_empty() {
        ruleset_ref.quiet_access(quiet.net)?;
    }
    if !quiet.scoped.is_empty() {
        ruleset_ref.quiet_scope(quiet.scoped)?;
    }
    ruleset_ref.set_compatibility(CompatLevel::BestEffort);

    // Parse LL_FORCE_LOG into a boolean.  Matches the kernel's sandboxer:
    // when set, require the feature (error out on unsupported kernels).
    let force_log = match env::var_os(ENV_FORCE_LOG_NAME) {
        Some(v) if v == "1" => true,
        Some(_) => bail!("Unknown value for {ENV_FORCE_LOG_NAME} (only \"1\" is handled)"),
        None => false,
    };

    let mut ruleset_created = ruleset
        .create()?
        .add_rules(PathEnv::new(ENV_FS_RO_NAME, AccessFs::from_read(abi))?.iter())?
        .add_rules(PathEnv::new(ENV_FS_RW_NAME, AccessFs::from_all(abi))?.iter())?;
    if env::var_os(ENV_FS_QUIET_NAME).is_some() {
        ruleset_created = ruleset_created.add_rules(
            PathEnv::new(ENV_FS_QUIET_NAME, BitFlags::<AccessFs>::EMPTY)?
                .iter()
                .map(|rule| rule.map(|rule| rule.quiet(true))),
        )?;
    }
    ruleset_created = ruleset_created
        .add_rules(PortEnv::new(ENV_TCP_BIND_NAME, AccessNet::BindTcp)?.iter())?
        .add_rules(PortEnv::new(ENV_TCP_CONNECT_NAME, AccessNet::ConnectTcp)?.iter())?
        .add_rules(PortEnv::new(ENV_UDP_BIND_NAME, AccessNet::BindUdp)?.iter())?
        .add_rules(PortEnv::new(ENV_UDP_CONNECT_SEND_NAME, AccessNet::ConnectSendUdp)?.iter())?
        .add_rules(
            PortEnv::new(ENV_NET_QUIET_NAME, BitFlags::<AccessNet>::EMPTY)?
                .iter()
                .map(|rule| rule.map(|rule| rule.quiet(true))),
        )?;

    let status = ruleset_created
        .set_compatibility(CompatLevel::HardRequirement)
        .log_new_exec(force_log)?
        .set_compatibility(CompatLevel::BestEffort)
        .restrict_self()
        .expect("Failed to enforce ruleset");

    match status.landlock {
        // This should never happen because of the previous check:
        LandlockStatus::NotEnabled => {
            eprintln!(
                "Hint: Landlock is currently disabled. \
                It can be enabled in the kernel configuration by prepending \"landlock,\"
                to the content of CONFIG_LSM, or at boot time by setting the same content to
                the \"lsm\" kernel parameter."
            );
        }
        LandlockStatus::NotImplemented => {
            eprintln!(
                "Hint: Landlock is not built into the current kernel. \
                To support it, build the kernel with CONFIG_SECURITY_LANDLOCK=y and \
                prepend \"landlock,\" to the content of CONFIG_LSM."
            );
        }
        LandlockStatus::Available {
            kernel_abi: Some(raw_abi),
            ..
        } => {
            eprintln!(
                "Hint: This sandboxer only supports Landlock ABI version up to {abi} \
                whereas the current kernel supports Landlock ABI version {raw_abi}. \
                To leverage all Landlock features, update this sandboxer."
            );
        }
        LandlockStatus::Available {
            kernel_abi: None,
            effective_abi,
        } => {
            if effective_abi < abi {
                eprintln!(
                    "Hint: This sandboxer supports Landlock ABI version up to {abi} \
                    but the current kernel only supports Landlock ABI version {effective_abi}. \
                    To leverage all Landlock features, update the kernel."
                );
            } else if effective_abi > abi {
                // This should not happen because the ABI used by the sandboxer
                // should be the latest supported by the Landlock crate, and
                // they should be updated at the same time.
                eprintln!(
                    "Warning: This sandboxer only supports Landlock ABI version up to {abi} \
                    but the current kernel supports Landlock ABI version {effective_abi}. \
                    To leverage all Landlock features, update this sandboxer."
                );
            }
        }
    }
    if status.ruleset == RulesetStatus::NotEnforced {
        bail!("The ruleset cannot be enforced at all");
    }

    eprintln!("Executing the sandboxed command...");
    Err(Command::new(cmd_name)
        .env_remove(ENV_FS_RO_NAME)
        .env_remove(ENV_FS_RW_NAME)
        .env_remove(ENV_FS_QUIET_NAME)
        .env_remove(ENV_TCP_BIND_NAME)
        .env_remove(ENV_TCP_CONNECT_NAME)
        .env_remove(ENV_UDP_BIND_NAME)
        .env_remove(ENV_UDP_CONNECT_SEND_NAME)
        .env_remove(ENV_NET_QUIET_NAME)
        .env_remove(ENV_SCOPED_NAME)
        .env_remove(ENV_QUIET_ACCESS_NAME)
        .env_remove(ENV_FORCE_LOG_NAME)
        .args(args)
        .exec()
        .into())
}
