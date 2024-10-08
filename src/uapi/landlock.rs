/* automatically generated by rust-bindgen 0.69.4 */

pub const __BITS_PER_LONG: u32 = 64;
pub const __BITS_PER_LONG_LONG: u32 = 64;
pub const __FD_SETSIZE: u32 = 1024;
pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
pub const LANDLOCK_ACCESS_FS_EXECUTE: u32 = 1;
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u32 = 2;
pub const LANDLOCK_ACCESS_FS_READ_FILE: u32 = 4;
pub const LANDLOCK_ACCESS_FS_READ_DIR: u32 = 8;
pub const LANDLOCK_ACCESS_FS_REMOVE_DIR: u32 = 16;
pub const LANDLOCK_ACCESS_FS_REMOVE_FILE: u32 = 32;
pub const LANDLOCK_ACCESS_FS_MAKE_CHAR: u32 = 64;
pub const LANDLOCK_ACCESS_FS_MAKE_DIR: u32 = 128;
pub const LANDLOCK_ACCESS_FS_MAKE_REG: u32 = 256;
pub const LANDLOCK_ACCESS_FS_MAKE_SOCK: u32 = 512;
pub const LANDLOCK_ACCESS_FS_MAKE_FIFO: u32 = 1024;
pub const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u32 = 2048;
pub const LANDLOCK_ACCESS_FS_MAKE_SYM: u32 = 4096;
pub const LANDLOCK_ACCESS_FS_REFER: u32 = 8192;
pub const LANDLOCK_ACCESS_FS_TRUNCATE: u32 = 16384;
pub const LANDLOCK_ACCESS_FS_IOCTL_DEV: u32 = 32768;
pub const LANDLOCK_ACCESS_NET_BIND_TCP: u32 = 1;
pub const LANDLOCK_ACCESS_NET_CONNECT_TCP: u32 = 2;
pub type __s8 = ::std::os::raw::c_schar;
pub type __u8 = ::std::os::raw::c_uchar;
pub type __s16 = ::std::os::raw::c_short;
pub type __u16 = ::std::os::raw::c_ushort;
pub type __s32 = ::std::os::raw::c_int;
pub type __u32 = ::std::os::raw::c_uint;
pub type __s64 = ::std::os::raw::c_longlong;
pub type __u64 = ::std::os::raw::c_ulonglong;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __kernel_fd_set {
    pub fds_bits: [::std::os::raw::c_ulong; 16usize],
}
#[test]
fn bindgen_test_layout___kernel_fd_set() {
    const UNINIT: ::std::mem::MaybeUninit<__kernel_fd_set> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<__kernel_fd_set>(),
        128usize,
        concat!("Size of: ", stringify!(__kernel_fd_set))
    );
    assert_eq!(
        ::std::mem::align_of::<__kernel_fd_set>(),
        8usize,
        concat!("Alignment of ", stringify!(__kernel_fd_set))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).fds_bits) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(__kernel_fd_set),
            "::",
            stringify!(fds_bits)
        )
    );
}
pub type __kernel_sighandler_t =
    ::std::option::Option<unsafe extern "C" fn(arg1: ::std::os::raw::c_int)>;
pub type __kernel_key_t = ::std::os::raw::c_int;
pub type __kernel_mqd_t = ::std::os::raw::c_int;
pub type __kernel_old_uid_t = ::std::os::raw::c_ushort;
pub type __kernel_old_gid_t = ::std::os::raw::c_ushort;
pub type __kernel_old_dev_t = ::std::os::raw::c_ulong;
pub type __kernel_long_t = ::std::os::raw::c_long;
pub type __kernel_ulong_t = ::std::os::raw::c_ulong;
pub type __kernel_ino_t = __kernel_ulong_t;
pub type __kernel_mode_t = ::std::os::raw::c_uint;
pub type __kernel_pid_t = ::std::os::raw::c_int;
pub type __kernel_ipc_pid_t = ::std::os::raw::c_int;
pub type __kernel_uid_t = ::std::os::raw::c_uint;
pub type __kernel_gid_t = ::std::os::raw::c_uint;
pub type __kernel_suseconds_t = __kernel_long_t;
pub type __kernel_daddr_t = ::std::os::raw::c_int;
pub type __kernel_uid32_t = ::std::os::raw::c_uint;
pub type __kernel_gid32_t = ::std::os::raw::c_uint;
pub type __kernel_size_t = __kernel_ulong_t;
pub type __kernel_ssize_t = __kernel_long_t;
pub type __kernel_ptrdiff_t = __kernel_long_t;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __kernel_fsid_t {
    pub val: [::std::os::raw::c_int; 2usize],
}
#[test]
fn bindgen_test_layout___kernel_fsid_t() {
    const UNINIT: ::std::mem::MaybeUninit<__kernel_fsid_t> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<__kernel_fsid_t>(),
        8usize,
        concat!("Size of: ", stringify!(__kernel_fsid_t))
    );
    assert_eq!(
        ::std::mem::align_of::<__kernel_fsid_t>(),
        4usize,
        concat!("Alignment of ", stringify!(__kernel_fsid_t))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).val) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(__kernel_fsid_t),
            "::",
            stringify!(val)
        )
    );
}
pub type __kernel_off_t = __kernel_long_t;
pub type __kernel_loff_t = ::std::os::raw::c_longlong;
pub type __kernel_old_time_t = __kernel_long_t;
pub type __kernel_time_t = __kernel_long_t;
pub type __kernel_time64_t = ::std::os::raw::c_longlong;
pub type __kernel_clock_t = __kernel_long_t;
pub type __kernel_timer_t = ::std::os::raw::c_int;
pub type __kernel_clockid_t = ::std::os::raw::c_int;
pub type __kernel_caddr_t = *mut ::std::os::raw::c_char;
pub type __kernel_uid16_t = ::std::os::raw::c_ushort;
pub type __kernel_gid16_t = ::std::os::raw::c_ushort;
pub type __s128 = i128;
pub type __u128 = u128;
pub type __le16 = __u16;
pub type __be16 = __u16;
pub type __le32 = __u32;
pub type __be32 = __u32;
pub type __le64 = __u64;
pub type __be64 = __u64;
pub type __sum16 = __u16;
pub type __wsum = __u32;
pub type __poll_t = ::std::os::raw::c_uint;
#[doc = " struct landlock_ruleset_attr - Ruleset definition\n\n Argument of sys_landlock_create_ruleset().  This structure can grow in\n future versions."]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct landlock_ruleset_attr {
    #[doc = " @handled_access_fs: Bitmask of actions (cf. `Filesystem flags`_)\n that is handled by this ruleset and should then be forbidden if no\n rule explicitly allow them: it is a deny-by-default list that should\n contain as much Landlock access rights as possible. Indeed, all\n Landlock filesystem access rights that are not part of\n handled_access_fs are allowed.  This is needed for backward\n compatibility reasons.  One exception is the\n %LANDLOCK_ACCESS_FS_REFER access right, which is always implicitly\n handled, but must still be explicitly handled to add new rules with\n this access right."]
    pub handled_access_fs: __u64,
    #[doc = " @handled_access_net: Bitmask of actions (cf. `Network flags`_)\n that is handled by this ruleset and should then be forbidden if no\n rule explicitly allow them."]
    pub handled_access_net: __u64,
}
#[test]
fn bindgen_test_layout_landlock_ruleset_attr() {
    const UNINIT: ::std::mem::MaybeUninit<landlock_ruleset_attr> =
        ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<landlock_ruleset_attr>(),
        16usize,
        concat!("Size of: ", stringify!(landlock_ruleset_attr))
    );
    assert_eq!(
        ::std::mem::align_of::<landlock_ruleset_attr>(),
        8usize,
        concat!("Alignment of ", stringify!(landlock_ruleset_attr))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).handled_access_fs) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(landlock_ruleset_attr),
            "::",
            stringify!(handled_access_fs)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).handled_access_net) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(landlock_ruleset_attr),
            "::",
            stringify!(handled_access_net)
        )
    );
}
#[doc = " @LANDLOCK_RULE_PATH_BENEATH: Type of a &struct\n landlock_path_beneath_attr ."]
pub const landlock_rule_type_LANDLOCK_RULE_PATH_BENEATH: landlock_rule_type = 1;
#[doc = " @LANDLOCK_RULE_NET_PORT: Type of a &struct\n landlock_net_port_attr ."]
pub const landlock_rule_type_LANDLOCK_RULE_NET_PORT: landlock_rule_type = 2;
#[doc = " enum landlock_rule_type - Landlock rule type\n\n Argument of sys_landlock_add_rule()."]
pub type landlock_rule_type = ::std::os::raw::c_uint;
#[doc = " struct landlock_path_beneath_attr - Path hierarchy definition\n\n Argument of sys_landlock_add_rule()."]
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct landlock_path_beneath_attr {
    #[doc = " @allowed_access: Bitmask of allowed actions for this file hierarchy\n (cf. `Filesystem flags`_)."]
    pub allowed_access: __u64,
    #[doc = " @parent_fd: File descriptor, preferably opened with ``O_PATH``,\n which identifies the parent directory of a file hierarchy, or just a\n file."]
    pub parent_fd: __s32,
}
#[test]
fn bindgen_test_layout_landlock_path_beneath_attr() {
    const UNINIT: ::std::mem::MaybeUninit<landlock_path_beneath_attr> =
        ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<landlock_path_beneath_attr>(),
        12usize,
        concat!("Size of: ", stringify!(landlock_path_beneath_attr))
    );
    assert_eq!(
        ::std::mem::align_of::<landlock_path_beneath_attr>(),
        1usize,
        concat!("Alignment of ", stringify!(landlock_path_beneath_attr))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).allowed_access) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(landlock_path_beneath_attr),
            "::",
            stringify!(allowed_access)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).parent_fd) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(landlock_path_beneath_attr),
            "::",
            stringify!(parent_fd)
        )
    );
}
#[doc = " struct landlock_net_port_attr - Network port definition\n\n Argument of sys_landlock_add_rule()."]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct landlock_net_port_attr {
    #[doc = " @allowed_access: Bitmask of allowed access network for a port\n (cf. `Network flags`_)."]
    pub allowed_access: __u64,
    #[doc = " @port: Network port in host endianness.\n\n It should be noted that port 0 passed to :manpage:`bind(2)` will\n bind to an available port from a specific port range. This can be\n configured thanks to the ``/proc/sys/net/ipv4/ip_local_port_range``\n sysctl (also used for IPv6). A Landlock rule with port 0 and the\n ``LANDLOCK_ACCESS_NET_BIND_TCP`` right means that requesting to bind\n on port 0 is allowed and it will automatically translate to binding\n on the related port range."]
    pub port: __u64,
}
#[test]
fn bindgen_test_layout_landlock_net_port_attr() {
    const UNINIT: ::std::mem::MaybeUninit<landlock_net_port_attr> =
        ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<landlock_net_port_attr>(),
        16usize,
        concat!("Size of: ", stringify!(landlock_net_port_attr))
    );
    assert_eq!(
        ::std::mem::align_of::<landlock_net_port_attr>(),
        8usize,
        concat!("Alignment of ", stringify!(landlock_net_port_attr))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).allowed_access) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(landlock_net_port_attr),
            "::",
            stringify!(allowed_access)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).port) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(landlock_net_port_attr),
            "::",
            stringify!(port)
        )
    );
}
