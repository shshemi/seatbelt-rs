//! Integration tests exercising every public `Sandbox` method except `init`.
//!
//! Each test drives the builder through the public API and checks the emitted
//! SBPL with [`seatbelt_rs::Sandbox::to_sbpl`]. Operation methods are grouped by
//! the macro that generates them; filter methods (shared within a group) are
//! covered once per group on a representative operation.

use regex::Regex;
use seatbelt_rs::{Proto, Sandbox};

const ALLOW_HEADER: &str = "(version 1)\n(allow default)\n";
const DENY_HEADER: &str = "(version 1)\n(deny default)\n";

// ── constructors / actions ──────────────────────────────────────────────

#[test]
fn allow_by_default_constructor() {
    assert_eq!(Sandbox::allow_by_default().to_sbpl(), ALLOW_HEADER);
}

#[test]
fn deny_by_default_constructor() {
    assert_eq!(Sandbox::deny_by_default().to_sbpl(), DENY_HEADER);
}

#[test]
fn allow_and_deny_actions() {
    assert_eq!(
        Sandbox::deny_by_default()
            .allow()
            .file_read()
            .any()
            .deny()
            .file_write()
            .any()
            .to_sbpl(),
        &format!("{DENY_HEADER}(allow file-read*)\n(deny file-write*)\n")
    );
}

// ── file operations ─────────────────────────────────────────────────────

#[test]
fn every_file_operation() {
    let sbpl = Sandbox::deny_by_default()
        .allow()
        .file_chroot()
        .any()
        .allow()
        .file_fsctl()
        .any()
        .allow()
        .file_ioctl()
        .any()
        .allow()
        .file_issue_extension()
        .any()
        .allow()
        .file_link()
        .any()
        .allow()
        .file_map_executable()
        .any()
        .allow()
        .file_mknod()
        .any()
        .allow()
        .file_read()
        .any()
        .allow()
        .file_read_data()
        .any()
        .allow()
        .file_read_metadata()
        .any()
        .allow()
        .file_read_xattr()
        .any()
        .allow()
        .file_revoke()
        .any()
        .allow()
        .file_search()
        .any()
        .allow()
        .file_write()
        .any()
        .allow()
        .file_write_create()
        .any()
        .allow()
        .file_write_data()
        .any()
        .allow()
        .file_write_flags()
        .any()
        .allow()
        .file_write_mode()
        .any()
        .allow()
        .file_write_mount()
        .any()
        .allow()
        .file_write_owner()
        .any()
        .allow()
        .file_write_setugid()
        .any()
        .allow()
        .file_write_times()
        .any()
        .allow()
        .file_write_umount()
        .any()
        .allow()
        .file_write_unlink()
        .any()
        .allow()
        .file_write_xattr()
        .any()
        .to_sbpl()
        .to_owned();

    assert_eq!(
        sbpl,
        "(version 1)\n\
         (deny default)\n\
         (allow file-chroot)\n\
         (allow file-fsctl)\n\
         (allow file-ioctl)\n\
         (allow file-issue-extension)\n\
         (allow file-link)\n\
         (allow file-map-executable)\n\
         (allow file-mknod)\n\
         (allow file-read*)\n\
         (allow file-read-data)\n\
         (allow file-read-metadata)\n\
         (allow file-read-xattr)\n\
         (allow file-revoke)\n\
         (allow file-search)\n\
         (allow file-write*)\n\
         (allow file-write-create)\n\
         (allow file-write-data)\n\
         (allow file-write-flags)\n\
         (allow file-write-mode)\n\
         (allow file-write-mount)\n\
         (allow file-write-owner)\n\
         (allow file-write-setugid)\n\
         (allow file-write-times)\n\
         (allow file-write-umount)\n\
         (allow file-write-unlink)\n\
         (allow file-write-xattr)\n"
    );
}

#[test]
fn file_filters() {
    let re = Regex::new(r"^/d$").unwrap();
    let sbpl = Sandbox::deny_by_default()
        .allow()
        .file_read()
        .literal("/a")
        .allow()
        .file_read()
        .prefix("/b")
        .allow()
        .file_read()
        .subpath("/c")
        .allow()
        .file_read()
        .regex(re)
        .allow()
        .file_read()
        .any()
        .to_sbpl()
        .to_owned();

    assert_eq!(
        sbpl,
        "(version 1)\n\
         (deny default)\n\
         (allow file-read* (literal \"/a\"))\n\
         (allow file-read* (prefix \"/b\"))\n\
         (allow file-read* (subpath \"/c\"))\n\
         (allow file-read* (regex #\"^/d$\"))\n\
         (allow file-read*)\n"
    );
}

#[test]
fn file_filters_escape_quotes_and_backslashes() {
    assert_eq!(
        Sandbox::deny_by_default()
            .allow()
            .file_read()
            .literal(r#"/odd"path\here"#)
            .to_sbpl(),
        &format!("{DENY_HEADER}(allow file-read* (literal \"/odd\\\"path\\\\here\"))\n")
    );
}

// ── process / system-socket ─────────────────────────────────────────────

#[test]
fn process_and_system_socket_operations() {
    let sbpl = Sandbox::deny_by_default()
        .allow()
        .process_exec()
        .literal("/bin/ls")
        .allow()
        .process_exec()
        .any()
        .allow()
        .process_fork()
        .allow()
        .system_socket()
        .to_sbpl()
        .to_owned();

    assert_eq!(
        sbpl,
        "(version 1)\n\
         (deny default)\n\
         (allow process-exec (literal \"/bin/ls\"))\n\
         (allow process-exec)\n\
         (allow process-fork)\n\
         (allow system-socket)\n"
    );
}

// ── mach (filtered) ─────────────────────────────────────────────────────

#[test]
fn mach_filtered_operations() {
    assert_eq!(
        Sandbox::deny_by_default()
            .allow()
            .mach_lookup()
            .any()
            .allow()
            .mach_register()
            .any()
            .to_sbpl(),
        &format!("{DENY_HEADER}(allow mach-lookup)\n(allow mach-register)\n")
    );
}

#[test]
fn mach_filters() {
    let g = Regex::new(r"^g$").unwrap();
    let l = Regex::new(r"^l$").unwrap();
    let sbpl = Sandbox::deny_by_default()
        .allow()
        .mach_lookup()
        .global_name("com.apple.g")
        .allow()
        .mach_lookup()
        .local_name("com.apple.l")
        .allow()
        .mach_lookup()
        .global_name_regex(g)
        .allow()
        .mach_lookup()
        .local_name_regex(l)
        .allow()
        .mach_lookup()
        .any()
        .to_sbpl()
        .to_owned();

    assert_eq!(
        sbpl,
        "(version 1)\n\
         (deny default)\n\
         (allow mach-lookup (global-name \"com.apple.g\"))\n\
         (allow mach-lookup (local-name \"com.apple.l\"))\n\
         (allow mach-lookup (global-name-regex #\"^g$\"))\n\
         (allow mach-lookup (local-name-regex #\"^l$\"))\n\
         (allow mach-lookup)\n"
    );
}

// ── mach (bare) ─────────────────────────────────────────────────────────

#[test]
fn every_bare_mach_operation() {
    let sbpl = Sandbox::deny_by_default()
        .allow()
        .mach_bootstrap()
        .allow()
        .mach_cross_domain_lookup()
        .allow()
        .mach_derive_port()
        .allow()
        .mach_host_special_port_set()
        .allow()
        .mach_issue_extension()
        .allow()
        .mach_per_user_lookup()
        .allow()
        .mach_priv_host_port()
        .allow()
        .mach_priv_task_port()
        .allow()
        .mach_task_name()
        .to_sbpl()
        .to_owned();

    assert_eq!(
        sbpl,
        "(version 1)\n\
         (deny default)\n\
         (allow mach-bootstrap)\n\
         (allow mach-cross-domain-lookup)\n\
         (allow mach-derive-port)\n\
         (allow mach-host-special-port-set)\n\
         (allow mach-issue-extension)\n\
         (allow mach-per-user-lookup)\n\
         (allow mach-priv-host-port)\n\
         (allow mach-priv-task-port)\n\
         (allow mach-task-name)\n"
    );
}

// ── ipc ─────────────────────────────────────────────────────────────────

#[test]
fn every_ipc_operation() {
    let sbpl = Sandbox::deny_by_default()
        .allow()
        .ipc_posix_sem()
        .any()
        .allow()
        .ipc_posix_sem_create()
        .any()
        .allow()
        .ipc_posix_sem_open()
        .any()
        .allow()
        .ipc_posix_sem_post()
        .any()
        .allow()
        .ipc_posix_sem_unlink()
        .any()
        .allow()
        .ipc_posix_sem_wait()
        .any()
        .allow()
        .ipc_posix_shm()
        .any()
        .allow()
        .ipc_posix_shm_read()
        .any()
        .allow()
        .ipc_posix_shm_read_data()
        .any()
        .allow()
        .ipc_posix_shm_read_metadata()
        .any()
        .allow()
        .ipc_posix_shm_write()
        .any()
        .allow()
        .ipc_posix_shm_write_create()
        .any()
        .allow()
        .ipc_posix_shm_write_data()
        .any()
        .allow()
        .ipc_posix_shm_write_unlink()
        .any()
        .to_sbpl()
        .to_owned();

    assert_eq!(
        sbpl,
        "(version 1)\n\
         (deny default)\n\
         (allow ipc-posix-sem*)\n\
         (allow ipc-posix-sem-create)\n\
         (allow ipc-posix-sem-open)\n\
         (allow ipc-posix-sem-post)\n\
         (allow ipc-posix-sem-unlink)\n\
         (allow ipc-posix-sem-wait)\n\
         (allow ipc-posix-shm*)\n\
         (allow ipc-posix-shm-read*)\n\
         (allow ipc-posix-shm-read-data)\n\
         (allow ipc-posix-shm-read-metadata)\n\
         (allow ipc-posix-shm-write*)\n\
         (allow ipc-posix-shm-write-create)\n\
         (allow ipc-posix-shm-write-data)\n\
         (allow ipc-posix-shm-write-unlink)\n"
    );
}

#[test]
fn ipc_filters() {
    let re = Regex::new(r"^/com\.app\.").unwrap();
    let sbpl = Sandbox::deny_by_default()
        .allow()
        .ipc_posix_sem()
        .name("mysem")
        .allow()
        .ipc_posix_shm()
        .regex(re)
        .allow()
        .ipc_posix_shm()
        .any()
        .to_sbpl()
        .to_owned();

    assert_eq!(
        sbpl,
        "(version 1)\n\
         (deny default)\n\
         (allow ipc-posix-sem* (ipc-posix-name \"mysem\"))\n\
         (allow ipc-posix-shm* (ipc-posix-name-regex #\"^/com\\.app\\.\"))\n\
         (allow ipc-posix-shm*)\n"
    );
}

// ── sysctl ──────────────────────────────────────────────────────────────

#[test]
fn sysctl_operations_and_filters() {
    let re = Regex::new(r"^kern\.").unwrap();
    let sbpl = Sandbox::deny_by_default()
        .allow()
        .sysctl_read()
        .name("kern.ostype")
        .allow()
        .sysctl_read()
        .regex(re)
        .allow()
        .sysctl_read()
        .any()
        .allow()
        .sysctl_write()
        .any()
        .to_sbpl()
        .to_owned();

    assert_eq!(
        sbpl,
        "(version 1)\n\
         (deny default)\n\
         (allow sysctl-read (sysctl-name \"kern.ostype\"))\n\
         (allow sysctl-read (sysctl-name-regex #\"^kern\\.\"))\n\
         (allow sysctl-read)\n\
         (allow sysctl-write)\n"
    );
}

// ── iokit ───────────────────────────────────────────────────────────────

#[test]
fn iokit_operations_and_filters() {
    let class_re = Regex::new(r"^IOSurface").unwrap();
    let prop_re = Regex::new(r"^Built").unwrap();
    let sbpl = Sandbox::deny_by_default()
        .allow()
        .iokit_open()
        .user_client_class("IOSurfaceRootUserClient")
        .allow()
        .iokit_open()
        .user_client_class_regex(class_re)
        .allow()
        .iokit_open()
        .property("IOServiceName")
        .allow()
        .iokit_open()
        .property_regex(prop_re)
        .allow()
        .iokit_open()
        .any()
        .allow()
        .iokit_set_properties()
        .any()
        .to_sbpl()
        .to_owned();

    assert_eq!(
        sbpl,
        "(version 1)\n\
         (deny default)\n\
         (allow iokit-open (iokit-user-client-class \"IOSurfaceRootUserClient\"))\n\
         (allow iokit-open (iokit-user-client-class-regex #\"^IOSurface\"))\n\
         (allow iokit-open (iokit-property \"IOServiceName\"))\n\
         (allow iokit-open (iokit-property-regex #\"^Built\"))\n\
         (allow iokit-open)\n\
         (allow iokit-set-properties)\n"
    );
}

// ── network ─────────────────────────────────────────────────────────────

#[test]
fn network_operations_filters_and_protocols() {
    let sbpl = Sandbox::deny_by_default()
        .allow()
        .network()
        .local(Proto::Ip, "*:1")
        .allow()
        .network()
        .remote(Proto::Tcp, "*:2")
        .allow()
        .network()
        .any()
        .allow()
        .network_bind()
        .local(Proto::Udp, "*:3")
        .allow()
        .network_inbound()
        .any()
        .allow()
        .network_outbound()
        .remote(Proto::Tcp, "*:443")
        .to_sbpl()
        .to_owned();

    assert_eq!(
        sbpl,
        "(version 1)\n\
         (deny default)\n\
         (allow network* (local ip \"*:1\"))\n\
         (allow network* (remote tcp \"*:2\"))\n\
         (allow network*)\n\
         (allow network-bind (local udp \"*:3\"))\n\
         (allow network-inbound)\n\
         (allow network-outbound (remote tcp \"*:443\"))\n"
    );
}

// ── signal ──────────────────────────────────────────────────────────────

#[test]
fn signal_operation_and_filters() {
    let sbpl = Sandbox::deny_by_default()
        .allow()
        .signal()
        .self_target()
        .allow()
        .signal()
        .others()
        .allow()
        .signal()
        .any()
        .to_sbpl()
        .to_owned();

    assert_eq!(
        sbpl,
        "(version 1)\n\
         (deny default)\n\
         (allow signal (target self))\n\
         (allow signal (target others))\n\
         (allow signal)\n"
    );
}

// ── a realistic, mixed-action policy ────────────────────────────────────

#[test]
fn realistic_mixed_policy() {
    let sbpl = Sandbox::deny_by_default()
        .allow()
        .file_read()
        .subpath("/usr")
        .allow()
        .file_write()
        .subpath("/tmp")
        .allow()
        .network_outbound()
        .remote(Proto::Tcp, "*:443")
        .deny()
        .file_read()
        .prefix("/Users")
        .allow()
        .mach_bootstrap()
        .to_sbpl()
        .to_owned();

    assert_eq!(
        sbpl,
        "(version 1)\n\
         (deny default)\n\
         (allow file-read* (subpath \"/usr\"))\n\
         (allow file-write* (subpath \"/tmp\"))\n\
         (allow network-outbound (remote tcp \"*:443\"))\n\
         (deny file-read* (prefix \"/Users\"))\n\
         (allow mach-bootstrap)\n"
    );
}
