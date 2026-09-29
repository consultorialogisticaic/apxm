//! The kernel boundary the capture child runs inside.
//!
//! Capturing typed intent runs an authoring frontend over submitted source, so
//! the submitted text is evaluated inside an interpreter. Each interpreter
//! carries a confinement of its own — an audit hook and resource limits for
//! Python, a permission model for TypeScript — and those remain the inner wall.
//! This module is the outer wall: the kernel's own answer, applied to the
//! capture child before it execs, so a submitted program that finds a hole in an
//! interpreter still reaches nothing.
//!
//! # What the boundary grants
//!
//! On Linux the child runs inside a Landlock ruleset that grants, and grants
//! nothing else:
//!
//! * read and execute on the authoring frontend package root, on the declared
//!   interpreter driver, and on the driver's own runtime prefix;
//! * read and execute on the shared-library directories the interpreter links
//!   against, and read on the architecture-independent runtime data beside them;
//! * read on `/proc`, on the loader cache, on the local time zone, and on the
//!   random and null devices the interpreters open at start;
//! * read, write and create inside one per-capture scratch directory, which is
//!   the only path in the filesystem the child may write.
//!
//! Everything else — `/etc/passwd`, `/home`, `/root`, `/var`, the artifact
//! directory, the rest of the checkout — is denied by the kernel. No system
//! binary outside the interpreter's own prefix is executable, so a submitted
//! program cannot exec a shell even where it can name one.
//!
//! A seccomp filter denies the child every socket domain but `AF_UNIX`, so the
//! network is closed whichever interpreter is running; denies every way of
//! asking for a new process while leaving thread creation, which both
//! interpreters need; and denies tracing, namespace, module and key-management
//! calls outright.
//!
//! Resource ceilings bound what the child may consume where no rule applies: CPU
//! time, writable data, produced file size, core dumps, and the number of tasks
//! the child may hold.
//!
//! # Threads are not processes
//!
//! Refusing a new process is the filter's job, not a ceiling's. `RLIMIT_NPROC`
//! counts tasks, and on Linux a thread is a task, so a ceiling of zero refuses
//! the first `pthread_create` as surely as the first `fork`: Node's libuv pool
//! and V8 platform threads never start, and the bridge dies inside the
//! interpreter before it reads a request. The ceiling is therefore a thread
//! budget — high enough for both bridges, low enough to bound a thread bomb —
//! while `fork`, `vfork`, `clone` without `CLONE_THREAD` and `clone3` stay
//! refused by the filter, which holds whatever user the service runs as.
//!
//! # The one writable path
//!
//! The scratch directory is the only path capture may write, so it has to exist
//! on a writable filesystem. A service container is normally read-only, which
//! makes the default temporary directory unwritable, so the root the
//! per-capture directory is created under is
//! [`CAPTURE_SCRATCH_DIR_VARIABLE`], and the service image declares a writable
//! mount at its default. The root is created if it is absent, and
//! [`capture_confinement_readiness`] reports it and whether it is writable, so
//! an operator learns of a read-only mount before the first refused compile.
//!
//! # Fail closed
//!
//! [`ConfinementMode::Enforce`] is the default and requires the kernel to
//! provide both Landlock and seccomp filtering. A Linux host without them
//! rejects every capture with `frontend_unavailable` rather than capturing
//! unconfined. `APXM_CAPTURE_CONFINEMENT=permissive` is the development escape:
//! it applies whatever the kernel offers and captures anyway. Any other value of
//! the variable is `enforce`, so a typo does not open the boundary.
//!
//! A host that is not Linux has no such kernel feature to fail closed against.
//! There the boundary is a documented no-op: capture proceeds behind the
//! interpreter-level confinement alone, and [`capture_confinement_readiness`]
//! reports [`ConfinementStatus::UnsupportedPlatform`] so an operator never has
//! to infer it.

#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

use crate::diagnostic::{SourceDiagnostic, SourceDiagnosticCode};

/// The operator flag that selects how a missing kernel feature is answered.
pub const CONFINEMENT_MODE_VARIABLE: &str = "APXM_CAPTURE_CONFINEMENT";

/// The operator flag that names the writable root every per-capture scratch
/// directory is created under. Absent, the platform temporary directory is
/// used, which is what a development host wants and what a read-only service
/// container does not have.
pub const CAPTURE_SCRATCH_DIR_VARIABLE: &str = "APXM_CAPTURE_SCRATCH_DIR";

/// The stable identifier of the boundary this build applies.
pub const CONFINEMENT_BOUNDARY: &str = "apxm.capture-confinement/1";

/// How the port answers a kernel that cannot provide the boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfinementMode {
    /// The default. A Linux host without Landlock and seccomp filtering
    /// captures nothing.
    Enforce,
    /// Development only. Apply whatever the kernel offers and capture anyway.
    Permissive,
}

impl ConfinementMode {
    /// Read the mode from the operator flag. Anything but the exact word
    /// `permissive` is [`ConfinementMode::Enforce`].
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_value(std::env::var(CONFINEMENT_MODE_VARIABLE).ok().as_deref())
    }

    fn from_value(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some("permissive") => Self::Permissive,
            _ => Self::Enforce,
        }
    }
}

/// What the boundary actually is on this host, right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfinementStatus {
    /// Every declared kernel feature is present and applied to each capture.
    Enforced,
    /// A feature is missing and the mode is permissive: capture runs behind
    /// whatever the kernel did provide.
    Degraded,
    /// A feature is missing and the mode is enforce: capture is refused.
    Unavailable,
    /// The host is not Linux. The boundary is a documented no-op and capture
    /// runs behind interpreter-level confinement alone.
    UnsupportedPlatform,
}

/// The boundary an operator can read before submitting anything to this service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConfinementReadiness {
    /// The stable identifier of the boundary this build applies.
    pub boundary: &'static str,
    /// The host operating system the service is running on.
    pub platform: &'static str,
    /// The configured answer to a missing kernel feature.
    pub mode: ConfinementMode,
    /// What the boundary is on this host.
    pub status: ConfinementStatus,
    /// The Landlock ABI the kernel reports, when it reports one.
    pub landlock_abi: Option<u32>,
    /// Whether the kernel accepts a seccomp filter.
    pub seccomp_filter: bool,
    /// Whether the child is given CPU, memory, file-size and task ceilings.
    pub resource_limits: bool,
    /// The writable root every per-capture scratch directory is created under.
    pub scratch_root: String,
    /// Whether that root exists and accepts a directory. A read-only mount here
    /// refuses every capture, so it is reported rather than discovered.
    pub scratch_writable: bool,
    /// One sentence an operator can act on.
    pub detail: String,
}

/// The scratch root this host uses, and whether capture can write it.
///
/// The probe creates the root when it is absent, so a container whose declared
/// mount arrives empty is usable without an operator step.
fn scratch_readiness() -> (String, bool) {
    let root = scratch_root();
    let writable = CaptureScratch::create_in(&root).is_ok();
    (root.display().to_string(), writable)
}

/// Report the capture boundary this host provides.
///
/// The Compilation Service prints this once at start, so an operator who
/// deployed onto a kernel without Landlock learns it from readiness rather than
/// from the first refused compile.
#[must_use]
pub fn capture_confinement_readiness() -> ConfinementReadiness {
    platform::readiness(ConfinementMode::from_env())
}

/// The ceilings the capture child runs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct ResourceCeilings {
    /// CPU seconds before the kernel signals, and five more before it kills.
    pub(crate) cpu_seconds: u64,
    /// Writable address space, in bytes.
    pub(crate) data_bytes: u64,
    /// Largest file the child may produce, in bytes.
    pub(crate) file_size_bytes: u64,
    /// Tasks the child's user may hold. `RLIMIT_NPROC` counts threads, so this
    /// is a thread budget and not the refusal of a new process: that refusal is
    /// the seccomp filter's, which holds whatever user the service runs as.
    pub(crate) tasks: u64,
}

impl ResourceCeilings {
    /// The ceilings one capture runs under. The CPU ceiling is below the port's
    /// wall-clock capture timeout, so a program that only spins is ended by the
    /// kernel rather than by the supervising thread. The task ceiling clears
    /// both bridges — Node's libuv pool and V8's platform threads, Python's
    /// interpreter threads — by three orders of magnitude while still bounding
    /// a program that only creates threads.
    pub(crate) const CAPTURE: Self = Self {
        cpu_seconds: 20,
        data_bytes: 2 * 1024 * 1024 * 1024,
        file_size_bytes: 64 * 1024 * 1024,
        tasks: 4096,
    };
}

/// The exact paths one capture may reach.
#[derive(Clone, Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct CaptureGrants {
    /// The authoring frontend package the interpreter resolves.
    pub(crate) frontend_root: PathBuf,
    /// The declared interpreter driver the capture runs.
    pub(crate) driver: PathBuf,
    /// The only path this capture may write.
    pub(crate) scratch: PathBuf,
}

/// The boundary applied to one capture child.
///
/// Constructed per capture because the ruleset names that capture's scratch
/// directory. [`Confinement::none`] is the mechanics-only value the port's own
/// pipe and timeout tests use: they drive `spawn` with a stand-in driver and
/// assert nothing about confinement, which the tests in this module assert
/// directly instead.
#[derive(Clone, Debug)]
pub(crate) struct Confinement {
    grants: Option<CaptureGrants>,
    ceilings: Option<ResourceCeilings>,
}

impl Confinement {
    /// The boundary one real capture runs inside.
    pub(crate) fn capture(frontend_root: &Path, driver: &Path, scratch: &Path) -> Self {
        Self {
            grants: Some(CaptureGrants {
                frontend_root: frontend_root.to_path_buf(),
                driver: driver.to_path_buf(),
                scratch: scratch.to_path_buf(),
            }),
            ceilings: Some(ResourceCeilings::CAPTURE),
        }
    }

    /// No boundary at all. Used only where the property under test is the
    /// port's own process mechanics.
    #[cfg(test)]
    pub(crate) const fn none() -> Self {
        Self {
            grants: None,
            ceilings: None,
        }
    }

    /// Apply this boundary to a command that has not been spawned.
    ///
    /// Everything the kernel needs is prepared here, in the parent, so the
    /// pre-exec step in the child allocates nothing and makes only the calls
    /// that restrict it.
    pub(crate) fn arm(&self, command: &mut Command) -> Result<(), SourceDiagnostic> {
        platform::arm(self.grants.as_ref(), self.ceilings, command)
    }
}

/// A directory that exists only for the lifetime of one capture, and the only
/// path in the filesystem that capture may write.
#[derive(Debug)]
pub(crate) struct CaptureScratch {
    path: PathBuf,
}

impl CaptureScratch {
    /// Create one scratch directory for one capture, under the declared root.
    pub(crate) fn create() -> Result<Self, SourceDiagnostic> {
        Self::create_in(&scratch_root())
    }

    /// Create one scratch directory under a named root, creating the root when
    /// it is absent. A root that cannot hold a directory is the one deployment
    /// mistake this boundary makes easy — a read-only container filesystem —
    /// so the refusal names the root and the flag that moves it.
    pub(crate) fn create_in(root: &Path) -> Result<Self, SourceDiagnostic> {
        let path = root.join(format!(
            "apxm-capture-scratch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&path).map_err(|error| {
            SourceDiagnostic::new(
                SourceDiagnosticCode::FrontendUnavailable,
                format!(
                    "the capture scratch directory could not be created under the scratch root: {}; \
                     capture writes nowhere else, so this root must be a writable mount — \
                     set {CAPTURE_SCRATCH_DIR_VARIABLE} to name another one",
                    error.kind()
                ),
            )
        })?;
        Ok(Self { path })
    }

    /// The directory itself.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CaptureScratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The writable root every per-capture scratch directory is created under.
#[must_use]
pub fn scratch_root() -> PathBuf {
    scratch_root_from(std::env::var_os(CAPTURE_SCRATCH_DIR_VARIABLE).as_deref())
}

/// A declared root is used exactly as written; an absent or empty value falls
/// back to the platform temporary directory, which is what a development host
/// has and a read-only container does not.
fn scratch_root_from(value: Option<&OsStr>) -> PathBuf {
    match value {
        Some(named) if !named.is_empty() => PathBuf::from(named),
        _ => std::env::temp_dir(),
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn unavailable(detail: &str) -> SourceDiagnostic {
    SourceDiagnostic::new(
        SourceDiagnosticCode::FrontendUnavailable,
        format!(
            "the capture confinement boundary is unavailable: {detail}; \
             set {CONFINEMENT_MODE_VARIABLE}=permissive to capture without it in development"
        ),
    )
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use std::process::Command;

    use super::{
        CONFINEMENT_BOUNDARY, CaptureGrants, ConfinementMode, ConfinementReadiness,
        ConfinementStatus, ResourceCeilings, SourceDiagnostic, scratch_readiness,
    };

    pub(super) fn readiness(mode: ConfinementMode) -> ConfinementReadiness {
        let (scratch_root, scratch_writable) = scratch_readiness();
        ConfinementReadiness {
            boundary: CONFINEMENT_BOUNDARY,
            platform: std::env::consts::OS,
            mode,
            status: ConfinementStatus::UnsupportedPlatform,
            landlock_abi: None,
            seccomp_filter: false,
            resource_limits: false,
            scratch_root,
            scratch_writable,
            detail: format!(
                "{} provides no Landlock ruleset and no seccomp filter, so the capture \
                 boundary is a documented no-op here and capture runs behind \
                 interpreter-level confinement alone; this is a development host, not a \
                 deployment target",
                std::env::consts::OS
            ),
        }
    }

    pub(super) fn arm(
        _grants: Option<&CaptureGrants>,
        _ceilings: Option<ResourceCeilings>,
        _command: &mut Command,
    ) -> Result<(), SourceDiagnostic> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::ffi::CString;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::{
        CONFINEMENT_BOUNDARY, CaptureGrants, ConfinementMode, ConfinementReadiness,
        ConfinementStatus, ResourceCeilings, SourceDiagnostic, SourceDiagnosticCode,
        scratch_readiness, unavailable,
    };

    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
    const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    const LANDLOCK_RULE_PATH_BENEATH: libc::c_long = 1;

    const FS_EXECUTE: u64 = 1 << 0;
    const FS_WRITE_FILE: u64 = 1 << 1;
    const FS_READ_FILE: u64 = 1 << 2;
    const FS_READ_DIR: u64 = 1 << 3;
    const FS_REMOVE_DIR: u64 = 1 << 4;
    const FS_REMOVE_FILE: u64 = 1 << 5;
    const FS_MAKE_CHAR: u64 = 1 << 6;
    const FS_MAKE_DIR: u64 = 1 << 7;
    const FS_MAKE_REG: u64 = 1 << 8;
    const FS_MAKE_SOCK: u64 = 1 << 9;
    const FS_MAKE_FIFO: u64 = 1 << 10;
    const FS_MAKE_BLOCK: u64 = 1 << 11;
    const FS_MAKE_SYM: u64 = 1 << 12;
    const FS_REFER: u64 = 1 << 13;
    const FS_TRUNCATE: u64 = 1 << 14;

    /// Rights the kernel rejects on a rule that names a file rather than a
    /// directory.
    const DIRECTORY_ONLY: u64 = FS_READ_DIR
        | FS_REMOVE_DIR
        | FS_REMOVE_FILE
        | FS_MAKE_CHAR
        | FS_MAKE_DIR
        | FS_MAKE_REG
        | FS_MAKE_SOCK
        | FS_MAKE_FIFO
        | FS_MAKE_BLOCK
        | FS_MAKE_SYM
        | FS_REFER;

    const READ_EXECUTE: u64 = FS_READ_FILE | FS_READ_DIR | FS_EXECUTE;
    const READ_ONLY: u64 = FS_READ_FILE | FS_READ_DIR;
    const SCRATCH: u64 = FS_READ_FILE
        | FS_READ_DIR
        | FS_WRITE_FILE
        | FS_TRUNCATE
        | FS_REMOVE_DIR
        | FS_REMOVE_FILE
        | FS_MAKE_DIR
        | FS_MAKE_REG
        | FS_MAKE_FIFO
        | FS_MAKE_SOCK
        | FS_MAKE_SYM
        | FS_REFER;

    /// Shared-library and runtime-data roots a distribution interpreter links
    /// against. Executable rights stop at the library roots: `/usr/bin` is not
    /// granted, so no system command is executable inside the boundary. A root
    /// that does not exist on this host contributes no rule.
    const RUNTIME_ROOTS: [(&str, u64); 9] = [
        ("/lib", READ_EXECUTE),
        ("/lib64", READ_EXECUTE),
        ("/usr/lib", READ_EXECUTE),
        ("/usr/lib64", READ_EXECUTE),
        ("/usr/libexec", READ_EXECUTE),
        ("/usr/local/lib", READ_EXECUTE),
        ("/usr/share", READ_ONLY),
        ("/usr/local/share", READ_ONLY),
        ("/proc", READ_ONLY),
    ];

    /// Individual files an interpreter opens at start. Naming the files rather
    /// than their directory is what keeps `/etc/passwd` unreadable.
    const RUNTIME_FILES: [(&str, u64); 7] = [
        ("/etc/ld.so.cache", FS_READ_FILE),
        ("/etc/ld.so.preload", FS_READ_FILE),
        ("/etc/localtime", FS_READ_FILE),
        // Node reads the distribution OpenSSL configuration at start, through
        // a symlink whose target is under `/etc`. The file is granted; the
        // directory holding it is not.
        ("/etc/ssl/openssl.cnf", FS_READ_FILE),
        ("/dev/urandom", FS_READ_FILE),
        ("/dev/random", FS_READ_FILE),
        ("/dev/null", FS_READ_FILE | FS_WRITE_FILE),
    ];

    /// Prefixes that are the system's, not one interpreter's. A driver under
    /// any of these is granted as a file and nothing more.
    const SYSTEM_PREFIXES: [&str; 6] = ["/", "/usr", "/usr/local", "/opt", "/snap", "/var"];

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
    }

    #[repr(C, packed)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    /// The Landlock ABI this kernel reports, if it supports Landlock at all.
    pub(super) fn landlock_abi() -> Option<u32> {
        let reported = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                std::ptr::null::<RulesetAttr>(),
                0_usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        u32::try_from(reported).ok().filter(|abi| *abi > 0)
    }

    /// Whether this kernel accepts a seccomp filter from an unprivileged
    /// process that has already set `no_new_privs`.
    pub(super) fn seccomp_supported() -> bool {
        Path::new("/proc/sys/kernel/seccomp/actions_avail").exists() && seccomp_filter().is_some()
    }

    /// Every right the running ABI understands. Naming a right the kernel does
    /// not know rejects the whole ruleset, so the handled set follows the ABI.
    fn handled_access(abi: u32) -> u64 {
        let mut handled = FS_EXECUTE
            | FS_WRITE_FILE
            | FS_READ_FILE
            | FS_READ_DIR
            | FS_REMOVE_DIR
            | FS_REMOVE_FILE
            | FS_MAKE_CHAR
            | FS_MAKE_DIR
            | FS_MAKE_REG
            | FS_MAKE_SOCK
            | FS_MAKE_FIFO
            | FS_MAKE_BLOCK
            | FS_MAKE_SYM;
        if abi >= 2 {
            handled |= FS_REFER;
        }
        if abi >= 3 {
            handled |= FS_TRUNCATE;
        }
        handled
    }

    /// The complete list of paths one capture may reach, and with which rights.
    fn grant_list(grants: &CaptureGrants) -> Vec<(PathBuf, u64)> {
        let mut list: Vec<(PathBuf, u64)> = RUNTIME_ROOTS
            .iter()
            .chain(RUNTIME_FILES.iter())
            .map(|(path, access)| (PathBuf::from(path), *access))
            .collect();

        list.push((grants.frontend_root.clone(), READ_EXECUTE));
        list.push((grants.scratch.clone(), SCRATCH));
        list.push((grants.driver.clone(), FS_READ_FILE | FS_EXECUTE));

        // A driver installed under its own runtime prefix — a virtual
        // environment, or a service image's vendored interpreter — keeps its
        // standard library beside its `bin` directory, so the prefix is granted
        // and the `bin` directory alone is not. A system prefix is never
        // granted: `/usr` holds every system command, and granting it would
        // make each one executable inside the boundary. A distribution
        // interpreter needs nothing from its prefix that the library and data
        // roots above do not already grant.
        if let Some(prefix) = grants.driver.parent().and_then(Path::parent)
            && !SYSTEM_PREFIXES
                .iter()
                .any(|system| prefix == Path::new(system))
        {
            list.push((prefix.to_path_buf(), READ_EXECUTE));
        }
        list
    }

    /// Open one granted path for the ruleset. A path that is absent on this
    /// host contributes no rule.
    fn open_beneath(path: &Path) -> Option<OwnedFd> {
        let raw = CString::new(path.as_os_str().as_bytes()).ok()?;
        let opened = unsafe { libc::open(raw.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if opened < 0 {
            return None;
        }
        Some(unsafe { OwnedFd::from_raw_fd(opened as RawFd) })
    }

    /// Build the ruleset in the parent, so the child only has to enter it.
    fn build_ruleset(abi: u32, grants: &CaptureGrants) -> io::Result<OwnedFd> {
        let handled = handled_access(abi);
        let attr = RulesetAttr {
            handled_access_fs: handled,
        };
        let created = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                &raw const attr,
                std::mem::size_of::<RulesetAttr>(),
                0_u32,
            )
        };
        if created < 0 {
            return Err(io::Error::last_os_error());
        }
        let ruleset = unsafe { OwnedFd::from_raw_fd(created as RawFd) };

        for (path, access) in grant_list(grants) {
            let Some(target) = open_beneath(&path) else {
                continue;
            };
            let directory = path.is_dir();
            let allowed = access & handled & if directory { u64::MAX } else { !DIRECTORY_ONLY };
            if allowed == 0 {
                continue;
            }
            let rule = PathBeneathAttr {
                allowed_access: allowed,
                parent_fd: target.as_raw_fd(),
            };
            let added = unsafe {
                libc::syscall(
                    SYS_LANDLOCK_ADD_RULE,
                    ruleset.as_raw_fd(),
                    LANDLOCK_RULE_PATH_BENEATH,
                    &raw const rule,
                    0_u32,
                )
            };
            if added != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(ruleset)
    }

    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;
    const BPF_ALU: u16 = 0x04;
    const BPF_AND: u16 = 0x50;

    const SECCOMP_DATA_NR: u32 = 0;
    const SECCOMP_DATA_ARCH: u32 = 4;
    const SECCOMP_DATA_ARG0: u32 = 16;

    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_SET_MODE_FILTER: libc::c_long = 1;
    const SECCOMP_MODE_FILTER: libc::c_int = 2;

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc000_00b7;

    /// Calls the capture child may never make. Filesystem reach is Landlock's
    /// answer; this list closes the channels a ruleset does not describe.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn denied_calls() -> Vec<libc::c_long> {
        let mut denied = vec![
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_perf_event_open,
            libc::SYS_bpf,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_pivot_root,
            libc::SYS_kexec_load,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
            libc::SYS_add_key,
            libc::SYS_keyctl,
            libc::SYS_request_key,
            libc::SYS_open_by_handle_at,
        ];
        #[cfg(target_arch = "x86_64")]
        denied.extend_from_slice(&[libc::SYS_fork, libc::SYS_vfork]);
        denied
    }

    /// `clone` creates a thread when this flag is set, and a process when it is
    /// not. The interpreters need threads and never need a process.
    const CLONE_THREAD: u32 = 0x0001_0000;

    const fn statement(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    /// The filter, or `None` on an architecture whose audit token this build
    /// does not know — which fails closed rather than filtering nothing.
    ///
    /// Every check carries its own refusal and jumps only over its own
    /// instructions, so the program has no shared landing pad and no offset
    /// that depends on how many checks precede it.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub(super) fn seccomp_filter() -> Option<Vec<libc::sock_filter>> {
        let load_nr = statement(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR);
        let deny = statement(
            BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | (u32::try_from(libc::EPERM).ok()? & 0xffff),
        );

        let mut program = vec![
            statement(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH),
            jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0),
            statement(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
            load_nr,
        ];

        for call in denied_calls() {
            program.push(jump(
                BPF_JMP | BPF_JEQ | BPF_K,
                u32::try_from(call).ok()?,
                0,
                1,
            ));
            program.push(deny);
        }

        // A socket in any domain but `AF_UNIX` is the network, whichever
        // interpreter asks for it.
        program.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            u32::try_from(libc::SYS_socket).ok()?,
            0,
            4,
        ));
        program.push(statement(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARG0));
        program.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            u32::try_from(libc::AF_UNIX).ok()?,
            1,
            0,
        ));
        program.push(deny);
        program.push(load_nr);

        // `clone3` carries its flags behind a pointer the filter cannot read.
        // Refusing it as unimplemented is what makes a thread-creating library
        // fall back to `clone`, whose flags the filter can read.
        program.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            u32::try_from(libc::SYS_clone3).ok()?,
            0,
            1,
        ));
        program.push(statement(
            BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | (u32::try_from(libc::ENOSYS).ok()? & 0xffff),
        ));

        // A new process is refused however the child asks for one; a new thread
        // is not. This holds whatever user the service runs as, which a process
        // ceiling alone does not.
        program.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            u32::try_from(libc::SYS_clone).ok()?,
            0,
            4,
        ));
        program.push(statement(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARG0));
        program.push(statement(BPF_ALU | BPF_AND | BPF_K, CLONE_THREAD));
        program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1));
        program.push(deny);

        program.push(statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        Some(program)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub(super) fn seccomp_filter() -> Option<Vec<libc::sock_filter>> {
        None
    }

    /// Enter the filter. The dedicated call is tried first; the older `prctl`
    /// path is what a container runtime's own outer filter usually leaves open.
    fn enter_filter(program: &[libc::sock_filter]) -> io::Result<()> {
        let length = u16::try_from(program.len())
            .map_err(|_| io::Error::other("the capture seccomp filter does not fit a program"))?;
        let fprog = libc::sock_fprog {
            len: length,
            filter: program.as_ptr().cast_mut(),
        };
        let applied = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                0_u32,
                &raw const fprog,
            )
        };
        if applied == 0 {
            return Ok(());
        }
        let applied = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                SECCOMP_MODE_FILTER,
                &raw const fprog,
            )
        };
        if applied == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Apply one ceiling, clamped to the hard limit the service already holds.
    ///
    /// A child that is not privileged cannot raise a hard limit, so a ceiling
    /// stated above the one the host imposes would be refused outright and take
    /// the whole capture with it. Clamping keeps the declared ceiling the
    /// intent and the host's the bound, which is the direction that is safe.
    fn set_ceiling(resource: libc::__rlimit_resource_t, soft: u64, hard: u64) -> io::Result<()> {
        let mut held = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let bound = if unsafe { libc::getrlimit(resource, &raw mut held) } == 0
            && held.rlim_max != libc::RLIM_INFINITY
        {
            held.rlim_max
        } else {
            u64::MAX
        };
        let limit = libc::rlimit {
            rlim_cur: soft.min(bound),
            rlim_max: hard.min(bound),
        };
        if unsafe { libc::setrlimit(resource, &raw const limit) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn enter_ceilings(ceilings: &ResourceCeilings) -> io::Result<()> {
        set_ceiling(
            libc::RLIMIT_CPU,
            ceilings.cpu_seconds,
            ceilings.cpu_seconds + 5,
        )?;
        set_ceiling(libc::RLIMIT_DATA, ceilings.data_bytes, ceilings.data_bytes)?;
        set_ceiling(
            libc::RLIMIT_FSIZE,
            ceilings.file_size_bytes,
            ceilings.file_size_bytes,
        )?;
        set_ceiling(libc::RLIMIT_NPROC, ceilings.tasks, ceilings.tasks)?;
        set_ceiling(libc::RLIMIT_CORE, 0, 0)
    }

    pub(super) fn readiness(mode: ConfinementMode) -> ConfinementReadiness {
        let abi = landlock_abi();
        let seccomp = seccomp_supported();
        let (scratch_root, scratch_writable) = scratch_readiness();
        let complete = abi.is_some() && seccomp;
        let status = match (complete, mode) {
            (true, _) => ConfinementStatus::Enforced,
            (false, ConfinementMode::Permissive) => ConfinementStatus::Degraded,
            (false, ConfinementMode::Enforce) => ConfinementStatus::Unavailable,
        };
        let detail = if !scratch_writable {
            format!(
                "the capture scratch root {scratch_root} is not writable, so every capture \
                 is refused; mount a writable filesystem there or name another root in \
                 {}",
                super::CAPTURE_SCRATCH_DIR_VARIABLE
            )
        } else if complete {
            "every capture child runs inside a Landlock ruleset, a seccomp filter, and \
             CPU, memory, file-size and thread ceilings"
                .to_owned()
        } else {
            let mut missing = Vec::new();
            if abi.is_none() {
                missing.push("Landlock");
            }
            if !seccomp {
                missing.push("seccomp filtering");
            }
            format!(
                "this kernel provides no {}; capture is {}",
                missing.join(" and "),
                match mode {
                    ConfinementMode::Enforce => "refused",
                    ConfinementMode::Permissive =>
                        "allowed by the permissive development setting of the operator flag",
                }
            )
        };
        ConfinementReadiness {
            boundary: CONFINEMENT_BOUNDARY,
            platform: std::env::consts::OS,
            mode,
            status,
            landlock_abi: abi,
            seccomp_filter: seccomp,
            resource_limits: true,
            scratch_root,
            scratch_writable,
            detail,
        }
    }

    pub(super) fn arm(
        grants: Option<&CaptureGrants>,
        ceilings: Option<ResourceCeilings>,
        command: &mut Command,
    ) -> Result<(), SourceDiagnostic> {
        let Some(grants) = grants else {
            return arm_parts(command, None, None, ceilings);
        };

        let mode = ConfinementMode::from_env();
        let abi = landlock_abi();
        let filter = seccomp_filter();
        if (abi.is_none() || filter.is_none()) && matches!(mode, ConfinementMode::Enforce) {
            return Err(unavailable(&readiness(mode).detail));
        }

        let ruleset = match abi {
            Some(abi) => Some(build_ruleset(abi, grants).map_err(|error| {
                SourceDiagnostic::new(
                    SourceDiagnosticCode::FrontendUnavailable,
                    format!("the capture confinement ruleset could not be built: {error}"),
                )
            })?),
            None => None,
        };
        arm_parts(command, ruleset, filter, ceilings)
    }

    /// Install exactly the steps the child performs before it execs. Everything
    /// they need is already built, so the child allocates nothing.
    fn arm_parts(
        command: &mut Command,
        ruleset: Option<OwnedFd>,
        filter: Option<Vec<libc::sock_filter>>,
        ceilings: Option<ResourceCeilings>,
    ) -> Result<(), SourceDiagnostic> {
        if ruleset.is_none() && filter.is_none() && ceilings.is_none() {
            return Ok(());
        }
        unsafe {
            command.pre_exec(move || {
                if let Some(ceilings) = ceilings.as_ref() {
                    enter_ceilings(ceilings)?;
                }
                if (ruleset.is_some() || filter.is_some())
                    && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if let Some(ruleset) = ruleset.as_ref() {
                    let entered = libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset.as_raw_fd(), 0_u32);
                    if entered != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                if let Some(filter) = filter.as_ref() {
                    enter_filter(filter)?;
                }
                Ok(())
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_operator_flag_defaults_to_enforcing() {
        assert_eq!(ConfinementMode::from_value(None), ConfinementMode::Enforce);
        assert_eq!(
            ConfinementMode::from_value(Some("permissive")),
            ConfinementMode::Permissive
        );
        assert_eq!(
            ConfinementMode::from_value(Some(" permissive ")),
            ConfinementMode::Permissive
        );
    }

    /// A typo is not a way to end up unconfined.
    #[test]
    fn an_unrecognised_flag_value_enforces() {
        for value in ["", "off", "none", "Permissive", "enforce", "yes"] {
            assert_eq!(
                ConfinementMode::from_value(Some(value)),
                ConfinementMode::Enforce,
                "{value} must not open the boundary"
            );
        }
    }

    /// The scratch root is the declared one when there is one, and the
    /// platform temporary directory otherwise. A read-only service container
    /// has no writable temporary directory, so this is the flag that makes the
    /// boundary deployable rather than a development convenience.
    #[test]
    fn the_scratch_root_follows_the_declared_mount() {
        assert_eq!(
            scratch_root_from(Some(OsStr::new("/var/lib/apxm/capture"))),
            PathBuf::from("/var/lib/apxm/capture")
        );
        assert_eq!(scratch_root_from(None), std::env::temp_dir());
        assert_eq!(
            scratch_root_from(Some(OsStr::new(""))),
            std::env::temp_dir()
        );
    }

    /// A root that cannot hold a directory — the read-only container filesystem
    /// this boundary makes easy to hit — is refused in the port's own closed
    /// vocabulary, naming the flag that moves it. The diagnostic crosses the
    /// compile protocol, so it never names a host path; readiness reports the
    /// root at deployment instead.
    #[test]
    fn a_scratch_root_that_cannot_be_written_names_the_flag_but_no_host_path() {
        let occupied = std::env::temp_dir().join(format!(
            "apxm-scratch-root-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::write(&occupied, b"not a directory").expect("a regular file stands in the way");
        let refusal = CaptureScratch::create_in(&occupied.join("beneath"))
            .expect_err("a root that is not a directory cannot hold a scratch directory");
        let _ = std::fs::remove_file(&occupied);

        assert_eq!(refusal.code, SourceDiagnosticCode::FrontendUnavailable);
        assert!(refusal.message.contains(CAPTURE_SCRATCH_DIR_VARIABLE));
        assert!(!refusal.message.contains(&occupied.display().to_string()));
    }

    /// Readiness answers the deployment question before the first request:
    /// where capture writes, and whether it can.
    #[test]
    fn readiness_reports_the_scratch_root_it_will_write() {
        let reported = platform::readiness(ConfinementMode::Enforce);
        assert_eq!(reported.scratch_root, scratch_root().display().to_string());
        assert!(
            reported.scratch_writable,
            "the platform temporary directory is writable on a development host"
        );
    }

    /// A kernel that cannot provide the boundary is refused in the port's own
    /// closed vocabulary, and the refusal names the one flag that changes it.
    #[test]
    fn a_missing_kernel_feature_is_refused_in_the_closed_vocabulary() {
        let refusal = unavailable("this kernel provides no Landlock");
        assert_eq!(refusal.code, SourceDiagnosticCode::FrontendUnavailable);
        assert!(refusal.message.contains(CONFINEMENT_MODE_VARIABLE));
        assert!(refusal.message.contains("permissive"));
    }

    #[test]
    fn readiness_names_the_boundary_and_the_host() {
        let reported = platform::readiness(ConfinementMode::Enforce);
        assert_eq!(reported.boundary, CONFINEMENT_BOUNDARY);
        assert_eq!(reported.platform, std::env::consts::OS);
        assert!(!reported.detail.is_empty());
    }

    /// On a host that is not Linux the boundary is a no-op, and readiness says
    /// so rather than leaving an operator to infer it.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn a_host_without_the_kernel_feature_reports_a_documented_no_op() {
        let reported = platform::readiness(ConfinementMode::Enforce);
        assert_eq!(reported.status, ConfinementStatus::UnsupportedPlatform);
        assert_eq!(reported.landlock_abi, None);
        assert!(!reported.seccomp_filter);
        assert!(!reported.resource_limits);
        assert!(reported.detail.contains("no-op"));
    }

    /// The no-op still lets a development host capture.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn a_no_op_boundary_still_arms() {
        let scratch = CaptureScratch::create().expect("a scratch directory is created");
        let mut command = Command::new("/bin/sh");
        Confinement::capture(
            Path::new("/nonexistent"),
            Path::new("/bin/sh"),
            scratch.path(),
        )
        .arm(&mut command)
        .expect("a development host captures behind interpreter confinement alone");
    }

    /// The hostile-source reproduction, run against the boundary itself.
    ///
    /// Each case is a program submitted to a stand-in interpreter — the
    /// distribution Python, which is also one of the two real capture drivers —
    /// running under exactly the boundary a capture runs under. A host without
    /// that interpreter has nothing to submit to and the case is skipped.
    #[cfg(target_os = "linux")]
    mod hostile_source {
        use super::*;
        use std::process::Stdio;

        /// Ceilings small enough that a test observes them without waiting.
        const TEST_CEILINGS: ResourceCeilings = ResourceCeilings {
            cpu_seconds: 1,
            data_bytes: 256 * 1024 * 1024,
            file_size_bytes: 4096,
            tasks: ResourceCeilings::CAPTURE.tasks,
        };

        const INTERPRETER: &str = "/usr/bin/python3";

        struct Reach {
            status: std::process::ExitStatus,
            stdout: String,
            stderr: String,
        }

        /// Submit one program to the stand-in interpreter inside the boundary.
        fn reach(program: &str) -> Option<Reach> {
            let driver = Path::new(INTERPRETER);
            if !driver.is_file() {
                return None;
            }
            let scratch = CaptureScratch::create().expect("a scratch directory is created");
            let mut command = Command::new(driver);
            command
                .arg("-I")
                .arg("-B")
                .arg("-c")
                .arg(program)
                .env_clear()
                .env("TMPDIR", scratch.path())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let confinement = Confinement {
                grants: Some(CaptureGrants {
                    frontend_root: scratch.path().to_path_buf(),
                    driver: driver.to_path_buf(),
                    scratch: scratch.path().to_path_buf(),
                }),
                ceilings: Some(TEST_CEILINGS),
            };
            confinement
                .arm(&mut command)
                .expect("this kernel provides the capture boundary");
            let output = command.output().expect("the submitted program runs");
            Some(Reach {
                status: output.status,
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            })
        }

        /// The boundary is a boundary, not a wall: the interpreter still starts,
        /// and still writes where capture is allowed to write.
        #[test]
        fn the_capture_child_starts_and_writes_only_its_scratch_directory() {
            let Some(reached) = reach(
                "import os\n\
                 note = os.path.join(os.environ['TMPDIR'], 'note')\n\
                 open(note, 'w').write('scratch')\n\
                 print(open(note).read(), end='')\n",
            ) else {
                return;
            };
            assert!(reached.status.success(), "stderr: {}", reached.stderr);
            assert_eq!(reached.stdout, "scratch");
        }

        /// Reading a file the package has no business reading.
        #[test]
        fn a_submitted_program_cannot_read_the_password_file() {
            let Some(reached) = reach(
                "try:\n\
                 \x20   print('leaked', open('/etc/passwd').readline(), end='')\n\
                 except OSError as error:\n\
                 \x20   print('denied', error.errno, end='')\n",
            ) else {
                return;
            };
            assert!(reached.stdout.starts_with("denied"), "{}", reached.stdout);
            assert!(!reached.stdout.contains("root:"));
        }

        /// Writing anywhere but the scratch directory, and no witness left
        /// behind.
        #[test]
        fn a_submitted_program_cannot_write_outside_the_scratch_directory() {
            let witness =
                std::env::temp_dir().join(format!("apxm-boundary-witness-{}", std::process::id()));
            let _ = std::fs::remove_file(&witness);
            let Some(reached) = reach(&format!(
                "try:\n\
                 \x20   open({path:?}, 'w').write('escaped')\n\
                 \x20   print('escaped', end='')\n\
                 except OSError as error:\n\
                 \x20   print('denied', error.errno, end='')\n",
                path = witness.display().to_string()
            )) else {
                return;
            };
            assert!(reached.stdout.starts_with("denied"), "{}", reached.stdout);
            assert!(!witness.exists(), "the boundary let a witness file appear");
            let _ = std::fs::remove_file(&witness);
        }

        /// Opening a socket. The kernel answers, not the interpreter.
        #[test]
        fn a_submitted_program_cannot_open_a_network_socket() {
            let Some(reached) = reach(
                "import socket\n\
                 try:\n\
                 \x20   socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n\
                 \x20   print('opened', end='')\n\
                 except OSError as error:\n\
                 \x20   print('denied', error.errno, end='')\n",
            ) else {
                return;
            };
            assert!(reached.stdout.starts_with("denied"), "{}", reached.stdout);
        }

        /// Executing a binary outside the interpreter's own runtime. No system
        /// command is executable inside the ruleset.
        #[test]
        fn a_submitted_program_cannot_execute_a_system_binary() {
            let Some(reached) = reach(
                "import os\n\
                 try:\n\
                 \x20   os.execv('/bin/sh', ['sh', '-c', 'echo escaped'])\n\
                 except OSError as error:\n\
                 \x20   print('denied', error.errno, end='')\n",
            ) else {
                return;
            };
            assert!(reached.stdout.starts_with("denied"), "{}", reached.stdout);
            assert!(!reached.stdout.contains("escaped"));
        }

        /// Spawning a shell. The filter denies the fork even where a binary
        /// could be reached, and denies it whatever the task ceiling is and
        /// whatever user the service runs as.
        #[test]
        fn a_submitted_program_cannot_spawn_a_shell() {
            let Some(reached) = reach(
                "import os\n\
                 try:\n\
                 \x20   os.fork()\n\
                 \x20   print('forked', end='')\n\
                 except OSError as error:\n\
                 \x20   print('denied', error.errno, end='')\n",
            ) else {
                return;
            };
            assert!(reached.stdout.starts_with("denied"), "{}", reached.stdout);
            assert!(!reached.stdout.contains("forked"));
        }

        /// Allocating without bound. The writable-data ceiling ends it rather
        /// than the host running out of memory.
        #[test]
        fn a_submitted_program_cannot_allocate_without_bound() {
            let Some(reached) = reach(
                "held = []\n\
                 try:\n\
                 \x20   while True:\n\
                 \x20       held.append(bytearray(32 * 1024 * 1024))\n\
                 except MemoryError:\n\
                 \x20   print('refused', end='')\n",
            ) else {
                return;
            };
            assert!(!reached.stdout.contains("allocated"));
            assert!(
                reached.stdout.starts_with("refused") || !reached.status.success(),
                "an unbounded allocation was neither refused nor ended: {}",
                reached.stderr
            );
        }

        /// Spinning. The CPU ceiling ends it well inside the port's own
        /// wall-clock capture timeout.
        #[test]
        fn a_spinning_program_is_ended_by_the_cpu_ceiling() {
            let started = std::time::Instant::now();
            let Some(reached) = reach("while True:\n\x20   pass\n") else {
                return;
            };
            assert!(!reached.status.success());
            assert!(
                started.elapsed() < std::time::Duration::from_secs(20),
                "the CPU ceiling did not end the spin"
            );
        }

        /// The ceilings the child actually holds, read back from inside it.
        #[test]
        fn the_capture_child_holds_every_declared_ceiling() {
            let Some(reached) = reach(
                "import resource\n\
                 for name in ('RLIMIT_CPU', 'RLIMIT_DATA', 'RLIMIT_FSIZE', 'RLIMIT_NPROC', 'RLIMIT_CORE'):\n\
                 \x20   print(name, resource.getrlimit(getattr(resource, name))[0])\n",
            ) else {
                return;
            };
            assert!(reached.status.success(), "stderr: {}", reached.stderr);
            for expected in [
                "RLIMIT_CPU 1",
                "RLIMIT_DATA 268435456",
                "RLIMIT_FSIZE 4096",
                "RLIMIT_CORE 0",
            ] {
                assert!(
                    reached.stdout.contains(expected),
                    "the child did not report {expected}: {}",
                    reached.stdout
                );
            }

            // The task ceiling is clamped to the hard limit the host already
            // holds, so what is asserted is the property and not one number: a
            // budget that is stated, positive — a zero would refuse the first
            // thread either bridge creates — and no wider than declared.
            let reported: u64 = reached
                .stdout
                .lines()
                .find_map(|line| line.strip_prefix("RLIMIT_NPROC "))
                .expect("the child reports its task ceiling")
                .parse()
                .expect("the task ceiling is a number");
            assert!(
                reported > 0 && reported <= TEST_CEILINGS.tasks,
                "the task ceiling is {reported}, not a bounded positive budget"
            );
        }

        /// The threads both bridges need. A ceiling of zero refuses the first
        /// one, which is how the confined compiler reached a container and
        /// killed Node before it read a request.
        #[test]
        fn a_submitted_program_creates_the_threads_an_interpreter_needs() {
            let Some(reached) = reach(
                "import threading\n\
                 seen = []\n\
                 workers = [threading.Thread(target=seen.append, args=(1,)) for _ in range(8)]\n\
                 for worker in workers:\n\
                 \x20   worker.start()\n\
                 for worker in workers:\n\
                 \x20   worker.join()\n\
                 print('threads', len(seen), end='')\n",
            ) else {
                return;
            };
            assert!(reached.status.success(), "stderr: {}", reached.stderr);
            assert_eq!(reached.stdout, "threads 8");
        }

        /// A thread is not a process. Every library route to a new process —
        /// `posix_spawn` here, `fork` above — is still refused, and the
        /// refusal is the filter's, so it holds where a task ceiling does not.
        #[test]
        fn a_submitted_program_cannot_start_a_process_through_posix_spawn() {
            let Some(reached) = reach(
                "import subprocess\n\
                 try:\n\
                 \x20   subprocess.run(['/bin/sh', '-c', 'echo escaped'], check=False)\n\
                 \x20   print('spawned', end='')\n\
                 except OSError as error:\n\
                 \x20   print('denied', error.errno, end='')\n",
            ) else {
                return;
            };
            assert!(reached.stdout.starts_with("denied"), "{}", reached.stdout);
            assert!(!reached.stdout.contains("escaped"));
        }

        /// Readiness on a kernel that has the features says the boundary is
        /// enforced, and names the ABI it found.
        #[test]
        fn readiness_reports_an_enforced_boundary() {
            let reported = platform::readiness(ConfinementMode::Enforce);
            assert_eq!(reported.status, ConfinementStatus::Enforced);
            assert!(reported.landlock_abi.unwrap_or_default() >= 1);
            assert!(reported.seccomp_filter);
            assert!(reported.resource_limits);
        }

        /// Both declared interpreters still start inside the boundary. A
        /// boundary that broke the frontend runtime would be no boundary at
        /// all, because it would be turned off.
        #[test]
        fn every_declared_interpreter_still_starts_inside_the_boundary() {
            // Each program reaches the interpreter's own thread pool rather
            // than only its main thread: Node's V8 platform threads start with
            // the process and its libuv pool starts with the first asynchronous
            // call, and a boundary that admits neither admits no TypeScript
            // capture at all.
            const NODE_USES_ITS_THREAD_POOL: &str = "require('crypto').pbkdf2('a', 'b', 1, 8, 'sha256', \
                 (error) => process.stdout.write(error ? 'failed' : 'alive'))";
            const PYTHON_USES_A_THREAD: &str = "import threading\n\
                 worker = threading.Thread(target=lambda: None)\n\
                 worker.start()\n\
                 worker.join()\n\
                 print('alive', end='')";
            for (driver, flag, program) in [
                (INTERPRETER, "-c", PYTHON_USES_A_THREAD),
                ("/usr/bin/node", "-e", NODE_USES_ITS_THREAD_POOL),
                ("/usr/local/bin/node", "-e", NODE_USES_ITS_THREAD_POOL),
            ] {
                let driver = Path::new(driver);
                if !driver.is_file() {
                    continue;
                }
                let scratch = CaptureScratch::create().expect("a scratch directory is created");
                let mut command = Command::new(driver);
                command
                    .arg(flag)
                    .arg(program)
                    .env_clear()
                    .env("TMPDIR", scratch.path())
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                Confinement::capture(scratch.path(), driver, scratch.path())
                    .arm(&mut command)
                    .expect("this kernel provides the capture boundary");
                let output = command.output().expect("the interpreter runs");
                assert_eq!(
                    String::from_utf8_lossy(&output.stdout),
                    "alive",
                    "{} did not start inside the boundary: {}",
                    driver.display(),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
}
