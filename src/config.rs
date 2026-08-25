use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Write content to a file with restricted permissions (0o600 on unix).
/// Use for files containing credentials (xray config, AWG conf, etc.).
///
/// [`open_write_restricted`] plus a truncating write. Every caller writes a
/// file corvex generates itself — never one a user authored — so neither a
/// symlink nor a FIFO at any of these paths is a shape worth preserving, and
/// neither is a file some other uid happens to own; that open is where all of
/// that is enforced, and why the truncation here is a `set_len(0)` on the
/// descriptor it returns rather than an `OpenOptions::truncate` inside the
/// `open` itself.
///
/// One thing that open cannot enforce from inside itself: on macOS the file
/// it created carries whatever `file_inherit` ACE the *directory* hands out,
/// and it carries it for the two syscalls between `open` and the strip.
/// Stripping it leaves the mode and the ACL right, but not the descriptor
/// somebody polling the path could have obtained during that window — and a
/// descriptor opened for reading keeps reading whatever is written through
/// the inode afterwards, which here is a VLESS UUID, a Trojan password or an
/// AWG private key. So a strip that actually removed something is treated as
/// "this inode may already be shared" and the content goes to a fresh one
/// instead, through [`write_via_private_dir`]. Nothing changes on the
/// overwhelmingly common path where there was no ACL to remove.
pub fn write_restricted(path: &Path, content: &str) -> Result<()> {
    #[cfg(unix)]
    {
        let (mut file, acl) = open_write_restricted_reporting_acl(path)
            .with_context(|| format!("failed to create {}", path.display()))?;
        if acl == AclState::Removed {
            drop(file);
            return write_via_private_dir(path, content)
                .with_context(|| format!("failed to write {}", path.display()));
        }
        file.set_len(0)
            .with_context(|| format!("failed to truncate {}", path.display()))?;
        std::io::Write::write_all(&mut file, content.as_bytes())
            .with_context(|| format!("failed to write {}", path.display()))?;
    }
    #[cfg(windows)]
    {
        // Not `fs::write`: that opens the path with no say over reparse
        // points, which is the Windows shape of the symlink problem the unix
        // twin refuses. `set_len(0)` for the same reason the unix twin gives.
        let mut file = open_write_restricted(path)
            .with_context(|| format!("failed to create {}", path.display()))?;
        file.set_len(0)
            .with_context(|| format!("failed to truncate {}", path.display()))?;
        std::io::Write::write_all(&mut file, content.as_bytes())
            .with_context(|| format!("failed to write {}", path.display()))?;
    }
    Ok(())
}

/// Open `path` for writing, creating it at 0o600, vetted by
/// [`accept_restricted_file`] and with any inherited ACL stripped — and
/// *without* truncating, so the caller decides whether the previous contents
/// go.
///
/// The open half of [`write_restricted`], split out because `xray.rs` needs
/// the same guarantees for `xray.pid` at two points that are not a
/// write-the-whole-file call: the pre-spawn writability preflight, which must
/// leave any existing contents alone, and the post-spawn write, which renders
/// its own error text and so wants the `io::Error` rather than an
/// `anyhow::Error`.
///
/// Everything [`open_append_restricted`] says about the flags applies here,
/// only more so: this descriptor is written through, and what goes into it is
/// either a credential or the PID corvex needs to be able to trust later.
/// `fs::write` at either of these paths follows a symlink and truncates its
/// target, which in the world-writable `/tmp` fallback is an arbitrary-file
/// clobber with corvex's privileges.
///
/// Note the deliberate `.truncate(false)`. `OpenOptions` truncates *inside*
/// `open`, which is before `accept_restricted_file` has had a chance to look
/// at what it opened, and the whole point of these checks is that they run
/// before the descriptor is used for anything. `write_restricted` truncates
/// with `set_len(0)` on the vetted descriptor instead — same result on the
/// file corvex means to write, no side effect at all on one it is about to
/// refuse.
#[cfg(unix)]
pub fn open_write_restricted(path: &Path) -> std::io::Result<std::fs::File> {
    open_write_restricted_reporting_acl(path).map(|(file, _)| file)
}

/// [`open_write_restricted`], plus whether an inherited ACL was actually
/// removed from the file it hands back.
///
/// Only [`write_restricted`] needs the second half, and only on macOS: a
/// removed ACE means the directory grants one to everything created in it,
/// so the inode may have been opened by somebody else in the window between
/// `open` and the strip. A PID is not a secret and a `xray.pid` reader gains
/// nothing, which is why `xray.rs` goes on using the plain wrapper.
#[cfg(unix)]
fn open_write_restricted_reporting_acl(path: &Path) -> std::io::Result<(std::fs::File, AclState)> {
    use std::os::unix::fs::OpenOptionsExt;
    // Before the open, because `O_NOFOLLOW` governs the *final* component and
    // nothing above it: the kernel still resolves every parent, symlinked ones
    // included. See [`ensure_trusted_ancestry`] for why that is the whole of
    // the exposure in the `/tmp` fallback.
    ensure_trusted_ancestry(path)?;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = accept_restricted_file(&file, path)?;
    // Before the write, never after: `.mode()` applies only to a file this
    // open *created*, so a pre-existing 0666 file would otherwise take the
    // credential at 0666 and be tightened a syscall too late.
    tighten_to_0600(&file, &metadata)?;
    let acl = strip_inherited_acl(&file, path)?;
    Ok((file, acl))
}

/// Windows has no mode bits; the file inherits the ACL of its parent, which
/// under `%APPDATA%`/`%LOCALAPPDATA%` is already per-user — and which
/// [`shared_fallback_rejection`] refuses to take on faith when the parent is
/// the temporary directory instead. What it does have is reparse points, and
/// they are this platform's spelling of the symlink the unix twin refuses —
/// see [`open_no_reparse`] for why the plain open is not enough at a path
/// corvex chose itself.
#[cfg(windows)]
pub fn open_write_restricted(path: &Path) -> std::io::Result<std::fs::File> {
    ensure_per_user_location(path)?;
    open_no_reparse(
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false),
        path,
    )
}

/// `FILE_FLAG_OPEN_REPARSE_POINT`, from `winnt.h`. Without it `CreateFile`
/// resolves a reparse point at the final path component and hands back a
/// handle to its target.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// `FILE_ATTRIBUTE_REPARSE_POINT`, from `winnt.h`.
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Open `path` with `options`, refusing a reparse point at the final
/// component. The Windows counterpart of `O_NOFOLLOW`.
///
/// `%LOCALAPPDATA%` and `%APPDATA%` are per-user, and so is the
/// `%USERPROFILE%` fallback [`windows_per_user_dir`] rebuilds when they are
/// unset — which is the change that took the shared `C:\Users\Public`
/// directory, and with it every other user's write access to these paths, out
/// of the picture; the temporary directory beneath that is not per-user by
/// construction, and [`shared_fallback_rejection`] refuses it rather than
/// trusting it. This refusal is what is left: a
/// *directory junction* needs no privilege to create (unlike a file symlink,
/// which needs `SeCreateSymbolicLinkPrivilege` or developer mode), and
/// `CreateFile` follows either one unless `FILE_FLAG_OPEN_REPARSE_POINT` is
/// passed. Following one at `xray.pid` or `corvex.log` means creating and
/// truncating whatever it names, with corvex's privileges — an
/// arbitrary-file clobber, and an elevated one when corvex runs elevated.
/// The plant now costs an account that can already write the profile
/// directory, but the ordinary user profile is exactly where a *different*
/// program's bug leaves a junction, and corvex is elevated often enough for
/// that to matter.
///
/// The flag alone would leave a handle *to* the reparse point, so the
/// attribute is checked afterwards and any tag is refused: corvex writes
/// none of these files through an indirection it did not create.
///
/// Honest about its reach: the flag governs the final component only, so a
/// junction planted at a *parent* directory is still traversed. Closing that
/// needs the path walked handle by handle. What stands in for the unix
/// ancestry walk ([`ensure_trusted_ancestry`], which has uids and mode bits
/// to work with and Windows does not) is that the hierarchy is per-user and
/// [`create_dir_restricted`] creates it before anything is written into it.
#[cfg(windows)]
fn open_no_reparse(
    options: &mut std::fs::OpenOptions,
    path: &Path,
) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    let file = options
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} is a reparse point; refusing to write through it",
                path.display()
            ),
        ));
    }
    Ok(file)
}

/// Refuse a path in the last-resort temporary directory
/// [`windows_per_user_dir`] falls back to when `%APPDATA%`/`%LOCALAPPDATA%`
/// *and* `%USERPROFILE%` are all unset.
///
/// Everything else on Windows rests on the directory being per-user: the file
/// inherits its DACL from the parent, so a per-user parent is what makes the
/// generated xray config (a VLESS UUID, a Trojan password) or the AWG private
/// key readable by this account and no other. `%APPDATA%` and
/// `%LOCALAPPDATA%` give that by construction and so does the
/// `%USERPROFILE%\AppData\…` rebuild; `std::env::temp_dir` does not. It reads
/// `%TMP%`, then `%TEMP%`, then `%USERPROFILE%`, and falls back to the
/// Windows directory, and while the ordinary answer is the per-user
/// `…\AppData\Local\Temp`, nothing guarantees it: a service started from the
/// system environment block gets `C:\Windows\Temp`, which every account may
/// create entries in, and a machine-wide `%TMP%` set by policy can name any
/// directory at all. Rust's own documentation warns the value may be shared.
///
/// There is no Windows twin of [`ensure_trusted_ancestry`] to fall back on —
/// no uids, no mode bits — and [`open_no_reparse`] judges the shape of the
/// final component, not who owns it. So corvex does not write there at all:
/// it fails with a message naming the variables to set, which is strictly
/// better than the alternative it used to have, where the same environment
/// wrote credentials into `C:\Users\Public`. The narrow case this costs is a
/// stripped environment with `%TMP%` set and nothing else, where corvex now
/// stops instead of writing a config it cannot vouch for.
///
/// Pure, and compiled into the test build everywhere, because that is the
/// only way this decision is testable off Windows; the path comparison is
/// against the very `temp_dir()` value the path was built from, so it needs
/// no case folding.
#[cfg(any(windows, test))]
fn shared_fallback_rejection(
    path: &Path,
    temp: &Path,
    appdata: Option<&str>,
    local_appdata: Option<&str>,
    user_profile: Option<&str>,
) -> Option<std::io::Error> {
    let is_set = |value: Option<&str>| value.is_some_and(|value| !value.is_empty());
    // `%USERPROFILE%` alone rules the fallback out, since both bases are
    // rebuilt from it; with it unset, either base whose own variable is unset
    // lands in the temporary directory.
    let fell_back = !is_set(user_profile) && (!is_set(appdata) || !is_set(local_appdata));
    if !fell_back || !path.starts_with(temp) {
        return None;
    }
    Some(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "{} is in the temporary directory corvex falls back to when \
             %APPDATA%, %LOCALAPPDATA% and %USERPROFILE% are all unset, and a \
             temporary directory is not guaranteed to belong to one user — a \
             file corvex creates there inherits whatever the directory hands \
             out, which may include another account. Set %APPDATA% and \
             %LOCALAPPDATA% (or %USERPROFILE%) to a directory of your own and \
             run corvex again",
            path.display()
        ),
    ))
}

/// [`shared_fallback_rejection`] against the environment this process was
/// started with, asked by every Windows open and directory creation that
/// handles a file corvex owns.
#[cfg(windows)]
fn ensure_per_user_location(path: &Path) -> std::io::Result<()> {
    let appdata = std::env::var("APPDATA").ok();
    let local_appdata = std::env::var("LOCALAPPDATA").ok();
    let user_profile = std::env::var("USERPROFILE").ok();
    match shared_fallback_rejection(
        path,
        &std::env::temp_dir(),
        appdata.as_deref(),
        local_appdata.as_deref(),
        user_profile.as_deref(),
    ) {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// Vet a freshly opened descriptor before anything is written through it, and
/// hand back the metadata the caller needs anyway, so the `fstat` is paid for
/// once.
///
/// `O_NOFOLLOW` rules out exactly one file type — a symlink — and leaves every
/// other one in play. Under the `/tmp` fallback described on
/// [`open_append_restricted`] the containing directory is world-writable, and
/// `mkfifo` needs no privilege at all: anyone can pre-create
/// `/tmp/.local/state/corvex/corvex.log` (or the xray config path, which falls
/// back the same way) as a FIFO. A FIFO opened for writing with no reader
/// attached is not a leak but a wedge — `open` blocks in the kernel until a
/// reader appears, and both of these opens run before the command they belong
/// to does any work, so corvex hangs producing no output whatsoever.
/// `O_NONBLOCK` turns that case into an immediate `ENXIO`; this check covers the
/// rest, including a FIFO the attacker holds open for reading, which opens
/// cleanly and would otherwise take a config or a log's worth of bytes.
///
/// `O_NONBLOCK` is safe to leave set on what survives: POSIX regular-file I/O
/// never returns `EAGAIN`, so the flag has no effect on the descriptor once its
/// type is known to be regular.
///
/// A *regular* file is not enough on its own, though, and this is the plant the
/// file-type check does not see. `mode(0o600)` applies only to a file the open
/// created; against one that already exists it is inert, and in that same
/// world-writable directory the cheapest plant of all is an ordinary
/// `install -m 666 /dev/null` at the path. corvex then opens it, keeps the
/// attacker as owner, and writes an xray config — a VLESS UUID, a Trojan
/// password, an AWG private key — into a file the attacker can read. The
/// ownership check is what closes that, and it has to be an equality test
/// against the effective uid rather than a chmod attempt: `fchmod` to 0600
/// *succeeds* when corvex runs as root, and leaves the attacker owning a file
/// they can chmod straight back.
///
/// The link count closes the same hole entered from the other side. `O_NOFOLLOW`
/// is about symlinks and says nothing about hard links, so an attacker who can
/// link — Linux's `fs.protected_hardlinks` stops a link to a file you neither
/// own nor can write, macOS has no such control — can point the log path at a
/// file corvex's own uid owns (a shell rc, a crontab) and pass the ownership
/// test on the strength of the victim's ownership. corvex writes exactly one
/// name for each of these files, so `nlink > 1` is never its own doing.
#[cfg(unix)]
fn accept_restricted_file(file: &std::fs::File, path: &Path) -> std::io::Result<std::fs::Metadata> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    // SAFETY: `geteuid` reads the calling process's own credentials. It takes
    // no arguments, touches no memory the caller owns, and POSIX gives it no
    // failure mode at all.
    let euid = unsafe { nix::libc::geteuid() };
    match restricted_file_rejection(
        path,
        metadata.is_file(),
        metadata.uid(),
        euid,
        metadata.nlink(),
    ) {
        Some(err) => Err(err),
        None => Ok(metadata),
    }
}

/// The pure core of [`accept_restricted_file`]: every refusal it makes, decided
/// from a bool and three numbers. Split out because the foreign-owner case is
/// the one a test cannot stage — the suite would have to become a second uid —
/// and an untested security check is a check that quietly stops working. The
/// other two are reachable over a real descriptor and are tested that way too.
#[cfg(unix)]
fn restricted_file_rejection(
    path: &Path,
    is_regular: bool,
    uid: u32,
    euid: u32,
    nlink: u64,
) -> Option<std::io::Error> {
    if !is_regular {
        return Some(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    if uid != euid {
        return Some(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} is owned by uid {uid}, not by uid {euid}; refusing to use it",
                path.display()
            ),
        ));
    }
    if nlink != 1 {
        return Some(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} has {nlink} hard links; refusing to write through an aliased path",
                path.display()
            ),
        ));
    }
    None
}

/// `fchmod` the descriptor to 0600 unless it is already there.
///
/// Through the descriptor, never through the path a second time.
/// `File::set_permissions` is `fchmod`, which acts on the inode the open
/// already pinned; `std::fs::set_permissions` is `chmod`, which resolves the
/// path afresh *and* follows symlinks. Checking the path with
/// `symlink_metadata` and then chmod-ing it is two resolutions of the same
/// name, so in the world-writable `/tmp` directory described on
/// [`accept_restricted_file`] an attacker could satisfy the check with a real
/// file and swap in a link before the chmod landed — an
/// arbitrary-file-chmod-to-0600 with corvex's privileges. `fchmod` has no such
/// window.
///
/// The comparison masks `0o7777`, not `0o777`: setuid, setgid and the sticky
/// bit are part of a planted file's mode too, and a file that is 0600 with
/// setgid set is not a file corvex should leave as it found it.
#[cfg(unix)]
fn tighten_to_0600(file: &std::fs::File, metadata: &std::fs::Metadata) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o7777 != 0o600 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Remove the extended ACL from a descriptor corvex is about to write a
/// credential (or a log, or a PID) through. macOS only, and the one hole
/// 0600 does not close there.
///
/// Darwin ACLs are not the POSIX kind. A macOS directory can carry ACEs
/// marked `file_inherit`, every file created inside it is given a copy, and
/// those entries are evaluated *independently of the mode bits* and before
/// them — so `chmod +a "someone allow read,file_inherit"` on a directory
/// makes every file later created in it readable by `someone` no matter what
/// its mode says. `fchmod` does not touch them: [`tighten_to_0600`] sees a
/// mode that is already 0600, has nothing to tighten, and leaves the ACE in
/// place. Nor do the checks in [`accept_restricted_file`] see it — the file
/// really is a regular, single-linked file this uid owns; the extra reader is
/// not recorded in `stat`.
///
/// That is reachable exactly where every other plant in this module is: the
/// `/tmp` fallback described on [`open_append_restricted`]. corvex creates
/// `/tmp/.config/xray` itself at 0700, but only if it is missing — an
/// attacker who pre-creates that hierarchy with an inheritable ACL gets a
/// readable copy of the xray config corvex writes into it, credentials and
/// all, without ever owning a single one of those files.
///
/// Linux needs no equivalent. POSIX draft ACLs there are masked by the group
/// permission bits: a file created with mode 0600 gets an `ACL_MASK` of
/// `---`, and `fchmod(0600)` recomputes it, so an inherited `default` entry
/// naming another user grants nothing.
///
/// A missing ACL is not an error, and neither is a filesystem that does not
/// store them: both are the state this function wants. An ACE somebody put on
/// one of these files deliberately goes the same way a deliberate `chmod
/// 0644` on them does, and for the same reason: corvex has exactly one
/// contract for the files it owns — reachable by their owner and nobody else
/// — and re-asserts it on every open rather than inheriting whatever the last
/// run, or the directory, left behind.
/// Whether [`strip_inherited_acl`] found an ACL on the descriptor it was
/// handed. `Removed` is only ever produced on macOS, and only where a
/// directory really did hand an ACE down; `Absent` is every other case,
/// including every filesystem that stores no ACLs at all.
///
/// The distinction exists for one caller: [`write_restricted`] cannot know
/// from the mode bits alone whether the inode it is about to put a credential
/// in was readable by somebody else a syscall ago, and this is the only
/// signal that says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Off macOS `Removed` is never constructed, which is the point: there is no
// inheritance to report. `dead_code` would rather it did not exist there.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
enum AclState {
    Absent,
    Removed,
}

#[cfg(target_os = "macos")]
fn strip_inherited_acl(file: &std::fs::File, path: &Path) -> std::io::Result<AclState> {
    use std::os::unix::io::AsRawFd;

    // `acl_get_fd_np(3)` and `acl_delete_fd_np(3)` are Darwin extensions
    // declared in <sys/acl.h> and exported by libSystem, which every Rust
    // binary on macOS already links; the `libc` crate binds none of the
    // `acl_*` family, so the declarations live here. `acl_type_t` is a C
    // enum, i.e. an `int`, and `ACL_TYPE_EXTENDED` (0x00000100) is the only
    // type Darwin stores.
    extern "C" {
        fn acl_get_fd_np(
            filedes: nix::libc::c_int,
            acl_type: nix::libc::c_int,
        ) -> *mut nix::libc::c_void;
        fn acl_init(count: nix::libc::c_int) -> *mut nix::libc::c_void;
        fn acl_set_fd_np(
            filedes: nix::libc::c_int,
            acl: *mut nix::libc::c_void,
            acl_type: nix::libc::c_int,
        ) -> nix::libc::c_int;
        fn acl_free(obj: *mut nix::libc::c_void) -> nix::libc::c_int;
    }
    const ACL_TYPE_EXTENDED: nix::libc::c_int = 0x0000_0100;

    // The verdict is taken from *reading* the ACL, not from whether the
    // write succeeded. `acl_set_fd_np` returning 0 says the descriptor
    // carries no extended ACL now; it says nothing about whether one was
    // there before, because setting an empty ACL on a file that had none is
    // a no-op that also returns 0. Reading its success as "an ACE was
    // inherited" does not fail safe:
    // [`create_in_private_dir`] reads `Removed` on a file it has just created
    // inside a directory it has just stripped as proof that the name was
    // swapped underneath it, and refuses the write. A delete that succeeds on
    // an ACL-less file would therefore turn every `write_restricted` on macOS
    // into a hard `PermissionDenied` — no `config.json`, no `xray.pid`, no
    // AWG conf — and every log into stderr-only. `acl_get_fd_np` has the
    // distinction built in: a null return with `ENOENT` is "no ACL of this
    // type", which is what an ordinary file has.
    //
    // SAFETY: the descriptor is owned by `file` and outlives the call, and
    // the type is the one constant Darwin stores. A non-null handle is owned
    // here and freed below.
    let existing = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if existing.is_null() {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            // ENOENT: no ACL of that type on the file - the good case, and the
            // common one. ENOTSUP and EOPNOTSUPP (distinct errnos on Darwin, 45
            // and 102): a filesystem that stores no ACLs at all, so there is
            // nothing to inherit either. Nothing is deleted in either case:
            // there is nothing there to delete.
            //
            // EINVAL is deliberately *not* in this arm. Darwin raises it in
            // libSystem, before the kernel is reached, for exactly one reason -
            // an `acl_type` that is not `ACL_TYPE_EXTENDED` - and that argument
            // is the constant above. Reading it as "nothing to strip" would
            // mean reading a bug in this file as a clean descriptor and writing
            // the credential through it anyway; the unsupported-filesystem case
            // that genuinely is benign has its own errnos above.
            Some(nix::libc::ENOENT) | Some(nix::libc::ENOTSUP) | Some(nix::libc::EOPNOTSUPP) => {
                Ok(AclState::Absent)
            }
            _ => Err(std::io::Error::new(
                err.kind(),
                format!("failed to read the ACL of {}: {err}", path.display()),
            )),
        };
    }
    // SAFETY: `existing` is the non-null handle from the call above. It is
    // owned here, freed exactly once, and not read afterwards - only its
    // existence mattered.
    unsafe {
        acl_free(existing);
    }

    // The strip itself is an empty ACL written over the file's, and not
    // `acl_delete_fd_np`, which is the call this reads like it should be.
    // That one fails with `ENOTSUP` on current macOS whatever the descriptor
    // and whatever the file — libSystem implements it as `fremovexattr` of
    // the ACL pseudo-attribute, which the kernel refuses on APFS, and the
    // path-based `acl_delete_link_np` behaves identically. It fails *after*
    // `acl_get_fd_np` has reported an ACL present, so the error arm below was
    // the only reachable outcome on exactly the files this function exists
    // for: a directory handing an ACE down turned every credential write into
    // a hard `PermissionDenied` instead of stripping it. Writing an ACL with
    // no entries leaves the same end state Darwin's own `chmod -N` does.
    //
    // SAFETY: `acl_init` returns either null or a handle owned here, freed
    // exactly once below and not read afterwards. `acl_set_fd_np` takes the
    // descriptor owned by `file`, that handle, and the one type constant
    // Darwin stores; it copies what it needs and retains nothing.
    let empty = unsafe { acl_init(0) };
    if empty.is_null() {
        let err = std::io::Error::last_os_error();
        return Err(std::io::Error::new(
            err.kind(),
            format!(
                "failed to build the empty ACL that clears {}: {err}",
                path.display()
            ),
        ));
    }
    let rc = unsafe { acl_set_fd_np(file.as_raw_fd(), empty, ACL_TYPE_EXTENDED) };
    let err = std::io::Error::last_os_error();
    unsafe {
        acl_free(empty);
    }
    if rc == 0 {
        return Ok(AclState::Removed);
    }
    match err.raw_os_error() {
        // An ACL was there a syscall ago and is not there now. Whoever took it
        // away, the file did carry an inherited ACE for a window, which is
        // precisely what `Removed` reports, so the callers' cold path is still
        // the right one. Every other errno is a strip that did not happen on a
        // file that demonstrably has an ACL, and that has to be an error: the
        // caller is about to write a credential through this descriptor.
        Some(nix::libc::ENOENT) => Ok(AclState::Removed),
        _ => Err(std::io::Error::new(
            err.kind(),
            format!("failed to remove the ACL of {}: {err}", path.display()),
        )),
    }
}

/// No-op off macOS; see the macOS twin for why Linux does not need one.
#[cfg(all(unix, not(target_os = "macos")))]
fn strip_inherited_acl(_file: &std::fs::File, _path: &Path) -> std::io::Result<AclState> {
    Ok(AclState::Absent)
}

/// Name of the file [`write_via_private_dir`] builds inside its staging
/// directory. Fixed, because the directory is the part that has to be
/// unguessable and the directory is corvex's own.
#[cfg(unix)]
const STAGED_FILE_NAME: &str = "staged";

/// Write `content` to `path` through a directory corvex creates itself, then
/// `rename` it into place.
///
/// The fallback [`write_restricted`] takes when the ordinary open found a
/// real ACL to strip. Stripping an ACE off a file makes the *file* private
/// from that syscall onwards; it does nothing about a descriptor an attacker
/// polling a predictable path may already hold on that same inode, and on
/// macOS the inherited ACE is what would have let them open it. The only way
/// to be sure the credential lands in an inode nobody else has ever been able
/// to open is for it never to have carried an ACE at all — which means
/// creating it somewhere that hands none down.
///
/// So: `mkdir` a fresh directory at 0700 (`create`, not `create_dir_all`, so
/// a name somebody else already made is an error rather than something to
/// reuse), strip *its* inherited ACL through a descriptor, and only then
/// create the file inside it. A file created under a directory with no
/// extended ACL inherits nothing, so there is no window to lose. `rename`
/// then moves that inode to `path`, and rename applies no inheritance — the
/// bytes are never visible under the final name in any other shape.
///
/// The staging directory goes next to the target rather than in `TMPDIR`,
/// because `rename` is only atomic within one filesystem, and the whole
/// guarantee here is that the file arrives complete or not at all.
///
/// What an attacker holding the parent directory can still do is delete or
/// swap what corvex leaves behind — that is inherent in owning the directory
/// and is why `accept_restricted_file` re-checks on every open. What they can
/// no longer do is *read* it.
#[cfg(unix)]
fn write_via_private_dir(path: &Path, content: &str) -> std::io::Result<()> {
    let staging = create_private_dir(&staging_parent(path))?;
    let result = write_into_private_dir(&staging, path, content);
    // Best effort, and after both outcomes: a successful rename leaves the
    // directory empty, a failure may leave the staged file in it, and neither
    // is worth turning into the error the caller sees.
    let _ = std::fs::remove_file(staging.join(STAGED_FILE_NAME));
    let _ = std::fs::remove_dir(&staging);
    result
}

/// `mkdir` a directory in `parent` that corvex is certain it created itself,
/// and return its path.
///
/// The name only has to be unpredictable enough that an attacker cannot
/// pre-create it and wait; it does not have to be secret, because what
/// protects the file inside is the stripped ACL and 0600, not the name. Hence
/// pid plus the nanosecond field of the clock rather than a CSPRNG. An
/// `AlreadyExists` is retried with a fresh reading instead of being reused:
/// a directory somebody else made is exactly what this function exists to
/// avoid returning.
#[cfg(unix)]
fn create_private_dir(parent: &Path) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;

    for attempt in 0..8u32 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.subsec_nanos())
            .unwrap_or(attempt);
        let candidate = parent.join(format!(".corvex-{}-{nanos}-{attempt}", std::process::id()));
        match std::fs::DirBuilder::new().mode(0o700).create(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "could not create a private staging directory in {}",
            parent.display()
        ),
    ))
}

/// The middle of [`write_via_private_dir`], split out so the cleanup there
/// runs on every path out of it. The checks that make the staging directory
/// trustworthy live in [`create_in_private_dir`], which the append twin
/// shares.
#[cfg(unix)]
fn write_into_private_dir(staging: &Path, path: &Path, content: &str) -> std::io::Result<()> {
    let mut file = create_in_private_dir(staging, false)?;
    std::io::Write::write_all(&mut file, content.as_bytes())?;
    drop(file);
    std::fs::rename(staging.join(STAGED_FILE_NAME), path)
}

/// The directory `write_via_private_dir` and `append_via_private_dir` stage
/// in: the target's own, so the `rename` that follows stays inside one
/// filesystem and is therefore atomic.
#[cfg(unix)]
fn staging_parent(path: &Path) -> PathBuf {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Vet the staging directory and create the file inside it, in `append` mode
/// or not. Shared by both private-dir writers, because everything up to the
/// first byte is the same question for a credential and for a log.
///
/// The checks on the directory are what a swapped name would fail:
/// `O_NOFOLLOW` so the name is not a link somebody left pointing elsewhere,
/// `O_DIRECTORY` so it is not a file, an owner that is this uid, and no group
/// or other permission bits at all. The owner check is the one that catches a
/// substitution — nobody else can produce a directory owned by corvex's uid —
/// and the mode check is what makes the file created inside unreachable to
/// anyone else regardless. It reads the group and other bits rather than
/// demanding exactly 0700, because `mkdir` takes the umask off the mode it is
/// given and only the absence of those bits actually matters here.
#[cfg(unix)]
fn create_in_private_dir(staging: &Path, append: bool) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
        .open(staging)?;
    let dir_meta = dir.metadata()?;
    // SAFETY: `geteuid` reads the calling process's own credentials, takes no
    // arguments and cannot fail.
    let euid = unsafe { nix::libc::geteuid() };
    if dir_meta.uid() != euid || dir_meta.permissions().mode() & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} is not the private directory corvex just created",
                staging.display()
            ),
        ));
    }
    strip_inherited_acl(&dir, staging)?;

    let staged = staging.join(STAGED_FILE_NAME);
    let file = std::fs::OpenOptions::new()
        .write(!append)
        .read(append)
        .append(append)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(&staged)?;
    let metadata = accept_restricted_file(&file, &staged)?;
    tighten_to_0600(&file, &metadata)?;
    if strip_inherited_acl(&file, &staged)? == AclState::Removed {
        // The directory it was created in had its own ACL removed a syscall
        // earlier, so an ACE on this file means the name no longer refers to
        // that directory. Fail rather than retry: this write cannot be made
        // private here, and a caller that hears about it is better off than
        // one handed a credential in a readable file.
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} inherited an ACL from a directory corvex did not create",
                staged.display()
            ),
        ));
    }
    Ok(file)
}

/// Replace the inode behind an append-mode log with one that never carried an
/// inherited ACE, carrying the bytes already in it across, and hand back a
/// descriptor on the replacement.
///
/// The append twin of [`write_via_private_dir`], and it exists for the same
/// reason: on macOS the file [`open_append_restricted`] just created was
/// given a copy of the directory's `file_inherit` ACE, and it carried it for
/// the two syscalls between `open` and the strip. Stripping fixes the file;
/// it does not close a descriptor somebody opened in that window, and that
/// descriptor goes on seeing everything appended to the inode afterwards —
/// which for `corvex.log` is the record of the run, and for `xray.log` is
/// xray's own stderr.
///
/// `vetted` is the descriptor from that open, not the path: the previous
/// contents are copied *through it*, so nothing between here and the
/// `rename` can substitute what gets copied. It is opened read-write by
/// [`open_append_vetted`] for exactly this. The copy is bounded by the
/// rotation [`LOG_MAX_BYTES`] applies before the open.
///
/// The old inode is unlinked by the `rename`, so a descriptor an attacker
/// holds keeps only what it could already read: nothing at all when the file
/// was created by this same call, and otherwise the bytes of previous runs,
/// which were never private from it.
#[cfg(unix)]
fn append_via_private_dir(
    path: &Path,
    mut vetted: std::fs::File,
) -> std::io::Result<std::fs::File> {
    let staging = create_private_dir(&staging_parent(path))?;
    let result = append_into_private_dir(&staging, path, &mut vetted);
    // Best effort, and after both outcomes, exactly as in the write twin.
    let _ = std::fs::remove_file(staging.join(STAGED_FILE_NAME));
    let _ = std::fs::remove_dir(&staging);
    result
}

/// The middle of [`append_via_private_dir`], split out so the cleanup there
/// runs on every path out of it.
#[cfg(unix)]
fn append_into_private_dir(
    staging: &Path,
    path: &Path,
    vetted: &mut std::fs::File,
) -> std::io::Result<std::fs::File> {
    use std::io::Seek;

    let mut file = create_in_private_dir(staging, true)?;
    // `O_APPEND` governs writes only, so the read cursor is this function's
    // to move; the descriptor is handed back to the caller as a writer and
    // every write through it lands at the end regardless.
    vetted.rewind()?;
    std::io::copy(vetted, &mut file)?;
    std::fs::rename(staging.join(STAGED_FILE_NAME), path)?;
    Ok(file)
}

/// Create `dir` and any missing parent, with 0700 on every component this call
/// creates.
///
/// Defence in depth behind [`accept_restricted_file`], not a replacement for
/// it: a directory corvex creates itself is one an attacker cannot plant a
/// file in afterwards, which removes the `/tmp`-fallback exposure entirely for
/// the ordinary case of a fresh machine. It does nothing for a directory that
/// already exists — `create_dir_all` semantics, so an existing one is left
/// exactly as it is, deliberately: corvex has no business widening or
/// narrowing `~/.config` because it happened to want a subdirectory of it, and
/// chmod-ing a directory the attacker already owns would not help anyway.
/// That case is the descriptor check's to catch.
pub fn create_dir_restricted(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(windows)]
    {
        // The mode bits have no Windows meaning, but the directory this would
        // create is where the DACL of every file under it comes from, so the
        // one location corvex cannot vouch for is refused here as well as at
        // the opens — earlier, and with the same message.
        ensure_per_user_location(dir)?;
        std::fs::create_dir_all(dir)
    }
}

/// Maximum size `corvex.log` is allowed to reach before it is rotated.
pub const LOG_MAX_BYTES: u64 = 5 * 1024 * 1024;

/// Open `path` for appending, creating it with 0o600 on unix.
///
/// `write_restricted` cannot be reused here: it opens with `.truncate(true)`,
/// so backing a log with it would discard the previous run's records on every
/// start. This is its append-mode twin. An already-existing file also has its
/// mode tightened to 0o600, because `.mode()` only applies at creation: a file
/// already sitting at the log path with a looser mode — put there by hand, by a
/// future build with a different default, or by a `sudo` run under a different
/// `HOME` — would otherwise stay exposed for as long as it is appended to. A
/// file at that path owned by anyone else is refused outright rather than
/// tightened; see [`accept_restricted_file`] for why tightening is not enough.
#[cfg(unix)]
pub fn open_append_restricted(path: &Path) -> std::io::Result<std::fs::File> {
    let (file, acl) = open_append_vetted(path)?;
    if acl == AclState::Removed {
        // The same reasoning [`write_restricted`] applies to a credential,
        // applied to a log: a stripped ACE makes the *file* private from that
        // syscall onwards and does nothing about a descriptor somebody
        // polling this very predictable path already holds on the inode.
        // They would go on reading every line appended to it — the record of
        // what a `start` did, and, for `xray.log`, whatever xray writes to
        // stderr. So the inode is replaced by one created where nothing is
        // inherited, exactly as the credential path does it; the difference
        // is that a log has a past worth keeping, so the bytes already in it
        // are carried across first.
        return append_via_private_dir(path, file);
    }
    Ok(file)
}

/// The plain half of [`open_append_restricted`]: the open, the checks, and
/// what the ACL strip found — split out so the decision above reads as one
/// line and the cold path can be told apart from the ordinary one.
#[cfg(unix)]
fn open_append_vetted(path: &Path) -> std::io::Result<(std::fs::File, AclState)> {
    use std::os::unix::fs::OpenOptionsExt;

    // Before the open, and for the same reason [`open_write_restricted`] runs
    // it there: `O_NOFOLLOW` refuses a link at `corvex.log` itself and says
    // nothing about a link at `/tmp/.local`, which resolves to wherever its
    // owner points it and takes every check below with it.
    ensure_trusted_ancestry(path)?;

    // `O_NOFOLLOW`, because `open` follows a symlink: appending to a link's
    // target is as bad as chmod-ing it. `state_dir` falls back to `/tmp` when
    // `HOME` and `XDG_STATE_HOME` are both unset — a stripped `env -i` run, a
    // systemd unit with no `Environment=HOME=`, a launchd job — which puts the
    // log under a world-writable directory. Anyone could pre-create
    // `/tmp/.local/state/corvex/corvex.log` as a link to a file corvex can
    // write (a shell rc, a crontab, a unit drop-in) and have every `info!` line
    // appended there, as root if corvex runs as root. Refusing the open costs
    // a deliberate symlink, which nothing documents as supported; the error
    // (`ELOOP`) reaches `prepare_log_file_at`, which degrades to stderr-only
    // with a message like any other open failure. `O_NONBLOCK` and the checks
    // in `accept_restricted_file` close the same directory's other plantable
    // shapes: a FIFO, a foreign-owned file, a hard link.
    //
    // `.read(true)` alongside `.append(true)` is for one caller: the
    // ACL-replacement path above has to copy what is already in the file into
    // its replacement, and doing that through *this* descriptor rather than a
    // second open of the same name is what stops the copy racing a swap. The
    // descriptor is only ever written through otherwise, and it is 0600
    // either way. The one shape it turns away that a write-only open would
    // have accepted is a log left mode 0200 - writable by its owner but not
    // readable - which is nobody's default and which reports itself like any
    // other open failure, naming the file.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = accept_restricted_file(&file, path)?;
    // Nothing is written between the open and here, so a pre-existing loose
    // file is never appended to while it is still loose.
    tighten_to_0600(&file, &metadata)?;
    let acl = strip_inherited_acl(&file, path)?;
    Ok((file, acl))
}

/// Windows has no mode bits; the file inherits the ACL of `%LOCALAPPDATA%`
/// (or of the `%USERPROFILE%` fallback [`windows_per_user_dir`] rebuilds),
/// which is per-user either way — and the temporary directory it falls back
/// to last, which is not, is refused by [`shared_fallback_rejection`]. The
/// reparse-point refusal is the same one [`open_write_restricted`] makes and
/// for the same reason: appending every `info!` line to a junction's target
/// is the Windows shape of the symlink case this function's unix twin
/// refuses.
#[cfg(windows)]
pub fn open_append_restricted(path: &Path) -> std::io::Result<std::fs::File> {
    ensure_per_user_location(path)?;
    open_no_reparse(std::fs::OpenOptions::new().create(true).append(true), path)
}

/// Append-open a file whose *path* corvex did not choose: the log targets the
/// user names in `log.xray.*`.
///
/// Deliberately not [`open_append_restricted`]. A path the user typed is a
/// path the user meant, including the shapes that function refuses on
/// corvex's own files: a symlink redirecting the log somewhere else, a
/// root-owned `/var/log/xray/error.log` in a group-writable directory,
/// `/dev/null` to discard it, a FIFO feeding a log shipper. corvex has no
/// business overruling any of those, and `preflight_log_paths` already
/// documents the symlink case as user intent.
///
/// What it does refuse to do is *hang*. `open` on a FIFO with no reader
/// attached blocks in the kernel until one appears, and this open runs before
/// xray is spawned, so a readerless FIFO anywhere in the log config wedges
/// `corvex start` with no output at all. `O_NONBLOCK` turns that into an
/// immediate `ENXIO` the caller reports like any other open failure.
///
/// The flag is then cleared, because it is wanted for the duration of `open`
/// and no longer: this descriptor becomes xray's stdout and stderr, and a
/// non-blocking write to a full pipe fails with `EAGAIN` and drops the line
/// rather than waiting its turn.
#[cfg(unix)]
pub fn open_append_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)?;

    // SAFETY: `fcntl` here reads and writes the file status flags of a
    // descriptor this function owns. Both commands take an `int` and return
    // an `int`; neither touches memory the caller owns.
    let flags = unsafe { nix::libc::fcntl(file.as_raw_fd(), nix::libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let cleared = flags & !nix::libc::O_NONBLOCK;
    if cleared != flags {
        // SAFETY: as above.
        let rc = unsafe { nix::libc::fcntl(file.as_raw_fd(), nix::libc::F_SETFL, cleared) };
        if rc == -1 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(file)
}

/// Windows has no `O_NONBLOCK` and no FIFOs of this shape; the plain open is
/// the whole of it.
#[cfg(windows)]
pub fn open_append_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

/// Whether corvex, rather than the user, chose `path` for one of xray's
/// logs.
///
/// Three paths qualify, and all three are corvex's own picks under the state
/// directory: `xray.log` for the process's stdout/stderr, and the `access.log`
/// and `error.log` that [`crate::protocol::XrayLogConfig::default`] writes
/// into the generated xray config when `log.xray.access`/`log.xray.error` say
/// nothing. `run()` replaces each of these wholesale with the configured
/// value, so equality with the default is exactly the question "did anyone
/// ask for this path".
///
/// Getting the set wrong is not cosmetic: it decides which open
/// [`open_xray_log`] makes, and treating a corvex-chosen path as
/// user-configured means following a symlink planted at it — creating and
/// appending to whatever it names, in the same world-writable `/tmp` fallback
/// every other check in this module is about. Only `xray.log` used to be
/// listed here, which left the two defaults corvex writes into xray's own
/// config on the lenient side.
///
/// Each default is compared twice, and the second comparison is the one that
/// earns its keep. `access.log` and `error.log` do not reach the preflight as
/// the `PathBuf`s below: [`crate::protocol::XrayLogConfig`] carries them as
/// `String`, because a `String` is what goes into xray's JSON config, and it
/// builds them with `to_string_lossy`; `main::xray_log_preflight_targets`
/// turns them back into a `PathBuf`. That round trip is the identity only
/// while the path is valid UTF-8. A single stray byte in `$XDG_STATE_HOME`
/// or `$HOME` — legal on unix, where a path is bytes and not text — comes
/// back as U+FFFD, the reconstructed path stops equalling the original, and
/// [`open_xray_log`] takes the *lenient* branch for precisely the two paths
/// the strict branch was added to protect. So the lossy rendering of each
/// default counts as that default. The reverse mistake is harmless: a path
/// the user named that collides with one of these renderings is opened
/// strictly, which refuses more than it must rather than less.
pub fn is_corvex_chosen_xray_log(path: &Path) -> bool {
    matches_chosen_xray_log(
        path,
        &[
            default_xray_log(),
            default_xray_access_log(),
            default_xray_error_log(),
        ],
    )
}

/// The pure half of [`is_corvex_chosen_xray_log`], holding the decision the
/// doc comment above describes. Split out because the round trip only bites
/// on a path that is not valid UTF-8, and the state directory of whatever
/// process runs the tests is not one — passing the candidates in is the only
/// way to pin it without mutating the environment out from under every
/// sibling test.
fn matches_chosen_xray_log(path: &Path, chosen: &[PathBuf]) -> bool {
    chosen.iter().any(|candidate| {
        let lossy = candidate.to_string_lossy();
        path == candidate.as_path() || path == Path::new(lossy.as_ref())
    })
}

/// Refuse a path whose *directory* someone other than its owner can
/// rearrange, before handing that path to xray.
///
/// The final-component checks in [`accept_restricted_file`] are made through
/// a descriptor, so what they vet is what corvex then writes through — no
/// window between the two. Two things fall outside that guarantee, and this
/// is the answer to both.
///
/// The first is a name handed to a second process. `access.log` and
/// `error.log` reach xray as *strings* in its generated config and xray opens
/// them itself, following whatever it finds, and `preflight_log_paths`
/// opening them a moment earlier says nothing about what is at the name when
/// xray gets there. A symlink planted in that window is appended to by xray,
/// with corvex's privileges. `config.json` is the same shape and worse
/// content: corvex writes the VLESS UUID or Trojan password into it and then
/// passes the *path* to `xray run -c`, so anyone who can swap that entry
/// between the write and the spawn chooses xray's inbounds and outbounds.
/// [`crate::engine::awg::write_conf`] is the sharpest case of all, and says
/// so itself.
///
/// The second is subtler and applies even where corvex never lets go of the
/// descriptor. `O_NOFOLLOW` refuses a symlink at the *last* component only —
/// the kernel resolves every parent as usual, symlinked ones included — so an
/// ancestor another account can replace decides which file the vetted
/// descriptor refers to. In the `/tmp` fallback that is a plant anyone with a
/// shell can leave: `/tmp/.config/xray` pointed at a directory holding a
/// readable `config.json` of corvex's own uid passes the owner, regular-file
/// and link-count checks, is tightened to 0600, truncated, and filled with
/// credentials that whoever opened it beforehand goes on reading through
/// their existing descriptor. [`create_dir_restricted`] does not stand in the
/// way: it leaves an existing ancestor exactly as it finds it, deliberately,
/// and an existing ancestor is what a symlink to a real directory looks like.
/// So every restricted open asks this first, and so does
/// [`rotate_if_oversized`], which acts on the name rather than on a
/// descriptor.
///
/// The only thing that closes it is the directory. Nobody can plant, swap or
/// unlink an entry in a directory they cannot write, so if every ancestor of
/// the log is owned by this uid (or root) and grants no write to group or
/// other, the point-in-time check becomes a lasting one. That is the whole of
/// this function, and it is why it walks the chain rather than looking at the
/// leaf: a private directory inside a world-writable one can be renamed out
/// of the way wholesale.
///
/// The sticky bit is the documented exception, and it is the one that keeps
/// the `/tmp` fallback working: `/tmp` is 1777 precisely so that an entry in
/// it can only be renamed or unlinked by its owner, which is the property
/// this check is after. corvex creates `/tmp/.local/state/xray` itself at
/// 0700 ([`create_dir_restricted`]), so the chain below `/tmp` is its own.
///
/// The chain is resolved here, a component at a time, and *not* by handing
/// the path to `canonicalize` first. Canonicalizing answers the wrong
/// question: it reports the directories the name resolves to at this instant,
/// and those are not what xray reopens — xray reopens the name corvex wrote
/// into its config, symlinked components and all. A walk over the canonical
/// chain therefore never looks at the directory *holding* a link, so a link
/// on corvex's own path (`/tmp/.local`, under the `HOME`-unset fallback,
/// which anyone with a shell can plant) is resolved away and never judged: it
/// can point at a trusted tree while this runs and anywhere its owner likes
/// by the time xray opens the log, and the sticky bit on `/tmp` does not
/// help, because sticky stops everyone *except* the entry's owner and the
/// entry is theirs.
///
/// So every component is judged as the walk passes through it: a directory by
/// [`untrusted_ancestor_rejection`], a symlink by [`untrusted_link_rejection`]
/// before its target is walked in turn. A link nobody but this uid or root
/// can replace is as good as the directory it names, which is what keeps the
/// legitimate cases working — `/var` → `/private/var` on macOS, `/home`
/// → `/usr/home`, a home directory moved to another volume.
///
/// Asked of every path corvex chose itself, and of no path the user chose. A
/// log the user named in `log.xray.*` is theirs to place, `/var/log/xray` and
/// a group-writable spool directory included, for the same reason it gets the
/// lenient open — and naming both logs is still the way out when it is those
/// two directories this refuses. What it no longer rescues is a home
/// directory belonging to another uid, since `config.json`, `xray.pid`,
/// `corvex.log` and `xray.log` are checked too and none of them has a
/// configurable path; `XDG_CONFIG_HOME` and `XDG_STATE_HOME` are the answer
/// there, and [`with_log_escape_hatch`] says so.
///
/// [`crate::engine::awg::write_conf`] asks it of the AWG config too, ahead of
/// the write, for the same reason in a sharper form: that file is handed by
/// name to `sudo awg-quick`, which runs its `PostUp`/`PreUp` lines as root.
#[cfg(unix)]
pub fn ensure_trusted_ancestry(path: &Path) -> std::io::Result<()> {
    let parent = staging_parent(path);
    // A relative path is resolved against the working directory, which is
    // where the kernel would resolve it from too. Every caller passes an
    // absolute path; this is here so the walk below can start at `/`
    // unconditionally.
    let absolute = if parent.is_absolute() {
        parent
    } else {
        std::env::current_dir()?.join(parent)
    };
    // SAFETY: `geteuid` reads the calling process's own credentials, takes no
    // arguments and cannot fail.
    let euid = unsafe { nix::libc::geteuid() };
    // `/` is checked once here rather than at the top of every recursion.
    let root = Path::new("/");
    reject_untrusted_directory(root, &std::fs::symlink_metadata(root)?, euid)?;
    walk_trusted_ancestry(&absolute, euid, &mut 0).map(|_| ())
}

/// Judge one directory the chain passes through: the numbers first, then the
/// ACL they do not show.
///
/// Split out because `/` is judged by [`ensure_trusted_ancestry`] and every
/// component below it by [`walk_trusted_ancestry`], and the two have to
/// decide the same way.
#[cfg(unix)]
fn reject_untrusted_directory(
    dir: &Path,
    meta: &std::fs::Metadata,
    euid: u32,
) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mode = meta.permissions().mode();
    // Only asked when the bit is actually set: the answer costs an NSS lookup
    // and, on Linux, an `lgetxattr`, and the overwhelmingly common directory
    // is not group-writable at all.
    let group_write_trusted = mode & 0o020 != 0 && group_write_is_private(dir, meta.gid(), euid)?;
    if let Some(err) = untrusted_ancestor_rejection(
        dir,
        meta.is_dir(),
        meta.uid(),
        euid,
        mode,
        group_write_trusted,
    ) {
        return Err(err);
    }
    if let Some(acl) = extended_acl_text(dir)? {
        if let Some(err) = untrusted_acl_rejection(dir, &acl, euid) {
            return Err(err);
        }
    }
    Ok(())
}

/// Symbolic links [`walk_trusted_ancestry`] follows before it gives up. The
/// kernel answers `ELOOP` on a chain that never ends; this walk follows the
/// links itself, so it has to count them itself.
#[cfg(unix)]
const MAX_ANCESTRY_SYMLINKS: u32 = 32;

/// Resolve `dir` one component at a time, judging every entry the resolution
/// passes through, and hand back the directory it ends at.
///
/// Recurses once per symlink, with `hops` shared across the whole resolution
/// so a loop ends in an error instead of a spin — and so the recursion is
/// bounded, since only a link can deepen it.
#[cfg(unix)]
fn walk_trusted_ancestry(dir: &Path, euid: u32, hops: &mut u32) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    let mut current = PathBuf::from("/");
    for component in dir.components() {
        match component {
            // Windows-only, and `/` is where this walk starts regardless.
            Component::Prefix(_) | Component::RootDir => current = PathBuf::from("/"),
            Component::CurDir => {}
            // `current` holds no unresolved link, so the directory it names is
            // the one `..` leads out of.
            Component::ParentDir => {
                current.pop();
            }
            Component::Normal(name) => {
                let candidate = current.join(name);
                let meta = std::fs::symlink_metadata(&candidate)?;
                if meta.file_type().is_symlink() {
                    if let Some(err) = untrusted_link_rejection(&candidate, meta.uid(), euid) {
                        return Err(err);
                    }
                    *hops += 1;
                    if *hops > MAX_ANCESTRY_SYMLINKS {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("too many symbolic links while resolving {}", dir.display()),
                        ));
                    }
                    let target = std::fs::read_link(&candidate)?;
                    // A relative target is resolved against the directory
                    // holding the link, exactly as the kernel resolves it.
                    let target = if target.is_absolute() {
                        target
                    } else {
                        current.join(target)
                    };
                    current = walk_trusted_ancestry(&target, euid, hops)?;
                } else {
                    reject_untrusted_directory(&candidate, &meta, euid)?;
                    current = candidate;
                }
            }
        }
    }
    Ok(current)
}

/// The refusal [`walk_trusted_ancestry`] makes on a symbolic link in the
/// chain, kept pure for the reason [`untrusted_ancestor_rejection`] is: the
/// case that matters is a link some other uid owns, and the suite cannot
/// become a second uid.
///
/// Only the owner is read. A symlink's own mode bits are meaningless — Linux
/// fixes them at 0777 and no unix consults them — so what decides whether the
/// link can be repointed is who may replace the entry: its owner, the owner
/// of the directory holding it (which the walk has already accepted), or
/// root.
#[cfg(unix)]
fn untrusted_link_rejection(link: &Path, uid: u32, euid: u32) -> Option<std::io::Error> {
    if uid == euid || uid == 0 {
        return None;
    }
    Some(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "{} is a symbolic link owned by uid {uid}, who can repoint it after \
             this check and before the file is used; put the file under a \
             directory you own",
            link.display()
        ),
    ))
}

/// The pure core of [`ensure_trusted_ancestry`]: every refusal it makes,
/// decided from a bool and three numbers, so the foreign-owner case — which a
/// test cannot stage without becoming a second uid — is tested like the rest.
///
/// `uid == 0` is accepted alongside the effective uid because the ordinary
/// chain above a home directory (`/`, `/home`, `/Users`, `/tmp`) belongs to
/// root, and a machine whose root is hostile has already lost.
///
/// `group_write_trusted` is the one thing here the numbers alone cannot
/// settle, so [`reject_untrusted_directory`] settles it and passes the answer
/// in: it is whether the group holding the write bit is this user's own
/// private group, holding nobody else. See [`group_write_is_private`] for why
/// that question has to be asked at all — a blanket refusal of group-write
/// rejects the default shape of a Debian or Ubuntu home directory.
#[cfg(unix)]
fn untrusted_ancestor_rejection(
    dir: &Path,
    is_dir: bool,
    uid: u32,
    euid: u32,
    mode: u32,
    group_write_trusted: bool,
) -> Option<std::io::Error> {
    if !is_dir {
        return Some(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a directory", dir.display()),
        ));
    }
    if uid != euid && uid != 0 {
        return Some(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} is owned by uid {uid}, so its contents can be replaced by \
                 someone else; put the file under a directory you own",
                dir.display()
            ),
        ));
    }
    // 0o1000 is the sticky bit: it is what makes a shared directory safe, by
    // restricting rename and unlink to the owner of each entry.
    if mode & 0o1000 == 0 {
        // World-write is never anything but a hole. Group-write is only as
        // wide as the group, and a private group holds this user alone.
        let world_writable = mode & 0o002 != 0;
        let shared_group = mode & 0o020 != 0 && !group_write_trusted;
        if world_writable || shared_group {
            return Some(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "{} is writable by other users (mode {:04o}), so anything corvex \
                     leaves in it can be swapped; fix with: chmod go-w {}",
                    dir.display(),
                    mode & 0o7777,
                    shell_quote(&dir.display().to_string())
                ),
            ));
        }
    }
    None
}

/// Whether the group write bit on `dir` grants nothing the owner does not
/// already have — that is, whether the owning group is this user's own
/// private group.
///
/// This exists because a blanket refusal of group-write refuses the default
/// shape of a mainstream Linux desktop. Debian and Ubuntu ship
/// `USERGROUPS_ENAB yes` with `pam_umask`, which lowers a normal user's umask
/// to 002 precisely *because* their primary group holds them alone, so every
/// directory they create — `~/.config`, `~/.local`, `~/.local/state` — lands
/// at 0775 owned by `alice:alice`. Refusing those aborts `start` on a stock
/// install, and `chmod go-w` is a change to directories corvex does not own.
///
/// Three things have to hold, and the third is the one that is easy to miss:
///
/// 1. `gid == euid`. This is the user-private-group convention — the group is
///    created with the account, named after it and numbered after it. It is
///    also what keeps macOS strict: every local account there is in `staff`
///    (gid 20) while uids start at 501, so a group-writable directory on
///    macOS is refused exactly as before. A shared `users` (gid 100) fails it
///    for the same reason.
/// 2. The group lists no supplementary members. `gid == euid` says the group
///    was *created* private; `getgrgid` says nobody has been added to it
///    since. This is the one condition that is not airtight, and the gap is
///    worth stating rather than arguing away: `gr_mem` holds *supplementary*
///    members only, so an account carrying this gid as its **primary** group
///    is invisible here. Condition 1 pins the *directory's* gid to this uid's
///    number; it says nothing about who else was given that number in
///    `/etc/passwd`. Closing it would mean enumerating every passwd entry on
///    every directory of every walk — and still missing NSS sources that do
///    not enumerate — to cover a machine that has abandoned the very
///    convention this exception exists to accommodate. So: on a machine where
///    gids were assigned by hand, a hand-made sharer of this gid can write an
///    ancestor that the walk accepts. `chmod go-w` on that ancestor is the
///    answer, and it is the shape the walk demanded before this exception.
/// 3. On Linux, no POSIX ACL is stored on the directory. This is the subtle
///    one: there the group bits are the ACL *mask*, so `setfacl -m u:bob:rwx`
///    on a 0700 directory recomputes the mode to 0770 and bob's grant hides
///    behind a group bit that conditions 1 and 2 would happily call private.
///    That is the very hole [`extended_acl_text`] says Linux does not need a
///    reader for, and it only stays closed while group-write is refused
///    outright — so relaxing it means asking. Presence of the xattr is enough
///    to refuse; there is no need to parse it, because a directory carrying a
///    non-trivial ACL is not one whose access this walk can vouch for from
///    three numbers.
///
/// An error reading any of it is not silently a `false`: it is returned, so a
/// directory whose access cannot be established fails the walk rather than
/// passing it.
#[cfg(unix)]
fn group_write_is_private(dir: &Path, gid: u32, euid: u32) -> std::io::Result<bool> {
    if gid != euid {
        return Ok(false);
    }
    if has_posix_acl(dir)? {
        return Ok(false);
    }
    group_has_no_other_members(gid)
}

/// Whether the group `gid` lists no supplementary members, i.e. condition 2
/// of [`group_write_is_private`].
///
/// A gid with no group entry at all is not private: it is a directory whose
/// group this machine cannot name, which is not something to extend trust to.
#[cfg(unix)]
fn group_has_no_other_members(gid: u32) -> std::io::Result<bool> {
    let group = nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(gid))
        .map_err(|err| std::io::Error::from_raw_os_error(err as i32))?;
    Ok(group.is_some_and(|group| group.mem.is_empty()))
}

/// Whether `dir` carries a POSIX ACL, i.e. condition 3 of
/// [`group_write_is_private`].
///
/// `lgetxattr` rather than `getxattr`: [`walk_trusted_ancestry`] resolves
/// links itself and judges each one on the way, so this must not follow one
/// that appeared since the `lstat`, exactly as [`extended_acl_text`] uses
/// `acl_get_link_np`. Only the size is asked for — the contents do not matter,
/// only that there are some.
#[cfg(target_os = "linux")]
fn has_posix_acl(dir: &Path) -> std::io::Result<bool> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(dir.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} contains an interior NUL", dir.display()),
        )
    })?;
    let name = c"system.posix_acl_access";
    // SAFETY: both pointers are NUL-terminated strings owned by locals that
    // outlive the call. A null value pointer with a zero size is the
    // documented way to ask `lgetxattr` for the length alone, so nothing is
    // written back.
    let size =
        unsafe { nix::libc::lgetxattr(c_path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if size >= 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        // ENODATA: no ACL on this directory, which is the ordinary case.
        // ENOTSUP: a filesystem that stores none at all. Both mean the mode
        // bits are the whole story, which is what this asks. EOPNOTSUPP is
        // not listed beside it the way [`extended_acl_text`] lists it: on
        // Linux the two are the same number, and spelling both is an
        // unreachable arm. On Darwin they differ, which is that function's
        // business and not this one's.
        Some(nix::libc::ENODATA) | Some(nix::libc::ENOTSUP) => Ok(false),
        _ => Err(std::io::Error::new(
            err.kind(),
            format!("failed to read the ACL of {}: {err}", dir.display()),
        )),
    }
}

/// Always `false` off Linux, and not a gap. macOS stores its ACLs in a
/// different scheme entirely, and [`reject_untrusted_directory`] reads them
/// through [`extended_acl_text`] for *every* directory — group-writable or
/// not — so a Darwin ACE granting another account write is refused by
/// [`untrusted_acl_rejection`] before this question is reached.
#[cfg(all(unix, not(target_os = "linux")))]
fn has_posix_acl(_dir: &Path) -> std::io::Result<bool> {
    Ok(false)
}

/// The extended ACL of `dir`, in the text form `acl_to_text(3)` renders, or
/// `None` when it carries none.
///
/// The mode bits are not the whole access story on macOS. An ACL is consulted
/// *ahead* of them and grants rights they do not, so
/// `chmod +a "bob allow add_file,delete_child" ~/.local/state` leaves a
/// directory `stat` still reports as 0700 — and
/// [`untrusted_ancestor_rejection`] still accepts — that bob can plant and
/// swap entries in for as long as it exists. That defeats the one thing this
/// walk is for: its verdict has to outlive the call, because xray reopens
/// `access.log`/`error.log` by name after the preflight closed them, and
/// `sudo awg-quick` reads the AWG config by name after
/// [`crate::engine::awg::write_conf`] wrote it. So the ACL is read too.
///
/// `acl_get_link_np(3)` rather than `acl_get_file(3)`: this walk resolves
/// links itself and judges each one on the way, so the ACL lookup must not
/// quietly follow one that appeared since the `lstat`. The `acl_*` family is
/// a Darwin extension exported by libSystem and bound by no crate here,
/// exactly as [`strip_inherited_acl`] describes.
#[cfg(target_os = "macos")]
fn extended_acl_text(dir: &Path) -> std::io::Result<Option<String>> {
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt;

    extern "C" {
        fn acl_get_link_np(
            path: *const nix::libc::c_char,
            acl_type: nix::libc::c_int,
        ) -> *mut nix::libc::c_void;
        fn acl_to_text(
            acl: *mut nix::libc::c_void,
            len_p: *mut nix::libc::ssize_t,
        ) -> *mut nix::libc::c_char;
        fn acl_free(obj: *mut nix::libc::c_void) -> nix::libc::c_int;
    }
    const ACL_TYPE_EXTENDED: nix::libc::c_int = 0x0000_0100;

    let c_path = CString::new(dir.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} contains an interior NUL", dir.display()),
        )
    })?;
    // SAFETY: the argument is a NUL-terminated path owned by `c_path`, which
    // outlives the call, and the type is the one constant Darwin stores. The
    // handle that comes back is owned here and freed below on every path.
    let acl = unsafe { acl_get_link_np(c_path.as_ptr(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            // ENOENT: no ACL of that type, which is the ordinary case and the
            // one this walk hopes for. ENOTSUP/EOPNOTSUPP: a filesystem that
            // stores none at all. EINVAL is left out for the reason
            // [`strip_inherited_acl`] leaves it out — Darwin raises it for a
            // wrong `acl_type`, so reading it as "nothing there" would mean
            // reading a bug in this file as a clean directory.
            Some(nix::libc::ENOENT) | Some(nix::libc::ENOTSUP) | Some(nix::libc::EOPNOTSUPP) => {
                Ok(None)
            }
            _ => Err(std::io::Error::new(
                err.kind(),
                format!("failed to read the ACL of {}: {err}", dir.display()),
            )),
        };
    }
    // SAFETY: `acl` is the non-null handle from the call above. `acl_to_text`
    // reads it and returns a NUL-terminated buffer it allocated for this
    // caller, which is copied out and freed here; a null return is an error
    // with `errno` set. `acl_free` is then given the handle itself.
    let rendered = unsafe {
        let text = acl_to_text(acl, std::ptr::null_mut());
        let rendered = if text.is_null() {
            Err(std::io::Error::last_os_error())
        } else {
            let owned = CStr::from_ptr(text).to_string_lossy().into_owned();
            acl_free(text.cast());
            Ok(owned)
        };
        acl_free(acl);
        rendered
    };
    match rendered {
        Ok(text) => Ok(Some(text)),
        Err(err) => Err(std::io::Error::new(
            err.kind(),
            format!("failed to read the ACL of {}: {err}", dir.display()),
        )),
    }
}

/// Always `None` off macOS, and not a gap: Linux stores POSIX ACLs, where the
/// group permission bits *are* the ACL mask. `setfacl -m u:bob:rwx` on a 0700
/// directory recomputes them to 0770, so a grant to another user shows up in
/// the mode as group-write — the same reason [`strip_inherited_acl`] needs no
/// Linux half. Darwin's ACLs are the ones that hide behind the mode.
///
/// Surfacing in the mode is only half an answer now that group-write is not
/// refused outright: a private group makes that bit acceptable, and bob's
/// grant would ride in under it. So [`group_write_is_private`] asks
/// [`has_posix_acl`] whether the mask is standing in for an ACL before it
/// calls the bit private. That check is deliberately confined to the
/// group-writable case — with the bit clear the mask is clear, and an ACL
/// that grants nothing is not one this walk needs to read.
#[cfg(all(unix, not(target_os = "macos")))]
fn extended_acl_text(_dir: &Path) -> std::io::Result<Option<String>> {
    Ok(None)
}

/// The rights an ACE has to grant before its holder can swap what corvex
/// leaves in a directory.
///
/// `add_file`/`add_subdirectory` are the directory spellings `chmod +a`
/// accepts for the same two bits `write`/`append` name. `acl_to_text` renders
/// only the latter pair — Darwin keeps one name per bit and it is the
/// non-directory one — but both are listed so the set stays right whichever
/// spelling reaches it. `writesecurity` and `chown` are here because either
/// one lets its holder
/// grant themselves the rest. Rights that only touch the directory's own
/// attributes — `writeattr`, `writeextattr` — are deliberately not: they
/// cannot replace an entry, and refusing them would reject directories that
/// are perfectly safe for this purpose.
#[cfg(unix)]
const ACL_MUTATION_RIGHTS: [&str; 8] = [
    "write",
    "append",
    "add_file",
    "add_subdirectory",
    "delete",
    "delete_child",
    "writesecurity",
    "chown",
];

/// The pure core of the ACL half of [`reject_untrusted_directory`], kept pure
/// for the reason [`untrusted_ancestor_rejection`] is: staging a hostile ACE
/// needs a second account, and the text is what Darwin hands back either way.
///
/// `acl_to_text` renders a `!#acl 1` header and then one ACE per line, in the
/// shape `acl_from_text(3)` reads back:
///
/// ```text
/// <user|group>:[<uuid>]:[<name>]:[<id>]:<allow|deny>[,<flag>…][:<right>[,<right>…]]
/// ```
///
/// ```text
/// user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000237:bob:502:allow:write,delete_child
/// group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:deny,inherited:delete
/// user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000238:::allow,file_inherit:read
/// ```
///
/// Only `allow` entries matter — a `deny` ACE takes rights away, and
/// `everyone deny delete` sits on half the directories of a stock home. A
/// `user` entry naming this uid or root is this walk's own trust boundary
/// restated. Everything else granting a right from [`ACL_MUTATION_RIGHTS`] is
/// refused, `group` included: a group holds accounts other than this one,
/// exactly like the group write bit the mode check already refuses.
/// Inheritance flags are not read at all — an ACE that only propagates still
/// describes what the directories corvex creates underneath it will grant —
/// but they have to be *parsed*, because Darwin appends them to the verdict
/// field rather than giving them one of their own: `allow,inherited` and
/// `deny,file_inherit,directory_inherit` are ordinary entries, and every ACE
/// of a directory that inherited its ACL from its parent carries `,inherited`.
///
/// A line whose shape this cannot place is refused rather than skipped. The
/// check is worth something only if it is sound, and an ACE that cannot be
/// read is not a clean one.
#[cfg(unix)]
fn untrusted_acl_rejection(dir: &Path, acl: &str, euid: u32) -> Option<std::io::Error> {
    for line in acl.lines() {
        let entry = line.trim();
        if entry.is_empty() || entry.starts_with("!#acl") {
            continue;
        }
        let fields: Vec<&str> = entry.split(':').collect();
        // Read by position from the left, which is how `acl_from_text` reads
        // it back — `strsep(":")` down the line, kind first. Counting from
        // the right instead slips a field whenever the rights are absent,
        // which `acl_to_text` renders by leaving their colon off entirely
        // (`user:<uuid>:bob:502:allow,only_inherit`), and the uuid, name and
        // id in front of the verdict may each be empty: a uuid that resolves
        // to no account renders as `user:<uuid>:::allow`. The verdict is
        // never *searched* for either, because a name may hold anything an
        // account name can, `allow` included.
        let (kind, id, verdict_field, rights) = match fields.as_slice() {
            [kind, _uuid, _name, id, verdict] => (*kind, *id, *verdict, ""),
            [kind, _uuid, _name, id, verdict, rights] => (*kind, *id, *verdict, *rights),
            _ => return Some(unreadable_acl_rejection(dir, entry)),
        };
        // Everything after the first comma is the inheritance flags, which
        // say where the ACE propagates and not what it hands out.
        let verdict = verdict_field.split(',').next().unwrap_or_default();
        let placed = matches!(kind, "user" | "group") && matches!(verdict, "allow" | "deny");
        if !placed {
            return Some(unreadable_acl_rejection(dir, entry));
        }
        if verdict == "deny" {
            continue;
        }
        let granted: Vec<&str> = rights
            .split(',')
            .map(str::trim)
            .filter(|right| ACL_MUTATION_RIGHTS.contains(right))
            .collect();
        if granted.is_empty() {
            continue;
        }
        if kind == "user" && matches!(id.parse::<u32>(), Ok(uid) if uid == euid || uid == 0) {
            continue;
        }
        return Some(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} carries an ACL entry granting {} to another account \
                 ({entry}), so its contents can be replaced by someone else \
                 — macOS consults an ACL ahead of the mode bits, which is why \
                 the directory still looks private; remove it with: chmod -N {}",
                dir.display(),
                granted.join(","),
                shell_quote(&dir.display().to_string())
            ),
        ));
    }
    None
}

/// The refusal [`untrusted_acl_rejection`] makes on an ACE it cannot read.
#[cfg(unix)]
fn unreadable_acl_rejection(dir: &Path, entry: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "{} carries an ACL entry corvex cannot read ({entry}), so it \
             cannot tell whether another account may replace what corvex \
             leaves there; remove the ACL with: chmod -N {}",
            dir.display(),
            shell_quote(&dir.display().to_string())
        ),
    )
}

/// Windows has no uid and no mode bits, and the directory this would guard is
/// per-user: `%LOCALAPPDATA%`, or the `%USERPROFILE%` fallback [`state_dir`]
/// picks when it is unset. Neither is writable by another unprivileged user,
/// which is the condition the unix twin exists to establish — and the
/// last-resort temporary directory, which carries no such guarantee, is
/// refused outright by [`shared_fallback_rejection`] before anything is
/// written into it.
#[cfg(windows)]
pub fn ensure_trusted_ancestry(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// [`ensure_trusted_ancestry`]'s refusal, plus the two ways out of it.
///
/// The refusal itself is worded for any file corvex hands to another process
/// by name — the AWG config goes through the same check — so the log-specific
/// advice is added here rather than baked into it.
///
/// There are two escape hatches and they cover different shapes of the same
/// problem. `log.xray.access`/`log.xray.error` take those two logs off
/// corvex's list of chosen paths entirely, which is what a `/var/log/xray` in
/// a group-writable spool directory needs. It no longer covers a *home
/// directory* another uid owns, because `xray.log` — and `config.json`, and
/// `corvex.log` — are checked as well now and none of the three has a
/// configurable path; the answer there is the XDG variables, which move
/// corvex's whole hierarchy somewhere its owner is the one running it. The
/// kind is carried across because `main.rs` reads it to decide what advice to
/// print.
fn with_log_escape_hatch(err: std::io::Error) -> std::io::Error {
    let kind = err.kind();
    std::io::Error::new(
        kind,
        format!(
            "{err}; name both logs yourself with log.xray.access / \
             log.xray.error, which corvex then leaves where you put them, or \
             point XDG_STATE_HOME and XDG_CONFIG_HOME at a directory you own"
        ),
    )
}

/// Open the file xray's stdout and stderr are wired to, at the trust level
/// its path earns: [`open_append_restricted`] for the one corvex places in
/// its own state directory (which the `/tmp` fallback makes plantable, and
/// which nothing but corvex has a reason to touch), [`open_append_nonblocking`]
/// for a path the user named.
///
/// Both `preflight_log_paths` and the spawn itself go through here, so the
/// preflight tests the same open the start will make.
pub fn open_xray_log(path: &Path) -> std::io::Result<std::fs::File> {
    if is_corvex_chosen_xray_log(path) {
        // Before the open, not after: the value of the directory check is
        // that it outlives this call, and for `access.log`/`error.log` it is
        // the only part of this function that still means anything once xray
        // reopens the path out of its own config.
        //
        // Asked of `xray.log` too, though corvex hands xray the descriptor it
        // opens here and nothing reopens that name. The exemption `xray.log`
        // used to get read `O_NOFOLLOW` as covering the path when it covers
        // only the last component of it: an untrusted ancestor resolves the
        // name somewhere else entirely, so the vetted descriptor is a
        // descriptor to whatever the attacker's link pointed at — a
        // pre-existing readable file of corvex's own uid, say, whose contents
        // this open then extends and whose already-open descriptors keep
        // reading. Vetting the file says nothing about *which* file it is.
        // [`open_append_restricted`] repeats the check; it is asked here as
        // well so the refusal carries the advice below.
        ensure_trusted_ancestry(path).map_err(with_log_escape_hatch)?;
        open_append_restricted(path)
    } else {
        open_append_nonblocking(path)
    }
}

/// Rename `path` to `path.1` once it has grown past `max`, replacing any
/// previous `.1`. Returns whether a rotation happened; a missing file is not
/// an error. The rotated file keeps its 0o600 mode for free, because a rename
/// moves the inode rather than copying its bytes into a fresh one.
///
/// [`ensure_trusted_ancestry`] first, because this is the one step of the
/// logging path that touches the file by *name* and not through a vetted
/// descriptor: `remove_file` and `rename` resolve the whole path every time,
/// so an untrusted ancestor turns rotation into somebody else's file being
/// deleted and somebody else's file being renamed over it, with corvex's
/// privileges. `prepare_log_file_at` runs this *before* the open — deliberately,
/// so nothing renames the log out from under a live handle — which also means
/// it runs before the check inside [`open_append_restricted`] would have
/// spoken.
pub fn rotate_if_oversized(path: &Path, max: u64) -> std::io::Result<bool> {
    ensure_trusted_ancestry(path)?;
    let size = match std::fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    if size <= max {
        return Ok(false);
    }

    let mut rotated = path.as_os_str().to_owned();
    rotated.push(".1");
    let rotated = PathBuf::from(rotated);
    // `rename` silently replaces the destination on unix but fails on Windows,
    // so retire the previous generation explicitly.
    match std::fs::remove_file(&rotated) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::fs::rename(path, &rotated)?;
    Ok(true)
}

/// Single-quote `s` for safe embedding in a shell command line: wraps it in
/// single quotes and escapes any embedded single quote as `'\''`. Without
/// this, a path containing a space, a glob character, or a leading `-` would
/// make a suggested recovery command (`chown`, `rm`, ...) wrong or unsafe to
/// paste. Shared by main.rs and xray.rs, so it lives here rather than in
/// either.
pub(crate) fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// `mkfifo(2)` through libc: nix's own wrapper sits behind its `fs` feature,
/// which this crate does not enable. Lives outside the test module because
/// `xray.rs`'s PID-file tests plant the same shape this module's log and
/// config tests do.
#[cfg(all(unix, test))]
pub(crate) fn make_fifo(path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c_path` outlives the call and `mkfifo` only reads through it.
    let rc = unsafe { nix::libc::mkfifo(c_path.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());
}

#[derive(Debug, Clone)]
pub struct Config {
    pub xray_bin: String,
    pub xray_config: PathBuf,
    pub xray_log: PathBuf,
    pub xray_pid_file: PathBuf,
    pub corvex_settings: PathBuf,
    pub corvex_log: PathBuf,
}

impl Config {
    /// Path for the AWG .conf file, derived from the xray config directory.
    pub fn awg_conf_path(&self) -> Result<PathBuf> {
        let parent = self
            .xray_config
            .parent()
            .context("xray_config has no parent directory")?;
        Ok(parent.join("corvex-awg.conf"))
    }

    pub fn new(config_override: Option<&str>) -> Self {
        let xray_dir = xray_config_dir();
        let config_base = config_base_dir();
        let state = state_dir();

        // Nothing is logged here: `Config` is now built before the logger, so
        // that `init_logger` knows where `corvex.log` lives. `run()` reports
        // the resolved paths once the logger is up.
        let xray_config = match config_override {
            Some(path) => PathBuf::from(path),
            None => xray_dir.join("config.json"),
        };

        Config {
            xray_bin: "xray".to_string(),
            xray_config,
            xray_log: default_xray_log(),
            xray_pid_file: default_xray_pid_file(&xray_dir, &state),
            corvex_settings: config_base.join("corvex").join("corvex.json"),
            corvex_log: state.join("corvex").join("corvex.log"),
        }
    }
}

fn config_base_dir() -> PathBuf {
    config_base_dir_inner(
        #[cfg(unix)]
        std::env::var("XDG_CONFIG_HOME").ok(),
        #[cfg(windows)]
        std::env::var("APPDATA").ok(),
        #[cfg(windows)]
        std::env::var("USERPROFILE").ok(),
    )
}

#[cfg(unix)]
fn config_base_dir_inner(xdg_home: Option<String>) -> PathBuf {
    if let Some(xdg) = xdg_home {
        if !xdg.is_empty() {
            return PathBuf::from(xdg);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".config")
}

/// `%APPDATA%`, then the same directory derived from `%USERPROFILE%`, then
/// the per-user temporary directory. See [`windows_per_user_dir`] for what
/// used to be at the end of that list and why it is not there any more.
#[cfg(windows)]
fn config_base_dir_inner(appdata: Option<String>, user_profile: Option<String>) -> PathBuf {
    windows_per_user_dir(appdata, user_profile, "Roaming")
}

fn xray_config_dir() -> PathBuf {
    config_base_dir().join("xray")
}

pub(crate) fn state_dir() -> PathBuf {
    state_dir_inner(
        #[cfg(unix)]
        std::env::var("XDG_STATE_HOME").ok(),
        #[cfg(windows)]
        std::env::var("LOCALAPPDATA").ok(),
        #[cfg(windows)]
        std::env::var("USERPROFILE").ok(),
    )
}

#[cfg(unix)]
fn state_dir_inner(xdg_state: Option<String>) -> PathBuf {
    if let Some(xdg) = xdg_state {
        if !xdg.is_empty() {
            return PathBuf::from(xdg);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".local/state")
}

/// The `%LOCALAPPDATA%` twin of [`config_base_dir_inner`].
#[cfg(windows)]
fn state_dir_inner(local_appdata: Option<String>, user_profile: Option<String>) -> PathBuf {
    windows_per_user_dir(local_appdata, user_profile, "Local")
}

/// Resolve a Windows base directory that belongs to *this user*: the
/// environment variable if it is set, else the same directory rebuilt from
/// `%USERPROFILE%`, else the per-user temporary directory.
///
/// The fallback used to be `C:\Users\Public\AppData\{Roaming,Local}`, and
/// that was the whole of this platform's exposure. `C:\Users\Public` grants
/// every user on the machine full access by inheritance, so a file corvex
/// created under it — the generated xray config, with a VLESS UUID or a
/// Trojan password in it — was readable by everyone the moment it existed,
/// and its directories were plantable with a junction or a pre-created file
/// whose DACL the attacker had chosen. No check corvex can make on a
/// *handle* fixes that: the permissions come from the parent by inheritance,
/// so the file is exposed however carefully it was opened. The only fix is
/// not to write there.
///
/// `%USERPROFILE%` is set wherever `%APPDATA%` is and in most places it is
/// not, and `AppData\Roaming` / `AppData\Local` beneath it are the very
/// directories those variables normally name. That they are environment
/// variables is not a hole: they belong to the user running corvex, exactly
/// as `$HOME` and `$XDG_STATE_HOME` do on unix, where the same reasoning
/// gives the `/tmp` fallback.
///
/// `std::env::temp_dir` is the last resort, and — unlike the two above — it
/// is *not* per-user by construction. The usual answer is
/// `…\AppData\Local\Temp`, but `GetTempPath` reads `%TMP%` and `%TEMP%`
/// first, a service started from the system environment block gets
/// `C:\Windows\Temp`, which every account may create entries in, and Rust's
/// own documentation warns the value may be shared. So the path is still
/// returned — callers that only *read* are unaffected, and so is anything
/// that never gets that far — but corvex writes none of its own files there:
/// [`shared_fallback_rejection`], asked by [`open_write_restricted`],
/// [`open_append_restricted`] and [`create_dir_restricted`], turns this
/// fallback into a refusal naming the variables to set.
#[cfg(windows)]
fn windows_per_user_dir(
    configured: Option<String>,
    user_profile: Option<String>,
    leaf: &str,
) -> PathBuf {
    if let Some(dir) = configured.filter(|d| !d.is_empty()) {
        return PathBuf::from(dir);
    }
    if let Some(profile) = user_profile.filter(|d| !d.is_empty()) {
        return PathBuf::from(profile).join("AppData").join(leaf);
    }
    std::env::temp_dir()
}

fn default_xray_log() -> PathBuf {
    state_dir().join("xray").join("xray.log")
}

/// The `log.access` value corvex writes into xray's generated config when the
/// user names none. Lives here, next to the other default corvex picks, so
/// [`is_corvex_chosen_xray_log`] and
/// [`crate::protocol::XrayLogConfig::default`] cannot drift apart — the whole
/// question that predicate answers is whether a path is one of these.
pub fn default_xray_access_log() -> PathBuf {
    state_dir().join("xray").join("access.log")
}

/// The `log.error` twin of [`default_xray_access_log`].
pub fn default_xray_error_log() -> PathBuf {
    state_dir().join("xray").join("error.log")
}

fn default_xray_pid_file(_xray_dir: &Path, _state: &Path) -> PathBuf {
    #[cfg(unix)]
    {
        _xray_dir.join("xray.pid")
    }
    #[cfg(windows)]
    {
        _state.join("xray").join("xray.pid")
    }
}

/// A temporary directory at 0700, whatever the ambient umask.
///
/// Every test that reaches a restricted open needs one, because
/// [`ensure_trusted_ancestry`] judges the *directory*, and `tempfile::tempdir`
/// creates it with `0777 & !umask`. A login shell that sets `umask 002` —
/// which is what a Debian-style `USERGROUPS_ENAB` setup hands out, and a
/// setting people carry over to macOS by hand — therefore hands the tests a
/// group-writable directory. On macOS that is a refusal by design: the group
/// is `staff`, which holds every local account, so `group_write_is_private`
/// never accepts it and fifty-odd tests fail on a developer's machine while
/// passing in CI, whose umask happens to be 022. None of those tests is about
/// the umask, so none of them should be inheriting it.
#[cfg(test)]
pub(crate) fn test_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create a temporary directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("tighten the temporary directory to 0700");
    }
    dir
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_values() {
        let config = Config::new(None);
        assert_eq!(config.xray_bin, "xray");
        assert!(config.xray_config.ends_with("xray/config.json"));
        assert!(config.xray_pid_file.ends_with("xray/xray.pid"));
        assert_eq!(
            config.xray_log.strip_prefix(state_dir()).unwrap(),
            Path::new("xray").join("xray.log")
        );
    }

    #[test]
    fn config_override_replaces_xray_config_path() {
        let config = Config::new(Some("/custom/config.json"));
        assert_eq!(config.xray_config, PathBuf::from("/custom/config.json"));
    }

    #[cfg(unix)]
    #[test]
    fn config_base_respects_override() {
        let dir = config_base_dir_inner(Some("/tmp/test-xdg".to_string()));
        assert_eq!(dir, PathBuf::from("/tmp/test-xdg"));
    }

    #[cfg(windows)]
    #[test]
    fn config_base_respects_appdata() {
        let dir = config_base_dir_inner(
            Some(r"D:\roaming".to_string()),
            Some(r"C:\Users\alice".to_string()),
        );
        assert_eq!(dir, PathBuf::from(r"D:\roaming"));
    }

    /// `settings::xdg_settings_path` used to pin these two fallbacks; it was a
    /// second, Windows-blind spelling of this resolution and has been deleted,
    /// so its coverage lives here now.
    #[cfg(unix)]
    #[test]
    fn config_base_falls_back_to_home_when_xdg_is_unset() {
        let dir = config_base_dir_inner(None);
        assert!(dir.ends_with(".config"), "got {}", dir.display());
    }

    #[cfg(unix)]
    #[test]
    fn config_base_ignores_an_empty_xdg_config_home() {
        // An exported-but-empty XDG_CONFIG_HOME is not an override.
        let dir = config_base_dir_inner(Some(String::new()));
        assert!(dir.ends_with(".config"), "got {}", dir.display());
    }

    #[test]
    fn new_fields_have_expected_defaults() {
        let config = Config::new(None);
        assert!(config.corvex_settings.ends_with("corvex/corvex.json"));
        assert!(config.corvex_log.ends_with("corvex/corvex.log"));
    }

    #[cfg(unix)]
    #[test]
    fn state_dir_respects_env_var() {
        let dir = state_dir_inner(Some("/tmp/test-state".to_string()));
        assert_eq!(dir, PathBuf::from("/tmp/test-state"));
    }

    #[cfg(unix)]
    #[test]
    fn state_dir_falls_back_to_default() {
        assert!(state_dir_inner(None).ends_with(".local/state"));
    }

    #[cfg(unix)]
    #[test]
    fn state_dir_ignores_empty_env_var() {
        assert!(state_dir_inner(Some(String::new())).ends_with(".local/state"));
    }

    /// The fallback that matters: with `%LOCALAPPDATA%` unset the state
    /// directory has to stay inside *this user's* profile. It used to land in
    /// `C:\Users\Public`, which every account on the machine can read and
    /// write - see `windows_per_user_dir`.
    #[cfg(windows)]
    #[test]
    fn state_dir_falls_back_to_the_user_profile() {
        for unset in [None, Some(String::new())] {
            let dir = state_dir_inner(unset, Some(r"C:\Users\alice".to_string()));
            assert_eq!(dir, PathBuf::from(r"C:\Users\alice\AppData\Local"));
        }
    }

    /// And with no profile either, the per-user temporary directory - never a
    /// shared one named in the source.
    #[cfg(windows)]
    #[test]
    fn state_dir_falls_back_to_the_temporary_directory() {
        for unset in [None, Some(String::new())] {
            let dir = state_dir_inner(None, unset);
            assert_eq!(dir, std::env::temp_dir());
            assert!(
                !dir.starts_with(r"C:\Users\Public"),
                "the shared fallback must not come back: {}",
                dir.display()
            );
        }
    }

    #[test]
    fn open_append_restricted_appends_rather_than_truncates() {
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");
        std::fs::write(&log, "first\n").unwrap();

        let mut file = open_append_restricted(&log).unwrap();
        std::io::Write::write_all(&mut file, b"second\n").unwrap();
        drop(file);

        assert_eq!(std::fs::read_to_string(&log).unwrap(), "first\nsecond\n");
    }

    #[cfg(unix)]
    #[test]
    fn open_append_restricted_creates_file_at_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");

        drop(open_append_restricted(&log).unwrap());

        let mode = std::fs::metadata(&log).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }

    #[cfg(unix)]
    #[test]
    fn open_append_restricted_tightens_an_existing_loose_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");
        std::fs::write(&log, "from a looser run\n").unwrap();
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644)).unwrap();

        drop(open_append_restricted(&log).unwrap());

        let mode = std::fs::metadata(&log).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "from a looser run\n",
            "tightening must not discard the existing log"
        );
    }

    /// A symlink at the log path must reach neither of the two calls that would
    /// act on its target. `O_NOFOLLOW` stops the open, and the mode is
    /// tightened with `fchmod` through the descriptor that open returned, so
    /// the link is never resolved a second time. Under the `/tmp` `HOME`
    /// fallback the target need not be a file corvex or the user owns, so
    /// dropping the flag turns the log open into an arbitrary-file-append
    /// primitive, and reaching for the path-based `std::fs::set_permissions`
    /// instead re-opens the arbitrary-file-chmod one behind a TOCTOU. Either
    /// regression passes every other test in this file.
    #[cfg(unix)]
    #[test]
    fn open_append_restricted_refuses_a_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::config::test_tempdir();
        let victim = dir.path().join("victim");
        let log = dir.path().join("corvex.log");
        std::fs::write(&victim, "not corvex's\n").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&victim, &log).unwrap();

        let err = open_append_restricted(&log).expect_err("a symlinked log path must be refused");
        assert_eq!(
            err.raw_os_error(),
            Some(nix::libc::ELOOP),
            "expected ELOOP from O_NOFOLLOW, got {err}"
        );

        let mode = std::fs::metadata(&victim).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o644,
            "the symlink target kept the mode its owner chose, got {:o}",
            mode & 0o777
        );
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "not corvex's\n",
            "the symlink target must not be appended to"
        );
    }

    /// `O_NOFOLLOW` rules out a symlink and nothing else, and `mkfifo` needs no
    /// privilege: in the world-writable `/tmp` fallback anyone can pre-create
    /// the log path as a FIFO. Opening a FIFO for writing blocks in the kernel
    /// until a reader shows up, and this open runs before the logger and before
    /// the command does any work — so without `O_NONBLOCK` every corvex
    /// invocation hangs, silently and indefinitely. That is a denial of service
    /// that costs the attacker one `mkfifo`.
    ///
    /// Driven from a worker thread with a bounded join, because a regression
    /// here does not fail — it hangs, and a wedged suite says far less than an
    /// assertion naming the flag.
    #[cfg(unix)]
    #[test]
    fn open_append_restricted_does_not_block_on_a_readerless_fifo() {
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");
        make_fifo(&log);

        let (sender, receiver) = std::sync::mpsc::channel();
        let probe = log.clone();
        std::thread::spawn(move || {
            let _ = sender.send(open_append_restricted(&probe).map(|_| ()));
        });

        receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the open must return, not block waiting for a reader")
            .expect_err("a FIFO at the log path must be refused");
    }

    /// The other half of the same plant: a FIFO the attacker is holding open
    /// for reading. `O_NONBLOCK` no longer refuses that open — a reader is
    /// attached, so it succeeds — and every `info!` line would be piped to the
    /// attacker's process. The file-type check is what closes it.
    #[cfg(unix)]
    #[test]
    fn open_append_restricted_refuses_a_fifo_with_a_reader_attached() {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");
        make_fifo(&log);

        // `O_RDONLY | O_NONBLOCK` on a FIFO returns immediately even with no
        // writer, which pins the case under test rather than racing for it.
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(&log)
            .expect("a FIFO opens for reading without a writer");

        let err = open_append_restricted(&log)
            .expect_err("a FIFO is not a log file, reader attached or not");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidInput,
            "expected the file-type refusal, got {err}"
        );
        drop(reader);
    }

    /// `$XDG_CONFIG_HOME` falls back to `/tmp` exactly as the state dir does, so
    /// the xray config path is plantable the same way — and `write_restricted`
    /// would pipe a freshly rendered credential straight into the FIFO.
    #[cfg(unix)]
    #[test]
    fn write_restricted_refuses_a_fifo_with_a_reader_attached() {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = crate::config::test_tempdir();
        let config = dir.path().join("config.json");
        make_fifo(&config);

        let reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(&config)
            .expect("a FIFO opens for reading without a writer");

        write_restricted(&config, "{\"secret\":1}")
            .expect_err("a FIFO at the config path must be refused");

        drop(reader);
    }

    /// The three refusals `accept_restricted_file` makes, driven through the
    /// pure core so the suite does not have to become a second uid to reach the
    /// middle one. The real-descriptor paths are covered by the symlink, FIFO
    /// and hard-link tests around this one; what is pinned here is the decision
    /// itself, foreign owner included.
    #[cfg(unix)]
    #[test]
    fn restricted_file_rejection_accepts_only_an_owned_unaliased_regular_file() {
        let path = Path::new("/tmp/.local/state/corvex/corvex.log");

        assert!(
            restricted_file_rejection(path, true, 501, 501, 1).is_none(),
            "a regular file this uid owns, with one name, is the good case"
        );

        let err = restricted_file_rejection(path, false, 501, 501, 1)
            .expect("a non-regular file must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

        // The plant `mode(0o600)` cannot see: an ordinary world-writable
        // regular file, pre-created by another uid in the world-writable
        // `/tmp` fallback. corvex must refuse it rather than write a
        // credential into a file its owner can chmod back open at will —
        // which is exactly what an `fchmod`-only defence would allow, since
        // that call *succeeds* when corvex runs as root.
        let err = restricted_file_rejection(path, true, 1000, 501, 1)
            .expect("a file owned by another uid must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            err.to_string().contains("owned by uid 1000"),
            "the message must name the owner: {err}"
        );

        // Ownership alone is not enough: a hard link planted at the path
        // points at a file this uid owns, so the ownership test passes on the
        // victim's ownership. `O_NOFOLLOW` says nothing about hard links.
        let err = restricted_file_rejection(path, true, 501, 501, 2)
            .expect("an aliased path must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("2 hard links"),
            "the message must name the link count: {err}"
        );
    }

    /// End-to-end over a real descriptor, for the one hostile shape a test can
    /// stage without privileges: a second name for a file corvex's own uid
    /// owns. `O_NOFOLLOW` lets this open through, and the ownership check does
    /// too — the link count is the only thing standing between an attacker's
    /// choice of path and an appended log.
    #[cfg(unix)]
    #[test]
    fn open_append_restricted_refuses_a_hard_link() {
        let dir = crate::config::test_tempdir();
        let victim = dir.path().join("shell-rc");
        let log = dir.path().join("corvex.log");
        std::fs::write(&victim, "not corvex's\n").unwrap();
        std::fs::hard_link(&victim, &log).unwrap();

        let err = open_append_restricted(&log).expect_err("a hard link must be refused");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidInput,
            "expected the link-count refusal, got {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "not corvex's\n",
            "the linked file must not be appended to"
        );
    }

    /// The same plant at the config path, where what would be written is a
    /// credential and the write would clobber the linked file as well.
    #[cfg(unix)]
    #[test]
    fn write_restricted_refuses_a_hard_link() {
        let dir = crate::config::test_tempdir();
        let victim = dir.path().join("crontab");
        let config = dir.path().join("config.json");
        std::fs::write(&victim, "not corvex's\n").unwrap();
        std::fs::hard_link(&victim, &config).unwrap();

        write_restricted(&config, "{\"secret\":1}").expect_err("a hard link must be refused");

        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "not corvex's\n",
            "the linked file must be left untouched, contents and length both"
        );
    }

    /// `.mode(0o600)` applies only to a file the open *created*. A file already
    /// sitting at the config path — left by an older build, an interrupted run,
    /// or planted — keeps whatever mode it has, so the credential would land in
    /// a world-readable file. `write_restricted` must tighten before it writes.
    #[cfg(unix)]
    #[test]
    fn write_restricted_tightens_an_existing_loose_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::config::test_tempdir();
        let config = dir.path().join("config.json");
        std::fs::write(&config, "{}").unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o666)).unwrap();

        write_restricted(&config, "{\"secret\":1}").unwrap();

        let mode = std::fs::metadata(&config).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o600, "mode was {:o}", mode & 0o7777);
        assert_eq!(std::fs::read_to_string(&config).unwrap(), "{\"secret\":1}");
    }

    /// Truncation moved off `OpenOptions` and onto `set_len` so that it happens
    /// after the vetting rather than inside `open`. It still has to happen: a
    /// shorter config written over a longer one must not leave the tail of the
    /// old one — a previous server's credential — readable past the JSON.
    #[cfg(unix)]
    #[test]
    fn write_restricted_truncates_a_longer_previous_file() {
        let dir = crate::config::test_tempdir();
        let config = dir.path().join("config.json");

        write_restricted(&config, "{\"old\":\"a-long-previous-credential\"}").unwrap();
        write_restricted(&config, "{\"new\":1}").unwrap();

        assert_eq!(std::fs::read_to_string(&config).unwrap(), "{\"new\":1}");
    }

    /// The fallback `write_restricted` takes on macOS when the file it opened
    /// turned out to carry an inherited ACE. Driven directly, on every unix,
    /// because the branch that reaches it needs a filesystem that hands ACLs
    /// down and only Darwin does that - and an untested fallback is a
    /// fallback that quietly stops working. The guarantee is the same either
    /// way: the content arrives at the final name, at 0600, and nothing is
    /// left behind next to it.
    #[cfg(unix)]
    #[test]
    fn write_via_private_dir_lands_the_content_at_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::config::test_tempdir();
        let config = dir.path().join("config.json");

        write_via_private_dir(&config, "{\"secret\":1}").unwrap();

        assert_eq!(std::fs::read_to_string(&config).unwrap(), "{\"secret\":1}");
        assert_eq!(
            std::fs::metadata(&config).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|name| name != "config.json")
            .collect();
        assert!(
            leftovers.is_empty(),
            "the staging directory must not survive the write: {leftovers:?}"
        );
    }

    /// `rename` replaces, so a previous credential goes whole rather than
    /// being overwritten in place - the same observable result as the
    /// truncating path, which is what makes the two interchangeable.
    #[cfg(unix)]
    #[test]
    fn write_via_private_dir_replaces_a_longer_previous_file() {
        let dir = crate::config::test_tempdir();
        let config = dir.path().join("config.json");
        std::fs::write(&config, "{\"old\":\"a-long-previous-credential\"}").unwrap();

        write_via_private_dir(&config, "{\"new\":1}").unwrap();

        assert_eq!(std::fs::read_to_string(&config).unwrap(), "{\"new\":1}");
    }

    /// The append twin of the two tests above, and the answer to the same
    /// race on a file that has a past: the bytes already in the log survive,
    /// later writes go to the replacement, and the inode really is a
    /// different one - which is the whole point, since the old one is what a
    /// descriptor obtained through the inherited ACE would still be holding.
    /// Driven directly for the same reason `write_via_private_dir` is: only
    /// Darwin reaches it by itself.
    #[cfg(unix)]
    #[test]
    fn append_via_private_dir_carries_the_log_across_to_a_new_inode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");
        std::fs::write(&log, "first\n").unwrap();
        let before = std::fs::metadata(&log).unwrap().ino();

        let (vetted, _) = open_append_vetted(&log).unwrap();
        let mut replaced = append_via_private_dir(&log, vetted).unwrap();
        std::io::Write::write_all(&mut replaced, b"second\n").unwrap();

        assert_eq!(std::fs::read_to_string(&log).unwrap(), "first\nsecond\n");
        let after = std::fs::metadata(&log).unwrap();
        assert_ne!(
            after.ino(),
            before,
            "the exposed inode must be left behind, not appended to"
        );
        assert_eq!(after.permissions().mode() & 0o7777, 0o600);
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|name| name != "corvex.log")
            .collect();
        assert!(
            leftovers.is_empty(),
            "the staging directory must not survive the replacement: {leftovers:?}"
        );
    }

    /// A log created by the open that found the ACE has no past to carry, and
    /// the replacement must not invent one.
    #[cfg(unix)]
    #[test]
    fn append_via_private_dir_starts_an_empty_log_empty() {
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");

        let (vetted, _) = open_append_vetted(&log).unwrap();
        let mut replaced = append_via_private_dir(&log, vetted).unwrap();
        std::io::Write::write_all(&mut replaced, b"only\n").unwrap();

        assert_eq!(std::fs::read_to_string(&log).unwrap(), "only\n");
    }

    /// The directory check corvex makes before handing a log path to xray.
    /// A directory only its owner can write is one nothing can be planted in
    /// after the preflight looked, which is what makes the preflight mean
    /// anything for `access.log` and `error.log` - the two xray opens by name
    /// itself.
    #[cfg(unix)]
    #[test]
    fn trusted_ancestry_accepts_a_directory_only_its_owner_can_write() {
        let dir = crate::config::test_tempdir();
        ensure_trusted_ancestry(&dir.path().join("xray.log"))
            .expect("a 0700 directory owned by this uid must be accepted");
    }

    /// The case it exists to refuse. Note that the leaf being 0700 would not
    /// save it: an attacker who can write the *parent* can rename the whole
    /// directory out of the way, so the walk checks every component.
    #[cfg(unix)]
    #[test]
    fn trusted_ancestry_refuses_a_world_writable_ancestor() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::config::test_tempdir();
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        let leaf = shared.join("xray");
        std::fs::create_dir(&leaf).unwrap();
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();

        let err = ensure_trusted_ancestry(&leaf.join("xray.log"))
            .expect_err("a world-writable ancestor must be refused");

        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            err.to_string().contains(&shared.display().to_string()),
            "the message must name the directory to fix: {err}"
        );
    }

    /// And the exception that keeps the `/tmp` fallback working: sticky is
    /// exactly the bit that stops one user renaming another's entry away, so
    /// a 1777 ancestor is not a hole. Every temporary directory in this suite
    /// is under one.
    #[cfg(unix)]
    #[test]
    fn trusted_ancestry_accepts_a_sticky_world_writable_ancestor() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::config::test_tempdir();
        let sticky = dir.path().join("tmp");
        std::fs::create_dir(&sticky).unwrap();
        let leaf = sticky.join("xray");
        std::fs::create_dir(&leaf).unwrap();
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&sticky, std::fs::Permissions::from_mode(0o1777)).unwrap();

        ensure_trusted_ancestry(&leaf.join("xray.log"))
            .expect("a sticky shared directory must be accepted");
    }

    /// The rejections a test cannot stage - a directory owned by somebody
    /// else needs a second uid - decided from the numbers instead. root is
    /// accepted deliberately: `/`, `/home`, `/Users` and `/tmp` are all
    /// root's, and a hostile root has already won.
    #[cfg(unix)]
    #[test]
    fn untrusted_ancestor_rejection_reads_the_numbers() {
        let dir = Path::new("/home/someone-else");
        assert!(untrusted_ancestor_rejection(dir, true, 501, 501, 0o755, false).is_none());
        assert!(untrusted_ancestor_rejection(dir, true, 0, 501, 0o755, false).is_none());
        assert!(untrusted_ancestor_rejection(dir, true, 0, 501, 0o1777, false).is_none());

        let foreign = untrusted_ancestor_rejection(dir, true, 502, 501, 0o700, false)
            .expect("a directory owned by another uid must be refused");
        assert!(foreign.to_string().contains("uid 502"), "{foreign}");

        let group_writable = untrusted_ancestor_rejection(dir, true, 501, 501, 0o770, false)
            .expect("a group-writable directory must be refused");
        assert!(
            group_writable.to_string().contains("0770"),
            "{group_writable}"
        );

        let not_a_dir = untrusted_ancestor_rejection(dir, false, 501, 501, 0o700, false)
            .expect("a component that is not a directory must be refused");
        assert_eq!(not_a_dir.kind(), std::io::ErrorKind::InvalidInput);
    }

    /// The bit that a private group makes acceptable, and the three things it
    /// still does not excuse. A 0775 `~/.config` owned by `alice:alice` is
    /// the default shape of a Debian or Ubuntu home directory - refusing it
    /// aborted `start` on a stock install - but the same bit under a shared
    /// group, and world-write under any group at all, stay refused.
    #[cfg(unix)]
    #[test]
    fn a_private_group_excuses_only_the_group_write_bit() {
        let dir = Path::new("/home/alice/.config");

        assert!(
            untrusted_ancestor_rejection(dir, true, 501, 501, 0o775, true).is_none(),
            "a private group's write bit is not a hole"
        );
        assert!(
            untrusted_ancestor_rejection(dir, true, 501, 501, 0o770, false).is_some(),
            "a shared group's write bit is"
        );

        // World-write is never excused, however private the group is.
        let world = untrusted_ancestor_rejection(dir, true, 501, 501, 0o777, true)
            .expect("a world-writable directory must be refused whatever its group");
        assert!(world.to_string().contains("0777"), "{world}");
        let world_only = untrusted_ancestor_rejection(dir, true, 501, 501, 0o707, true)
            .expect("other-write alone must be refused");
        assert!(world_only.to_string().contains("0707"), "{world_only}");

        // Nor does a private group excuse a foreign owner, which is a
        // different question entirely and asked first.
        assert!(
            untrusted_ancestor_rejection(dir, true, 502, 501, 0o775, true).is_some(),
            "a private group says nothing about who owns the directory"
        );
    }

    /// `gid == euid` is the user-private-group convention, and it is what
    /// keeps macOS strict: local accounts there share `staff` (gid 20) while
    /// uids start at 501, so no group-writable directory on macOS reaches the
    /// member lookup at all.
    #[cfg(unix)]
    #[test]
    fn group_write_is_never_private_under_a_foreign_gid() {
        let dir = Path::new("/home/alice/.config");
        // gid 20 is `staff`; gid 100 is a shared `users`. Neither matches the
        // euid, so neither is asked about further.
        assert!(!group_write_is_private(dir, 20, 501).expect("a mismatched gid needs no lookup"));
        assert!(!group_write_is_private(dir, 100, 501).expect("a mismatched gid needs no lookup"));
    }

    /// The hole a private group would otherwise reopen on Linux. `setfacl -m
    /// u:bob:rwx` on a directory of this uid's own private group recomputes
    /// the mode to group-write, so conditions 1 and 2 of
    /// [`group_write_is_private`] both pass and bob's grant would ride in
    /// under a bit called private. The ACL is staged as the raw xattr the
    /// kernel stores, because `setfacl` is a package this container does not
    /// carry - the blob is the documented on-disk form, and the kernel
    /// validates it on the way in, so a malformed one fails the set rather
    /// than passing the test.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_posix_acl_is_not_a_private_group() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let scratch = crate::config::test_tempdir();
        let dir = scratch.path();
        let euid = unsafe { nix::libc::geteuid() };
        let egid = unsafe { nix::libc::getegid() };

        assert!(
            !has_posix_acl(dir).expect("a fresh directory must answer"),
            "a directory nobody has run setfacl on carries no ACL"
        );

        // Version 2, then 8-byte entries of (tag, perm, id) sorted by tag:
        // USER_OBJ rwx, USER(bob) rwx, GROUP_OBJ r-x, MASK rwx, OTHER r-x.
        let mut blob = Vec::from(2u32.to_le_bytes());
        for (tag, perm, id) in [
            (0x01u16, 7u16, u32::MAX),
            (0x02, 7, 4242),
            (0x04, 5, u32::MAX),
            (0x10, 7, u32::MAX),
            (0x20, 5, u32::MAX),
        ] {
            blob.extend_from_slice(&tag.to_le_bytes());
            blob.extend_from_slice(&perm.to_le_bytes());
            blob.extend_from_slice(&id.to_le_bytes());
        }
        let c_path = CString::new(dir.as_os_str().as_bytes()).expect("no interior NUL");
        let name = c"system.posix_acl_access";
        // SAFETY: both pointers are NUL-terminated strings owned by locals
        // that outlive the call, and the value is the buffer `blob` owns,
        // passed with its own length.
        let set = unsafe {
            nix::libc::lsetxattr(
                c_path.as_ptr(),
                name.as_ptr(),
                blob.as_ptr().cast(),
                blob.len(),
                0,
            )
        };
        if set != 0 {
            // A filesystem that stores no ACLs cannot stage the hole, and
            // there is nothing to assert about one that cannot have it.
            let err = std::io::Error::last_os_error();
            assert_eq!(
                err.raw_os_error(),
                Some(nix::libc::ENOTSUP),
                "staging the ACL failed for a reason other than filesystem support: {err}"
            );
            return;
        }

        assert!(
            has_posix_acl(dir).expect("a directory with an ACL must answer"),
            "the staged ACL must be seen"
        );
        assert!(
            !group_write_is_private(dir, egid, euid).expect("the verdict must not error"),
            "a directory carrying a POSIX ACL is never a private group, whatever its gid"
        );
    }

    /// The walk's own answer for the process running the suite: whatever the
    /// machine's convention is, asking must not error, and it must agree with
    /// the two conditions that can be checked independently here.
    #[cfg(unix)]
    #[test]
    fn group_write_is_private_agrees_with_this_machine() {
        let euid = unsafe { nix::libc::geteuid() };
        let egid = unsafe { nix::libc::getegid() };
        let dir = std::env::temp_dir();

        let private = group_write_is_private(&dir, egid, euid)
            .expect("asking about this machine's own group must not error");
        if egid != euid {
            assert!(!private, "a gid that is not the uid is never private");
        } else {
            assert_eq!(
                private,
                group_has_no_other_members(egid).expect("the group of this process must resolve")
                    && !has_posix_acl(&dir).expect("the temp dir's ACL must be readable"),
                "the verdict must be exactly the conjunction of its parts"
            );
        }
    }

    /// The hole a canonicalizing walk left open. `shared` is world-writable,
    /// so anyone can replace the link inside it - but the link points at a
    /// 0700 directory of this uid's, so canonicalizing first and walking the
    /// *result* saw nothing but trusted directories and accepted it. The
    /// walk has to judge the chain the name goes through, because that is
    /// the chain xray reopens.
    #[cfg(unix)]
    #[test]
    fn trusted_ancestry_refuses_a_link_anyone_can_repoint() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::config::test_tempdir();
        let private = dir.path().join("private/xray");
        std::fs::create_dir_all(&private).unwrap();
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        let link = shared.join("state");
        std::os::unix::fs::symlink(&private, &link).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();

        let err = ensure_trusted_ancestry(&link.join("access.log"))
            .expect_err("a link anyone can repoint must be refused, whatever it points at now");

        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            err.to_string().contains(&shared.display().to_string()),
            "the message must name the directory to fix: {err}"
        );
    }

    /// And the case that must keep working, since `/var` -> `/private/var` on
    /// macOS puts a symlink on the path of every temporary directory in this
    /// suite: a link in a directory only its owner can write is as good as
    /// the directory it names.
    #[cfg(unix)]
    #[test]
    fn trusted_ancestry_follows_a_link_only_its_owner_can_replace() {
        let dir = crate::config::test_tempdir();
        // Through `create_dir_restricted`, not `create_dir_all`, so the two
        // components land at 0700 rather than at whatever the ambient umask
        // leaves them - the walk under test judges exactly those mode bits.
        create_dir_restricted(&dir.path().join("real/xray")).unwrap();
        let link = dir.path().join("state");
        std::os::unix::fs::symlink(dir.path().join("real"), &link).unwrap();

        ensure_trusted_ancestry(&link.join("xray/access.log"))
            .expect("a link nobody else can replace names a directory as good as itself");
    }

    /// The walk is asked at every restricted open, not only at the two logs
    /// xray reopens by name. `O_NOFOLLOW` refuses a link *at* the file and
    /// leaves the kernel resolving every parent as usual, so a component
    /// somebody else can repoint decides which file the vetted descriptor
    /// lands on - and every check that follows then passes, because what it
    /// landed on is an ordinary 0600 file of this uid's. `shared` stands in
    /// for the world-writable `/tmp` the `HOME`-unset fallback puts all of
    /// these paths under, and the file already sitting at the end of the link
    /// is the shape that makes it worth doing: a reader who opened it while
    /// it was still readable keeps reading whatever is written through the
    /// inode next, which here would be a VLESS UUID.
    #[cfg(unix)]
    #[test]
    fn restricted_opens_refuse_a_parent_reached_through_a_repointable_link() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::config::test_tempdir();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("config.json"), "{\"previous\":true}").unwrap();
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        let link = shared.join("xray");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();

        let target = link.join("config.json");
        write_restricted(&target, "{\"secret\":1}")
            .expect_err("a credential must not be written through a link anyone can repoint");
        open_write_restricted(&target).expect_err("nor may a descriptor be opened through one");
        open_append_restricted(&link.join("corvex.log"))
            .expect_err("nor may a log be appended through one");

        assert_eq!(
            std::fs::read_to_string(real.join("config.json")).unwrap(),
            "{\"previous\":true}",
            "the file at the end of the link must be left exactly as it was"
        );
    }

    /// Rotation is the one step of the logging path that acts on the *name*
    /// rather than through a vetted descriptor: `remove_file` and `rename`
    /// resolve every component afresh, so an ancestor somebody else can
    /// rearrange turns it into their choice of file being deleted and their
    /// choice of file being renamed over it. `prepare_log_file_at` runs it
    /// before the open, deliberately, which is exactly why the check inside
    /// `open_append_restricted` cannot speak for it.
    #[cfg(unix)]
    #[test]
    fn rotate_if_oversized_refuses_an_untrusted_ancestor() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::config::test_tempdir();
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        let log = shared.join("corvex.log");
        std::fs::write(&log, "well past the threshold this test names").unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();

        let err = rotate_if_oversized(&log, 4)
            .expect_err("a rename in a directory anyone can rearrange must be refused");

        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            log.exists(),
            "nothing may be renamed on the way to refusing the rotation"
        );
    }

    /// The walk follows links itself, so it counts them itself: a loop is an
    /// error rather than a spin or a blown stack.
    #[cfg(unix)]
    #[test]
    fn trusted_ancestry_gives_up_on_a_symlink_loop() {
        let dir = crate::config::test_tempdir();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::os::unix::fs::symlink(&b, &a).unwrap();
        std::os::unix::fs::symlink(&a, &b).unwrap();

        let err = ensure_trusted_ancestry(&a.join("access.log"))
            .expect_err("a symlink loop must end the walk");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    /// The refusal is worded for any file handed to another process by name,
    /// so the log-only way out has to be added where the log asks for it -
    /// and the kind has to survive, because `main.rs` reads it to decide
    /// whether to print the `chown` advice.
    #[test]
    fn log_escape_hatch_keeps_the_kind_and_names_the_setting() {
        let refusal = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "/tmp/shared is writable by other users",
        );

        let wrapped = with_log_escape_hatch(refusal);

        assert_eq!(wrapped.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(wrapped.to_string().contains("/tmp/shared"), "{wrapped}");
        assert!(wrapped.to_string().contains("log.xray.access"), "{wrapped}");
    }

    /// The link rejection a test cannot stage, decided from the numbers - the
    /// same bargain [`untrusted_ancestor_rejection_reads_the_numbers`] makes.
    /// root's links are accepted because `/var`, `/tmp` and `/etc` are full
    /// of them.
    #[cfg(unix)]
    #[test]
    fn untrusted_link_rejection_reads_the_owner() {
        let link = Path::new("/tmp/.local");
        assert!(untrusted_link_rejection(link, 501, 501).is_none());
        assert!(untrusted_link_rejection(link, 0, 501).is_none());

        let foreign = untrusted_link_rejection(link, 502, 501)
            .expect("a link owned by another uid must be refused");
        assert_eq!(foreign.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(foreign.to_string().contains("uid 502"), "{foreign}");
    }

    /// The rejection the mode bits cannot make, decided from the text Darwin
    /// renders - staging one needs a second account, so the ACE is the fixture
    /// here the way the numbers are in
    /// [`untrusted_ancestor_rejection_reads_the_numbers`].
    #[cfg(unix)]
    #[test]
    fn untrusted_acl_rejection_reads_the_entries() {
        let dir = Path::new("/Users/alice/.local/state");
        let ace = |body: &str| format!("!#acl 1\n{body}\n");

        // No entries at all, and the deny ACE a stock macOS home is full of:
        // a deny takes rights away, it never hands them out.
        assert!(untrusted_acl_rejection(dir, "!#acl 1\n", 501).is_none());
        let stock = ace("group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:deny:delete");
        assert!(untrusted_acl_rejection(dir, &stock, 501).is_none());

        // This uid's own grant, and root's, are the trust boundary the walk
        // already draws; a read-only grant cannot swap an entry. `write` and
        // `append` are the names Darwin renders for the bits `chmod +a`
        // spells `add_file` and `add_subdirectory` on a directory.
        let own = ace("user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000237:alice:501:allow:write");
        assert!(untrusted_acl_rejection(dir, &own, 501).is_none());
        let root = ace("user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000:root:0:allow:delete_child");
        assert!(untrusted_acl_rejection(dir, &root, 501).is_none());
        let readable =
            ace("user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000238:bob:502:allow:read,execute,readattr");
        assert!(untrusted_acl_rejection(dir, &readable, 501).is_none());

        let foreign =
            ace("user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000238:bob:502:allow:write,delete_child");
        let refused = untrusted_acl_rejection(dir, &foreign, 501)
            .expect("an ACE granting another account write must be refused");
        assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(refused.to_string().contains("write"), "{refused}");
        assert!(refused.to_string().contains("chmod -N"), "{refused}");

        // The directory spellings are accepted too, so the set stays right
        // whichever one reaches it.
        let spelled =
            ace("user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000238:bob:502:allow:add_file,delete_child");
        assert!(untrusted_acl_rejection(dir, &spelled, 501).is_some());

        // A group holds accounts other than this one, exactly like the group
        // write bit the mode check refuses - and a uuid that resolves to no
        // account, which Darwin renders with the name and the id both empty,
        // cannot be shown to be this one.
        let group =
            ace("group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000014:staff:20:allow:add_subdirectory");
        assert!(untrusted_acl_rejection(dir, &group, 501).is_some());
        let unresolved = ace("user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000238:::allow:write");
        assert!(untrusted_acl_rejection(dir, &unresolved, 501).is_some());

        // An account named `allow` puts that word in the name field too. The
        // fields are read by position, so the entry is still judged on its
        // own id rather than read one field out of step.
        let ambiguous = ace("user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000239:allow:503:allow:write");
        assert!(untrusted_acl_rejection(dir, &ambiguous, 501).is_some());
        let ambiguous_own = ace("user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000237:allow:501:allow:write");
        assert!(untrusted_acl_rejection(dir, &ambiguous_own, 501).is_none());
    }

    /// Darwin appends an ACE's inheritance flags to its *verdict* field, so
    /// `allow,inherited` is what every entry of a directory that inherited its
    /// ACL looks like. Reading the verdict as the whole field refused all of
    /// them as unreadable, which is a `start` that fails on a perfectly
    /// ordinary tree.
    #[cfg(unix)]
    #[test]
    fn untrusted_acl_rejection_reads_entries_carrying_inheritance_flags() {
        let dir = Path::new("/Users/alice/.local/state");
        let ace = |body: &str| format!("!#acl 1\n{body}\n");

        // A deny is still a deny, and a read-only allow still grants nothing
        // that can swap an entry, however the ACE propagates.
        let denied =
            ace("group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:deny,inherited:delete");
        assert!(untrusted_acl_rejection(dir, &denied, 501).is_none());
        let readable =
            ace("user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000238:bob:502:allow,inherited:read,execute");
        assert!(untrusted_acl_rejection(dir, &readable, 501).is_none());
        let own = ace(
            "user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000237:alice:501:allow,file_inherit,directory_inherit:write",
        );
        assert!(untrusted_acl_rejection(dir, &own, 501).is_none());

        // An ACE granting nothing at all renders with no rights field and no
        // colon in front of one, which is the shape counting from the right
        // read a field out of step.
        let rightless = ace("user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000238:bob:502:allow,only_inherit");
        assert!(untrusted_acl_rejection(dir, &rightless, 501).is_none());

        // And the grant that matters is still refused through its flags.
        let foreign = ace(
            "user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000238:bob:502:allow,inherited,file_inherit,directory_inherit:write,delete_child",
        );
        let refused = untrusted_acl_rejection(dir, &foreign, 501)
            .expect("an inherited ACE granting another account write must be refused");
        assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(refused.to_string().contains("write"), "{refused}");
    }

    /// An ACE in a shape this cannot read is refused, not skipped: the walk
    /// is worth something only if its verdict is sound.
    #[cfg(unix)]
    #[test]
    fn untrusted_acl_rejection_refuses_what_it_cannot_read() {
        let dir = Path::new("/Users/alice/.local/state");
        let refusal = |acl: &str| {
            untrusted_acl_rejection(dir, acl, 501)
                .expect("an entry this cannot place must be refused")
        };

        let unreadable = untrusted_acl_rejection(dir, "!#acl 1\nuser:bob:rwx\n", 501)
            .expect("an entry with no allow/deny field must be refused");

        assert_eq!(unreadable.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            unreadable.to_string().contains("cannot read"),
            "{unreadable}"
        );

        // Neither too many fields nor a kind that is neither user nor group,
        // and a verdict this cannot recognise is refused however it is
        // flagged - a field of flags alone is not an entry granting nothing.
        let extra = "!#acl 1\nuser:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000238:bob:502:allow:write:more\n";
        assert_eq!(refusal(extra).kind(), std::io::ErrorKind::InvalidInput);
        let kind = "!#acl 1\nmask:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000238:bob:502:allow:write\n";
        assert_eq!(refusal(kind).kind(), std::io::ErrorKind::InvalidInput);
        let verdict =
            "!#acl 1\nuser:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000238:bob:502:inherited:write\n";
        assert_eq!(refusal(verdict).kind(), std::io::ErrorKind::InvalidInput);
    }

    /// The Windows fallback that is not per-user by construction. The
    /// decision is pure and path-shaped, so it is tested everywhere rather
    /// than only in the Windows CI job.
    #[test]
    fn shared_fallback_is_refused_only_when_it_was_taken() {
        let temp = Path::new("/tmp");
        let path = Path::new("/tmp/corvex/corvex.log");
        let set = Some("C:\\Users\\alice");

        // Any of the per-user variables being set means the fallback was
        // never reached, whatever the path looks like.
        assert!(shared_fallback_rejection(path, temp, None, None, set).is_none());
        assert!(shared_fallback_rejection(path, temp, set, set, None).is_none());
        // Empty is unset, as everywhere else in this module - but a path
        // outside the temporary directory came from somewhere else.
        assert!(shared_fallback_rejection(
            Path::new("/elsewhere/corvex"),
            temp,
            None,
            None,
            Some("")
        )
        .is_none());

        let refused = shared_fallback_rejection(path, temp, None, None, None)
            .expect("a credential path in the shared fallback must be refused");
        assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(refused.to_string().contains("%APPDATA%"), "{refused}");
        // One base variable set and the other not still leaves the base whose
        // variable is missing in the temporary directory.
        assert!(shared_fallback_rejection(path, temp, set, None, None).is_some());
    }

    /// The staging directory has to be one this process created. A name that
    /// already exists is somebody else's, so it is never reused - and eight
    /// collisions in a row means something is sitting on the pattern, which
    /// is an error rather than a directory to write a credential into.
    #[cfg(unix)]
    #[test]
    fn create_private_dir_never_reuses_an_existing_directory() {
        let dir = crate::config::test_tempdir();

        let first = create_private_dir(dir.path()).unwrap();
        let second = create_private_dir(dir.path()).unwrap();

        assert_ne!(first, second);
        for made in [&first, &second] {
            assert!(made.is_dir());
            assert!(
                made.starts_with(dir.path()),
                "the staging directory must sit beside the target, so the rename stays \
                 within one filesystem"
            );
        }
    }

    /// A directory that is not the one `create_private_dir` just made is
    /// refused rather than written into: an attacker who can swap the name
    /// cannot produce a 0700 directory owned by this uid, so the owner and
    /// mode check is what catches the swap.
    #[cfg(unix)]
    #[test]
    fn write_into_private_dir_refuses_a_directory_it_did_not_create() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::config::test_tempdir();
        let staging = dir.path().join("someone-elses");
        std::fs::create_dir(&staging).unwrap();
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o777)).unwrap();

        let err = write_into_private_dir(&staging, &dir.path().join("config.json"), "{}")
            .expect_err("a directory at the wrong mode must not be written into");

        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            !dir.path().join("config.json").exists(),
            "nothing must reach the target name"
        );
    }

    /// `ls -le` is the ACL reader available here: the `acl_*` family is bound
    /// in this crate only where production code needs it — the strip and the
    /// ancestry walk — and widening those bindings to satisfy a test is the
    /// wrong direction.
    #[cfg(target_os = "macos")]
    fn acl_text(path: &Path) -> String {
        let out = std::process::Command::new("/bin/ls")
            .arg("-le")
            .arg(path)
            .output()
            .expect("ls must run");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// The hole 0600 does not close on macOS, driven end to end because
    /// nothing about it is visible to `stat`: a directory carrying a
    /// `file_inherit` ACE hands a copy to every file created inside it, and
    /// that entry is evaluated ahead of the mode. An attacker who
    /// pre-creates the `/tmp` fallback hierarchy that way reads every
    /// credential corvex writes into it without owning a single file.
    ///
    /// The control file is the gate: if the filesystem under `TMPDIR` stores
    /// no ACLs, nothing was inherited and there is nothing to strip, so the
    /// test has no case to make. Where inheritance does happen — which is
    /// APFS, i.e. every current Mac — a regression fails here.
    #[cfg(target_os = "macos")]
    #[test]
    fn write_restricted_strips_an_acl_inherited_from_its_directory() {
        let dir = crate::config::test_tempdir();
        let _ = std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg("everyone allow read,file_inherit")
            .arg(dir.path())
            .status();

        let control = dir.path().join("control");
        std::fs::write(&control, "inherited?").unwrap();
        if !acl_text(&control).contains("everyone") {
            return;
        }

        let config = dir.path().join("config.json");
        write_restricted(&config, "{\"secret\":1}").unwrap();

        let acl = acl_text(&config);
        assert!(
            !acl.contains("everyone"),
            "the inherited ACE must not survive the write: {acl}"
        );
    }

    /// The ordinary case, which is the one nothing else pins: a file under a
    /// directory that hands down no ACE must come back `Absent`, so the
    /// private-directory paths stay the cold paths they are documented to be.
    ///
    /// Trivially true off macOS, where the function is a stub — the test is
    /// here for the Darwin half, where the verdict comes from a libSystem
    /// call whose behaviour on an ACL-less file this repo cannot exercise
    /// anywhere else. Getting it wrong is not a small mistake in the safe
    /// direction: `Removed` on a freshly created file is what
    /// `create_in_private_dir` treats as proof of a swapped name, so a
    /// spurious one fails every credential write on the platform.
    #[cfg(unix)]
    #[test]
    fn strip_inherited_acl_reports_absent_on_an_ordinary_file() {
        let dir = crate::config::test_tempdir();
        let path = dir.path().join("ordinary");
        let file = std::fs::File::create(&path).unwrap();

        assert_eq!(
            strip_inherited_acl(&file, &path).unwrap(),
            AclState::Absent,
            "a file that inherited nothing must not be reported as stripped"
        );
    }

    /// The consequence of the above, driven end to end: two opens of the same
    /// log must land on the same inode. `open_append_restricted` replaces the
    /// inode when — and only when — an ACE was inherited, so a `Removed` that
    /// fires on every ordinary open would copy up to `LOG_MAX_BYTES` and swap
    /// the file on every single corvex invocation, breaking the `tail -f` the
    /// README points users at and losing whichever of two concurrent runs
    /// renamed last.
    #[cfg(unix)]
    #[test]
    fn open_append_restricted_keeps_one_inode_across_calls() {
        use std::io::Write;
        use std::os::unix::fs::MetadataExt;

        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");

        let mut first = open_append_restricted(&log).unwrap();
        first.write_all(b"first run\n").unwrap();
        let before = std::fs::metadata(&log).unwrap().ino();
        drop(first);

        let mut second = open_append_restricted(&log).unwrap();
        second.write_all(b"second run\n").unwrap();
        drop(second);

        assert_eq!(
            std::fs::metadata(&log).unwrap().ino(),
            before,
            "an ordinary log must not be replaced by a fresh inode on reopen"
        );
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "first run\nsecond run\n",
            "and the previous run's records must still be there exactly once"
        );
    }

    /// `open_write_restricted` is the open behind both `write_restricted` and
    /// the PID file, so the refusal has to hold there in its own right: a
    /// symlink is never resolved, and the file it points at is neither
    /// created nor touched.
    #[cfg(unix)]
    #[test]
    fn open_write_restricted_refuses_a_symlink() {
        let dir = crate::config::test_tempdir();
        let victim = dir.path().join("victim");
        let target = dir.path().join("config.json");
        std::fs::write(&victim, "not corvex's\n").unwrap();
        std::os::unix::fs::symlink(&victim, &target).unwrap();

        let err =
            open_write_restricted(&target).expect_err("a symlinked write path must be refused");
        assert_eq!(
            err.raw_os_error(),
            Some(nix::libc::ELOOP),
            "expected ELOOP from O_NOFOLLOW, got {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "not corvex's\n",
            "the symlink target must be left alone"
        );
    }

    /// The open must not truncate: the PID-file preflight probes writability
    /// on a file that may still be tracking a live xray, and emptying it
    /// there would destroy the very thing the next step reads.
    #[cfg(unix)]
    #[test]
    fn open_write_restricted_leaves_existing_contents_alone() {
        let dir = crate::config::test_tempdir();
        let path = dir.path().join("xray.pid");
        std::fs::write(&path, "4242").unwrap();

        drop(open_write_restricted(&path).unwrap());

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "4242");
    }

    /// The lenient twin, for paths the *user* chose. A readerless FIFO must
    /// come back as an error rather than parking the process in `open`
    /// forever - that plant is a whole-command denial of service that costs
    /// one `mkfifo`. Bounded join, because a regression hangs rather than
    /// fails.
    #[cfg(unix)]
    #[test]
    fn open_append_nonblocking_does_not_block_on_a_readerless_fifo() {
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("error.log");
        make_fifo(&log);

        let (sender, receiver) = std::sync::mpsc::channel();
        let probe = log.clone();
        std::thread::spawn(move || {
            let _ = sender.send(open_append_nonblocking(&probe).map(|_| ()));
        });

        receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the open must return, not block waiting for a reader")
            .expect_err("a FIFO with no reader has nowhere to put the bytes");
    }

    /// `O_NONBLOCK` is wanted for the duration of `open` and no longer: this
    /// descriptor becomes xray's stdout and stderr, and a non-blocking write
    /// to a full pipe drops the line instead of waiting for room.
    #[cfg(unix)]
    #[test]
    fn open_append_nonblocking_clears_the_flag_it_opened_with() {
        use std::os::unix::io::AsRawFd;
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("error.log");

        let file = open_append_nonblocking(&log).unwrap();

        // SAFETY: `F_GETFL` on a descriptor this test owns; it reads an int
        // flag word and touches no memory.
        let flags = unsafe { nix::libc::fcntl(file.as_raw_fd(), nix::libc::F_GETFL) };
        assert!(flags != -1, "F_GETFL failed");
        assert_eq!(
            flags & nix::libc::O_NONBLOCK,
            0,
            "the flag must not survive the open, got {flags:o}"
        );
    }

    /// And the difference from the strict open, pinned deliberately: a
    /// symlink at a path the *user* named is redirection they set up, and
    /// `preflight_log_paths` documents it as such. corvex refuses that shape
    /// only where it chose the path itself.
    #[cfg(unix)]
    #[test]
    fn open_append_nonblocking_follows_a_symlink_the_user_set_up() {
        let dir = crate::config::test_tempdir();
        let real = dir.path().join("real-error.log");
        let link = dir.path().join("error.log");
        std::fs::write(&real, "first\n").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let mut file = open_append_nonblocking(&link).unwrap();
        std::io::Write::write_all(&mut file, b"second\n").unwrap();
        drop(file);

        assert_eq!(std::fs::read_to_string(&real).unwrap(), "first\nsecond\n");
    }

    /// Which open `open_xray_log` picks is decided by who chose the path.
    /// `run()` replaces each of these wholesale when `log.xray.*` is set, so
    /// anything that is not a default came from the user. All three defaults
    /// have to be in the set: `access.log` and `error.log` are corvex's picks
    /// just as much as `xray.log` is, and leaving them out was what let the
    /// preflight follow a symlink planted at one of them.
    #[test]
    fn is_corvex_chosen_xray_log_matches_every_path_corvex_picks() {
        for path in [
            default_xray_log(),
            default_xray_access_log(),
            default_xray_error_log(),
        ] {
            assert!(
                is_corvex_chosen_xray_log(&path),
                "a path corvex picks for itself must take the strict open: {}",
                path.display()
            );
        }
        assert!(
            !is_corvex_chosen_xray_log(&PathBuf::from("/var/log/xray/error.log")),
            "a configured path must not"
        );
    }

    /// The defaults xray is handed in its generated config must be the same
    /// paths the predicate above recognises. They were spelled out twice -
    /// once here and once in `XrayLogConfig::default` - and a divergence
    /// silently downgrades the open corvex makes on them.
    #[test]
    fn xray_log_config_defaults_are_the_paths_corvex_claims_to_have_chosen() {
        let defaults = crate::protocol::XrayLogConfig::default();
        assert!(
            is_corvex_chosen_xray_log(Path::new(&defaults.access)),
            "the default access log must be recognised as corvex's own: {}",
            defaults.access
        );
        assert!(
            is_corvex_chosen_xray_log(Path::new(&defaults.error)),
            "the default error log must be recognised as corvex's own: {}",
            defaults.error
        );
    }

    /// The two defaults do not reach the preflight as `PathBuf`s. They are
    /// rendered to `String` by `XrayLogConfig::default` - a JSON string is
    /// what xray's config takes - and rebuilt by
    /// `main::xray_log_preflight_targets`. A path is bytes on unix, so that
    /// round trip loses information the moment `$XDG_STATE_HOME` holds a
    /// byte that is not valid UTF-8, and the reconstructed path stops being
    /// equal to the one the predicate compares against. Answering "not
    /// corvex's" there hands `open_xray_log` the lenient branch for a path
    /// corvex picked itself, in a directory the `/tmp` fallback makes
    /// plantable - the same hole leaving `access.log` and `error.log` out of
    /// the set used to open, arriving through a different door.
    #[cfg(unix)]
    #[test]
    fn matches_chosen_xray_log_survives_the_lossy_round_trip_to_xrays_config() {
        use std::os::unix::ffi::OsStringExt;

        // A state directory that is not valid UTF-8. `\xff` is not a legal
        // byte anywhere in UTF-8, so `to_string_lossy` must substitute it.
        let state = PathBuf::from(std::ffi::OsString::from_vec(b"/tmp/st\xffate".to_vec()));
        let chosen = vec![state.join("xray").join("access.log")];

        let round_tripped = PathBuf::from(chosen[0].to_string_lossy().to_string());
        assert_ne!(
            round_tripped, chosen[0],
            "the fixture must actually be lossy, or this test proves nothing"
        );

        assert!(
            matches_chosen_xray_log(&round_tripped, &chosen),
            "a corvex-chosen log must keep the strict open after the trip \
             through xray's config: {}",
            round_tripped.display()
        );
        assert!(
            matches_chosen_xray_log(&chosen[0], &chosen),
            "and the unrendered path must still match"
        );
        assert!(
            !matches_chosen_xray_log(Path::new("/var/log/xray/access.log"), &chosen),
            "a configured path must not match either spelling"
        );
    }

    /// A directory corvex creates itself is one nobody else can plant a file
    /// in, which removes the `/tmp`-fallback exposure entirely on a fresh
    /// machine. Every component the call creates gets 0700, not just the leaf.
    #[cfg(unix)]
    #[test]
    fn create_dir_restricted_creates_every_component_at_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::config::test_tempdir();
        let leaf = dir.path().join(".local/state/corvex");

        create_dir_restricted(&leaf).unwrap();

        for component in [
            dir.path().join(".local"),
            dir.path().join(".local/state"),
            leaf,
        ] {
            let mode = std::fs::metadata(&component).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o7777,
                0o700,
                "{} was {:o}",
                component.display(),
                mode & 0o7777
            );
        }
    }

    /// `create_dir_all` semantics for a directory that already exists, mode
    /// included. corvex has no business narrowing `~/.config` because it wanted
    /// a subdirectory of it, and chmod-ing a directory an attacker already owns
    /// would fail anyway — that case belongs to `accept_restricted_file`.
    #[cfg(unix)]
    #[test]
    fn create_dir_restricted_leaves_an_existing_directory_alone() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::config::test_tempdir();
        let existing = dir.path().join("config");
        std::fs::create_dir(&existing).unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).unwrap();

        create_dir_restricted(&existing).expect("an existing directory is not an error");

        let mode = std::fs::metadata(&existing).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o755, "mode was {:o}", mode & 0o7777);
    }

    /// `write_restricted` truncates, so following a link there clobbers the
    /// target as well as leaking the credential it is about to write.
    #[cfg(unix)]
    #[test]
    fn write_restricted_refuses_a_symlink() {
        let dir = crate::config::test_tempdir();
        let victim = dir.path().join("victim");
        let config = dir.path().join("config.json");
        std::fs::write(&victim, "not corvex's\n").unwrap();
        std::os::unix::fs::symlink(&victim, &config).unwrap();

        write_restricted(&config, "{\"secret\":1}").expect_err("a symlinked path must be refused");

        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "not corvex's\n",
            "the symlink target must not be written through"
        );
    }

    #[test]
    fn rotate_if_oversized_rotates_past_the_threshold() {
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");
        std::fs::write(&log, "0123456789").unwrap();

        assert!(rotate_if_oversized(&log, 4).unwrap());

        assert!(!log.exists());
        assert_eq!(
            std::fs::read_to_string(log.with_extension("log.1")).unwrap(),
            "0123456789"
        );
    }

    /// Rotation is strictly greater-than: a file exactly at the limit stays.
    #[test]
    fn rotate_if_oversized_is_exclusive_at_the_threshold() {
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");
        std::fs::write(&log, "0123456789").unwrap();

        assert!(
            !rotate_if_oversized(&log, 10).unwrap(),
            "a file exactly at the limit has not passed it"
        );
        assert!(log.exists());

        assert!(
            rotate_if_oversized(&log, 9).unwrap(),
            "one byte past the limit rotates"
        );
        assert!(!log.exists());
    }

    #[test]
    fn rotate_if_oversized_leaves_a_small_file_alone() {
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");
        std::fs::write(&log, "small").unwrap();

        assert!(!rotate_if_oversized(&log, LOG_MAX_BYTES).unwrap());

        assert_eq!(std::fs::read_to_string(&log).unwrap(), "small");
        assert!(!log.with_extension("log.1").exists());
    }

    #[test]
    fn rotate_if_oversized_overwrites_a_previous_generation() {
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");
        let rotated = log.with_extension("log.1");
        std::fs::write(&rotated, "stale generation").unwrap();
        std::fs::write(&log, "current generation").unwrap();

        assert!(rotate_if_oversized(&log, 4).unwrap());

        assert_eq!(
            std::fs::read_to_string(&rotated).unwrap(),
            "current generation"
        );
    }

    #[test]
    fn rotate_if_oversized_tolerates_a_missing_file() {
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("never-written.log");

        assert!(!rotate_if_oversized(&log, LOG_MAX_BYTES).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn rotated_file_keeps_the_restricted_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");
        {
            let mut file = open_append_restricted(&log).unwrap();
            std::io::Write::write_all(&mut file, b"0123456789").unwrap();
        }

        assert!(rotate_if_oversized(&log, 4).unwrap());

        let mode = std::fs::metadata(log.with_extension("log.1"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }

    #[test]
    fn shell_quote_wraps_plain_string() {
        assert_eq!(
            shell_quote("/var/log/xray/access.log"),
            "'/var/log/xray/access.log'"
        );
    }

    #[test]
    fn shell_quote_escapes_embedded_single_quote() {
        assert_eq!(shell_quote("it's/here"), "'it'\\''s/here'");
    }

    #[test]
    fn shell_quote_preserves_spaces() {
        assert_eq!(
            shell_quote("/var/log/xray dir/access.log"),
            "'/var/log/xray dir/access.log'"
        );
    }
}
