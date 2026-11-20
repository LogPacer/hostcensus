//! Handing a bundle to the person who ran `sudo`.
//!
//! A census has to run as root to see everything, and a file root creates
//! belongs to root. The person who ran `sudo hostcensus` could then not open
//! their own census. So a bundle written as root under `sudo` is given to
//! the user who ran `sudo`, wherever that user could have put a file
//! themselves. Anywhere else it stays root's: a file of one's own in a
//! directory only root may write to is a way to become root.

use std::fmt;
use std::fs::File;
use std::io;
use std::path::Path;

/// The user who ran `sudo`, by the ids `sudo` passes on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SudoUser {
    uid: u32,
    gid: u32,
}

impl SudoUser {
    /// Who ran this process through `sudo`, if it runs as root that way.
    pub fn of_this_process() -> Option<Self> {
        #[cfg(unix)]
        {
            let variable = |name| std::env::var(name).ok();
            Self::who_ran(
                crate::host::privileged(),
                variable("SUDO_UID").as_deref(),
                variable("SUDO_GID").as_deref(),
            )
        }
        #[cfg(not(unix))]
        None
    }

    /// `sudo` names the user who ran it in `SUDO_UID` and `SUDO_GID`. The
    /// variables count only for a process that runs as root, because no
    /// other process can give a file away, and only when both hold a plain
    /// id. Root running `sudo` is nobody to hand a file to.
    #[cfg(any(unix, test))]
    pub(crate) fn who_ran(
        as_root: bool,
        sudo_uid: Option<&str>,
        sudo_gid: Option<&str>,
    ) -> Option<Self> {
        if !as_root {
            return None;
        }
        let uid = plain_id(sudo_uid?)?;
        let gid = plain_id(sudo_gid?)?;
        (uid != 0).then_some(Self { uid, gid })
    }
}

impl fmt::Display for SudoUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "user {} (group {})", self.uid, self.gid)
    }
}

/// An id written in decimal digits and nothing else. The highest number is
/// not an id: to the call that changes an owner it means "leave as it is".
#[cfg(any(unix, test))]
fn plain_id(text: &str) -> Option<u32> {
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok().filter(|id| *id != u32::MAX)
}

/// Whose a bundle file is once it is written.
#[derive(Debug)]
pub enum Handover {
    /// Nobody ran `sudo`. The file belongs to whoever ran hostcensus.
    NotNeeded,
    /// The file belongs to the user who ran `sudo`.
    Done(SudoUser),
    /// That user could not have put a file in this directory themselves, so
    /// the file stays root's.
    NotTheirDirectory(SudoUser),
    /// The file system would not change the owner, so the file stays root's.
    Refused(SudoUser, io::Error),
}

impl Handover {
    /// What the person is told about the owner of the file, when `sudo` was
    /// involved.
    pub fn note(&self) -> Option<String> {
        match self {
            Self::NotNeeded => None,
            Self::Done(user) => Some(format!("The file belongs to {user}, who ran sudo.")),
            Self::NotTheirDirectory(user) => Some(format!(
                "The file belongs to root, because {user}, who ran sudo, does not own the \
                 directory it is in. For a file that user can read, run hostcensus from a \
                 directory of that user's, or pass --output into one."
            )),
            Self::Refused(user, error) => Some(format!(
                "The file belongs to root, because it could not be given to {user}, who ran \
                 sudo: {error}"
            )),
        }
    }
}

#[cfg(unix)]
impl SudoUser {
    /// Creates the file for a new bundle, readable by its owner only, and
    /// hands it to this user where the directory allows it. An existing
    /// file is never replaced.
    pub(crate) fn create(self, path: &Path) -> io::Result<(File, Handover)> {
        let (directory, name) = Directory::holding(path)?;
        let theirs = directory.admits(self)?;
        let file = directory.create_private(name)?;
        let handover = if !theirs {
            Handover::NotTheirDirectory(self)
        } else {
            match self.take(&file) {
                Ok(()) => Handover::Done(self),
                Err(error) => Handover::Refused(self, error),
            }
        };
        Ok((file, handover))
    }

    /// Replaces the bundle at `path` with `content`, written beside it and
    /// moved into place. The new file is this user's when the directory
    /// allows it or the bundle it replaces was already theirs. When the
    /// owner cannot be changed the bundle is left as it was.
    pub(crate) fn replace(self, path: &Path, content: &[u8]) -> io::Result<Handover> {
        use std::io::Write as _;

        let (directory, name) = Directory::holding(path)?;
        let theirs = directory.admits(self)? || directory.has_a_file_of(name, self)?;
        let mut beside = name.to_owned();
        beside.push(crate::output::BESIDE_SUFFIX);

        let mut file = directory.create_private(&beside)?;
        let owner_set = if theirs { self.take(&file) } else { Ok(()) };
        let written = owner_set
            .and_then(|()| file.write_all(content))
            .and_then(|()| file.sync_all())
            .and_then(|()| directory.rename(&beside, name));
        if written.is_err() {
            let _ = directory.remove(&beside);
        }
        written.map(|()| {
            if theirs {
                Handover::Done(self)
            } else {
                Handover::NotTheirDirectory(self)
            }
        })
    }

    /// Makes this user the owner of an open file. The change goes through
    /// the handle, so it lands on the file hostcensus created and on no
    /// other, whatever has been put at its path since.
    fn take(self, file: &File) -> io::Result<()> {
        std::os::unix::fs::fchown(file, Some(self.uid), Some(self.gid))
    }
}

/// `sudo` exists on Unix only, so there is never such a user here.
#[cfg(not(unix))]
impl SudoUser {
    pub(crate) fn create(self, _: &Path) -> io::Result<(File, Handover)> {
        Err(io::ErrorKind::Unsupported.into())
    }

    pub(crate) fn replace(self, _: &Path, _: &[u8]) -> io::Result<Handover> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// The directory a bundle lies in, held open. Whether the user who ran
/// `sudo` could have written here is asked of this handle, and the file is
/// created and moved into place through it. A link swapped into the path
/// after the question cannot move the file to a directory with another
/// answer.
#[cfg(unix)]
struct Directory(std::os::fd::OwnedFd);

#[cfg(unix)]
impl Directory {
    /// Opens the directory `file` lies in, and names the file within it.
    fn holding(file: &Path) -> io::Result<(Self, &std::ffi::OsStr)> {
        use rustix::fs::{Mode, OFlags};

        let name = file
            .file_name()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let directory = match file.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let handle = rustix::fs::open(
            directory,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok((Self(handle), name))
    }

    /// Whether `user` could have put a file here themselves: the directory
    /// is theirs, or everyone may write to it.
    fn admits(&self, user: SudoUser) -> io::Result<bool> {
        use rustix::fs::Mode;

        let directory = rustix::fs::fstat(&self.0)?;
        Ok(directory.st_uid == user.uid
            || Mode::from_raw_mode(directory.st_mode).contains(Mode::WOTH))
    }

    /// Whether `name` is a file here that belongs to `user`. A link is not
    /// followed.
    fn has_a_file_of(&self, name: &std::ffi::OsStr, user: SudoUser) -> io::Result<bool> {
        use rustix::fs::{AtFlags, FileType};

        match rustix::fs::statat(&self.0, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(found) => Ok(found.st_uid == user.uid
                && FileType::from_raw_mode(found.st_mode) == FileType::RegularFile),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn create_private(&self, name: &std::ffi::OsStr) -> io::Result<File> {
        use rustix::fs::{Mode, OFlags};

        let handle = rustix::fs::openat(
            &self.0,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        Ok(File::from(handle))
    }

    fn rename(&self, from: &std::ffi::OsStr, to: &std::ffi::OsStr) -> io::Result<()> {
        Ok(rustix::fs::renameat(&self.0, from, &self.0, to)?)
    }

    fn remove(&self, name: &std::ffi::OsStr) -> io::Result<()> {
        Ok(rustix::fs::unlinkat(
            &self.0,
            name,
            rustix::fs::AtFlags::empty(),
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_under_sudo_writes_for_the_user_sudo_names() {
        assert_eq!(
            SudoUser::who_ran(true, Some("1000"), Some("1001")),
            Some(SudoUser {
                uid: 1000,
                gid: 1001
            })
        );
    }

    #[test]
    fn without_root_the_sudo_variables_count_for_nothing() {
        assert_eq!(SudoUser::who_ran(false, Some("1000"), Some("1000")), None);
    }

    #[test]
    fn root_without_both_variables_writes_for_itself() {
        assert_eq!(SudoUser::who_ran(true, None, None), None);
        assert_eq!(SudoUser::who_ran(true, Some("1000"), None), None);
        assert_eq!(SudoUser::who_ran(true, None, Some("1000")), None);
    }

    #[test]
    fn a_value_that_is_not_a_plain_id_names_nobody() {
        for value in [
            "",
            "-1",
            "+1000",
            " 1000",
            "1000 ",
            "1e3",
            "0x3e8",
            "1000.0",
            "morten",
            "１０００",
            "4294967295",
            "4294967296",
        ] {
            assert_eq!(
                SudoUser::who_ran(true, Some(value), Some("1000")),
                None,
                "SUDO_UID={value:?}"
            );
            assert_eq!(
                SudoUser::who_ran(true, Some("1000"), Some(value)),
                None,
                "SUDO_GID={value:?}"
            );
        }
    }

    #[test]
    fn root_running_sudo_is_nobody_to_hand_a_file_to() {
        assert_eq!(SudoUser::who_ran(true, Some("0"), Some("0")), None);
    }

    #[test]
    fn the_note_names_the_user_or_says_why_the_file_stayed_with_root() {
        let user = SudoUser {
            uid: 1000,
            gid: 1001,
        };

        assert_eq!(Handover::NotNeeded.note(), None);
        assert_eq!(
            Handover::Done(user).note().unwrap(),
            "The file belongs to user 1000 (group 1001), who ran sudo."
        );
        let not_theirs = Handover::NotTheirDirectory(user).note().unwrap();
        assert!(
            not_theirs.starts_with("The file belongs to root, because user 1000 (group 1001)"),
            "{not_theirs}"
        );
        assert!(not_theirs.contains("--output"), "{not_theirs}");
        let refused = Handover::Refused(user, io::ErrorKind::PermissionDenied.into())
            .note()
            .unwrap();
        assert!(
            refused.starts_with("The file belongs to root, because it could not be given to"),
            "{refused}"
        );
    }

    #[cfg(unix)]
    mod on_disk {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        use super::super::*;

        fn myself() -> SudoUser {
            SudoUser {
                uid: rustix::process::getuid().as_raw(),
                gid: rustix::process::getgid().as_raw(),
            }
        }

        fn someone_else() -> SudoUser {
            SudoUser {
                uid: myself().uid + 4242,
                gid: myself().gid + 4242,
            }
        }

        fn as_root() -> bool {
            rustix::process::geteuid().is_root()
        }

        fn open_to_everyone(directory: &Path) {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o777)).unwrap();
        }

        #[test]
        fn a_file_in_the_users_own_directory_is_handed_over_private() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("census.json");

            let (_, handover) = myself().create(&path).unwrap();

            assert!(matches!(handover, Handover::Done(user) if user == myself()));
            let written = std::fs::metadata(&path).unwrap();
            assert_eq!(written.uid(), myself().uid);
            assert_eq!(written.gid(), myself().gid);
            assert_eq!(written.permissions().mode() & 0o777, 0o600);
        }

        #[test]
        fn a_file_in_a_directory_that_is_not_the_users_stays_as_it_was_created() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("census.json");

            let (_, handover) = someone_else().create(&path).unwrap();

            assert!(matches!(handover, Handover::NotTheirDirectory(_)));
            let written = std::fs::metadata(&path).unwrap();
            assert_eq!(written.uid(), myself().uid);
            assert_eq!(written.permissions().mode() & 0o777, 0o600);
        }

        #[test]
        fn a_directory_open_to_everyone_admits_any_user() {
            let dir = tempfile::tempdir().unwrap();
            open_to_everyone(dir.path());
            let path = dir.path().join("census.json");

            let (_, handover) = someone_else().create(&path).unwrap();

            // Only root may give a file away, so the same call is refused
            // by the system for anyone else.
            let written = std::fs::metadata(&path).unwrap();
            if as_root() {
                assert!(matches!(handover, Handover::Done(_)));
                assert_eq!(written.uid(), someone_else().uid);
                assert_eq!(written.gid(), someone_else().gid);
            } else {
                assert!(matches!(handover, Handover::Refused(..)));
                assert_eq!(written.uid(), myself().uid);
            }
            assert_eq!(written.permissions().mode() & 0o777, 0o600);
        }

        #[test]
        fn an_existing_file_is_never_replaced_and_a_link_is_not_followed() {
            let dir = tempfile::tempdir().unwrap();
            let existing = dir.path().join("census.json");
            std::fs::write(&existing, "keep me").unwrap();
            let elsewhere = dir.path().join("elsewhere");
            let link = dir.path().join("link.json");
            std::os::unix::fs::symlink(&elsewhere, &link).unwrap();

            for path in [&existing, &link] {
                let error = myself().create(path).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
            }

            assert_eq!(std::fs::read_to_string(&existing).unwrap(), "keep me");
            assert!(!elsewhere.exists());
        }

        #[test]
        fn a_replaced_bundle_is_handed_over_and_nothing_is_left_beside_it() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("census.json");
            std::fs::write(&path, "old").unwrap();

            let handover = myself().replace(&path, b"new").unwrap();

            assert!(matches!(handover, Handover::Done(_)));
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
            let written = std::fs::metadata(&path).unwrap();
            assert_eq!(written.uid(), myself().uid);
            assert_eq!(written.permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }

        #[test]
        fn a_bundle_in_a_directory_that_is_not_the_users_is_replaced_without_a_handover() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("census.json");
            std::fs::write(&path, "old").unwrap();

            let handover = someone_else().replace(&path, b"new").unwrap();

            assert!(matches!(handover, Handover::NotTheirDirectory(_)));
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
            assert_eq!(std::fs::metadata(&path).unwrap().uid(), myself().uid);
        }

        #[test]
        fn a_bundle_that_cannot_be_handed_over_is_left_as_it_was() {
            if as_root() {
                return;
            }
            let dir = tempfile::tempdir().unwrap();
            open_to_everyone(dir.path());
            let path = dir.path().join("census.json");
            std::fs::write(&path, "old").unwrap();

            let error = someone_else().replace(&path, b"new").unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "old");
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }
}
