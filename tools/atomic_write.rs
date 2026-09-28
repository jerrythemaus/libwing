//! Crash-safe publication of tool outputs, shared by `wingschema` and `wingcapture` via
//! `#[path = "atomic_write.rs"] mod atomic_write;`.
//!
//! Every output is staged beside its destination, synced, and renamed into place. An existing
//! destination that is a symlink or not a regular file is refused before anything is written,
//! and a failure part-way through a multi-file publish restores the previous files.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub fn staged_path(path: &Path, suffix: &str) -> PathBuf {
    static NEXT_STAGED_PATH: AtomicU64 = AtomicU64::new(0);
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let sequence = NEXT_STAGED_PATH.fetch_add(1, Ordering::Relaxed);
    path.with_file_name(format!(
        ".{name}.{}.{sequence}.{suffix}",
        std::process::id()
    ))
}

pub fn publication_error(primary: std::io::Error, rollback_errors: &[String]) -> std::io::Error {
    if rollback_errors.is_empty() {
        primary
    } else {
        std::io::Error::new(
            primary.kind(),
            format!(
                "{primary}; rollback also failed: {}",
                rollback_errors.join("; ")
            ),
        )
    }
}

pub fn publish_outputs(outputs: &[(&Path, &[u8])]) -> std::io::Result<()> {
    for (path, _) in outputs {
        if let Ok(metadata) = std::fs::symlink_metadata(path) {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(std::io::Error::other(format!(
                    "refusing to replace non-regular output {}",
                    path.display()
                )));
            }
        }
    }

    let mut staged = Vec::with_capacity(outputs.len());
    for (path, contents) in outputs {
        let temp = staged_path(path, "tmp");
        let write_result = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .and_then(|mut file| file.write_all(contents).and_then(|()| file.sync_all()));
        if let Err(error) = write_result {
            for prior in &staged {
                let _ = std::fs::remove_file(prior);
            }
            return Err(error);
        }
        staged.push(temp);
    }

    let mut backups: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(outputs.len());
    for (path, _) in outputs {
        if path.exists() {
            let backup = staged_path(path, "bak");
            let backup_result = std::fs::hard_link(path, &backup).and_then(|()| {
                if let Err(error) = std::fs::remove_file(path) {
                    let _ = std::fs::remove_file(&backup);
                    return Err(error);
                }
                Ok(())
            });
            if let Err(error) = backup_result {
                let mut rollback_errors = Vec::new();
                for (original, saved) in backups.iter().rev() {
                    if let Err(rollback_error) = std::fs::rename(saved, original) {
                        rollback_errors.push(format!(
                            "restore {} from {}: {rollback_error}",
                            original.display(),
                            saved.display()
                        ));
                    }
                }
                for temp in &staged {
                    let _ = std::fs::remove_file(temp);
                }
                return Err(publication_error(error, &rollback_errors));
            }
            backups.push((path.to_path_buf(), backup));
        }
    }

    for (index, ((path, _), temp)) in outputs.iter().zip(&staged).enumerate() {
        if let Err(error) = std::fs::rename(temp, path) {
            let mut rollback_errors = Vec::new();
            for (published, _) in outputs.iter().take(index) {
                if let Err(rollback_error) = std::fs::remove_file(published) {
                    rollback_errors.push(format!(
                        "remove partially published {}: {rollback_error}",
                        published.display()
                    ));
                }
            }
            for (original, saved) in backups.iter().rev() {
                if let Err(rollback_error) = std::fs::rename(saved, original) {
                    rollback_errors.push(format!(
                        "restore {} from {}: {rollback_error}",
                        original.display(),
                        saved.display()
                    ));
                }
            }
            for remaining in staged.iter().skip(index) {
                let _ = std::fs::remove_file(remaining);
            }
            return Err(publication_error(error, &rollback_errors));
        }
    }
    // Every output is published by now; a leftover backup is clutter, not a failed publish.
    for (_, backup) in backups {
        if let Err(error) = std::fs::remove_file(&backup) {
            eprintln!(
                "warning: could not remove backup {}: {error}",
                backup.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_error_includes_rollback_failures() {
        let error = publication_error(
            std::io::Error::other("publish failed"),
            &["restore first output failed".to_string()],
        );

        let message = error.to_string();
        assert!(message.contains("publish failed"));
        assert!(message.contains("restore first output failed"));
    }

    #[cfg(unix)]
    #[test]
    fn staged_publication_rejects_symlink_outputs_and_temp_collisions() {
        use std::os::unix::fs::symlink;

        let temp =
            std::env::temp_dir().join(format!("wingschema-symlink-output-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let victim = temp.join("victim");
        let output = temp.join("output");
        std::fs::write(&victim, "keep").unwrap();
        symlink(&victim, &output).unwrap();

        assert!(publish_outputs(&[(&output, b"replace")]).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        assert!(std::fs::symlink_metadata(&output)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn publish_replaces_an_existing_output_and_leaves_no_staging_files() {
        let temp =
            std::env::temp_dir().join(format!("atomic-write-replace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let output = temp.join("output");
        std::fs::write(&output, "old").unwrap();

        publish_outputs(&[(&output, b"new")]).unwrap();

        assert_eq!(std::fs::read_to_string(&output).unwrap(), "new");
        let leftovers: Vec<_> = std::fs::read_dir(&temp)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name != "output")
            .collect();
        assert!(
            leftovers.is_empty(),
            "staging files left behind: {leftovers:?}"
        );
        let _ = std::fs::remove_dir_all(&temp);
    }
}
