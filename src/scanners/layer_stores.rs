//! Where a container runtime keeps the layers of its images. The search for
//! log files leaves these directories alone: what a container logs is found
//! through its runtime, and a file inside an image is not a log this host
//! writes.

use std::path::{Path, PathBuf};

/// A Docker engine gives each storage driver one directory under its data
/// root, named after the driver. The driver keeps nothing there but layers:
/// those of every image, and the writable one of every container.
#[cfg(unix)]
const DOCKER_STORAGE_DRIVERS: &[&str] = &[
    "aufs",
    "btrfs",
    "devicemapper",
    "fuse-overlayfs",
    "overlay",
    "overlay2",
    "vfs",
    "zfs",
];
#[cfg(windows)]
const DOCKER_STORAGE_DRIVERS: &[&str] = &["windowsfilter"];

/// containerd gives each snapshotter one directory under its root, named
/// after the kind of plugin and then the snapshotter.
const CONTAINERD_SNAPSHOTTER: &str = "io.containerd.snapshotter.v1";
#[cfg(unix)]
const CONTAINERD_SNAPSHOTTERS: &[&str] = &[
    "blockfile",
    "btrfs",
    "devmapper",
    "erofs",
    "native",
    "overlayfs",
    "zfs",
];
#[cfg(windows)]
const CONTAINERD_SNAPSHOTTERS: &[&str] = &["windows", "windows-lcow"];

#[cfg(unix)]
const DEFAULT_CONTAINERD_ROOT: &str = "/var/lib/containerd";
#[cfg(windows)]
const DEFAULT_CONTAINERD_ROOT: &str = r"C:\ProgramData\containerd\root";

/// Every place a layer store can be on this host: under the default data
/// roots of Docker and containerd, and under the data root a Docker engine
/// named. A data root that was moved and that no engine named is not known.
pub(crate) fn on_this_host(docker_data_root: Option<&Path>) -> Vec<PathBuf> {
    let mut docker_data_roots = vec![super::docker::default_data_root()];
    if let Some(named) = docker_data_root
        && named != docker_data_roots[0]
    {
        docker_data_roots.push(named.to_path_buf());
    }

    let mut containerd_roots = vec![PathBuf::from(DEFAULT_CONTAINERD_ROOT)];
    let mut stores = Vec::new();
    for data_root in &docker_data_roots {
        stores.extend(
            DOCKER_STORAGE_DRIVERS
                .iter()
                .map(|driver| data_root.join(driver)),
        );
        // A Docker engine that starts a containerd of its own keeps that
        // one's data here.
        containerd_roots.push(data_root.join("containerd").join("daemon"));
    }
    for root in &containerd_roots {
        stores.extend(
            CONTAINERD_SNAPSHOTTERS
                .iter()
                .map(|snapshotter| root.join(format!("{CONTAINERD_SNAPSHOTTER}.{snapshotter}"))),
        );
    }
    stores
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn layer_stores_lie_under_the_default_data_roots_and_the_one_the_engine_named() {
        let stores = on_this_host(Some(Path::new("/mnt/docker-data")));

        for store in [
            "/var/lib/docker/overlay2",
            "/var/lib/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs",
            "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs",
            "/mnt/docker-data/overlay2",
            "/mnt/docker-data/containerd/daemon/io.containerd.snapshotter.v1.overlayfs",
        ] {
            assert!(stores.contains(&PathBuf::from(store)), "{store}");
        }
    }

    #[test]
    fn a_data_root_holds_more_than_layers() {
        let stores = on_this_host(None);

        for searched in [
            "/var/lib/docker",
            "/var/lib/docker/containers",
            "/var/lib/docker/volumes",
            "/var/lib/docker/image",
            "/var/lib/containerd",
            "/var/lib/containerd/io.containerd.content.v1.content",
        ] {
            assert!(
                !stores
                    .iter()
                    .any(|store| Path::new(searched).starts_with(store)),
                "{searched}"
            );
        }
    }

    #[test]
    fn the_default_data_root_counts_once_when_the_engine_names_it() {
        assert_eq!(
            on_this_host(Some(Path::new("/var/lib/docker"))),
            on_this_host(None)
        );
    }
}
