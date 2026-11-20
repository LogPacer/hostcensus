//! Containers of a Docker-compatible engine, read over its local endpoint.
//!
//! Only a Unix socket or, on Windows, a named pipe of this host is ever
//! contacted. An engine configured through a network address, or a pipe on
//! another machine, is refused, not followed.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use bollard::query_parameters::{InspectContainerOptions, ListContainersOptions};
use bollard::{API_DEFAULT_VERSION, Docker};

use super::container::ObservedContainer;
use crate::bundle::ScannerReport;

const ENGINE_TIMEOUT_SECS: u64 = 10;
#[cfg(any(unix, test))]
const DEFAULT_SOCKET: &str = "/var/run/docker.sock";
#[cfg(any(windows, test))]
const DEFAULT_PIPE: &str = "//./pipe/docker_engine";
#[cfg(unix)]
const DEFAULT_DATA_ROOT: &str = "/var/lib/docker";
#[cfg(windows)]
const DEFAULT_DATA_ROOT: &str = r"C:\ProgramData\docker";

pub(crate) struct DockerScan {
    pub containers: Vec<ObservedContainer>,
    /// The engine's log directory and the log file of each inspected
    /// container. These are accounted for by the containers listed here.
    pub owned_paths: Vec<PathBuf>,
    pub engine_answered: bool,
    /// Where the engine keeps its data, when it said. When it did not, its
    /// log directory is assumed to be the default one.
    pub data_root: Option<PathBuf>,
    pub report: ScannerReport,
}

impl DockerScan {
    fn nothing(report: ScannerReport) -> Self {
        Self {
            containers: Vec::new(),
            owned_paths: Vec::new(),
            engine_answered: false,
            data_root: None,
            report,
        }
    }
}

pub(crate) fn default_data_root() -> PathBuf {
    PathBuf::from(DEFAULT_DATA_ROOT)
}

pub(crate) fn default_json_log_root() -> PathBuf {
    json_log_root(Path::new(DEFAULT_DATA_ROOT))
}

fn json_log_root(data_root: &Path) -> PathBuf {
    data_root.join("containers")
}

pub(crate) async fn scan() -> DockerScan {
    let docker_host = std::env::var("DOCKER_HOST").ok();
    let container_host = std::env::var("CONTAINER_HOST").ok();

    #[cfg(unix)]
    let (default_endpoint, local_address) = (
        Path::new(DEFAULT_SOCKET).exists().then_some(DEFAULT_SOCKET),
        local_unix_socket,
    );
    #[cfg(windows)]
    let (default_endpoint, local_address) = (
        pipe_exists(Path::new(DEFAULT_PIPE)).then_some(DEFAULT_PIPE),
        local_named_pipe,
    );

    match choose_endpoint(
        docker_host.as_deref(),
        container_host.as_deref(),
        default_endpoint,
        local_address,
    ) {
        // No engine is configured and none listens at the default endpoint.
        None => DockerScan::nothing(ScannerReport::complete()),
        Some(Endpoint::Remote {
            configured_by,
            scheme,
        }) => DockerScan::nothing(remote_engine_refused(configured_by, &scheme)),
        #[cfg(unix)]
        Some(Endpoint::Local(socket)) => scan_socket(&socket).await,
        #[cfg(windows)]
        Some(Endpoint::Local(pipe)) => scan_pipe(&pipe).await,
    }
}

/// Opens the pipe the way a client would, and closes it again. That is the
/// one way to learn whether a named pipe exists and may be used.
#[cfg(windows)]
fn open_pipe(pipe: &Path) -> std::io::Result<()> {
    let windows_path = pipe.to_string_lossy().replace('/', "\\");
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(windows_path)
        .map(drop)
}

/// A pipe that is busy or refuses this user still exists.
#[cfg(windows)]
fn pipe_exists(pipe: &Path) -> bool {
    !matches!(open_pipe(pipe), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
}

#[cfg(windows)]
async fn scan_pipe(pipe: &Path) -> DockerScan {
    if let Err(error) = open_pipe(pipe)
        && matches!(
            error.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
        )
    {
        return DockerScan::nothing(ScannerReport::unavailable(format!(
            "cannot open the Docker pipe at {}: {}",
            pipe.display(),
            error.kind()
        )));
    }
    let Ok(engine) = Docker::connect_with_named_pipe(
        &pipe.to_string_lossy(),
        ENGINE_TIMEOUT_SECS,
        API_DEFAULT_VERSION,
    ) else {
        return DockerScan::nothing(ScannerReport::unavailable(format!(
            "cannot use the Docker pipe at {}",
            pipe.display()
        )));
    };
    scan_engine(&engine, pipe).await
}

#[cfg(unix)]
async fn scan_socket(socket: &Path) -> DockerScan {
    if let Err(error) = std::os::unix::net::UnixStream::connect(socket) {
        return DockerScan::nothing(ScannerReport::unavailable(format!(
            "cannot connect to the Docker socket at {}: {}",
            socket.display(),
            error.kind()
        )));
    }
    let Ok(engine) = Docker::connect_with_unix(
        &socket.to_string_lossy(),
        ENGINE_TIMEOUT_SECS,
        API_DEFAULT_VERSION,
    ) else {
        return DockerScan::nothing(ScannerReport::unavailable(format!(
            "cannot use the Docker socket at {}",
            socket.display()
        )));
    };
    scan_engine(&engine, socket).await
}

async fn scan_engine(engine: &Docker, endpoint: &Path) -> DockerScan {
    let everything = ListContainersOptions {
        all: true,
        ..Default::default()
    };
    let (info, listed) = tokio::join!(engine.info(), engine.list_containers(Some(everything)));

    let Ok(listed) = listed else {
        return DockerScan::nothing(ScannerReport::unavailable(format!(
            "the Docker engine at {} did not list its containers",
            endpoint.display()
        )));
    };
    let data_root = info
        .ok()
        .and_then(|info| info.docker_root_dir)
        .filter(|root| !root.is_empty())
        .map(PathBuf::from);

    let mut containers = Vec::with_capacity(listed.len());
    let mut not_inspected = 0usize;

    for summary in &listed {
        let id = summary.id.as_deref().unwrap_or("");
        let short_id = id.get(..12).unwrap_or(id);
        let name = summary
            .names
            .as_deref()
            .and_then(<[String]>::first)
            .map_or(short_id, String::as_str);
        let name = name.strip_prefix('/').unwrap_or(name).to_string();
        let state = summary
            .state
            .as_ref()
            .map_or_else(|| "unknown".to_string(), ToString::to_string);
        let labels = summary.labels.clone().unwrap_or_default();

        // Only a running container is inspected, for its log path and its
        // environment. Which of its variables keep their value in the bundle
        // is decided where the census entry is made.
        let (log_path, log_driver, env) = if state == "running" {
            match engine
                .inspect_container(id, None::<InspectContainerOptions>)
                .await
            {
                Ok(detail) => (
                    detail.log_path.unwrap_or_default(),
                    detail
                        .host_config
                        .and_then(|host| host.log_config)
                        .and_then(|log| log.typ)
                        .unwrap_or_default(),
                    detail
                        .config
                        .and_then(|config| config.env)
                        .unwrap_or_default(),
                ),
                Err(_) => {
                    not_inspected += 1;
                    (String::new(), String::new(), Vec::new())
                }
            }
        } else {
            (String::new(), String::new(), Vec::new())
        };

        // The variable is the only signal that counts as naming the service
        // on purpose. Labels and the container name fill it in otherwise.
        let chosen_service_name = explicit_service_name(&env);
        let service_name_explicit = chosen_service_name.is_some();
        let service_name =
            chosen_service_name.unwrap_or_else(|| service_name_from_labels(&labels, &name));

        containers.push(ObservedContainer {
            id: short_id.to_string(),
            name,
            service_name,
            service_name_explicit,
            image: summary.image.clone().unwrap_or_else(|| "unknown".into()),
            state,
            labels,
            env,
            runtime: "docker".to_string(),
            log_path,
            log_driver,
            container_id: id.to_string(),
            ..ObservedContainer::default()
        });
    }

    let mut owned_paths: Vec<PathBuf> = data_root
        .as_deref()
        .map(json_log_root)
        .into_iter()
        .collect();
    owned_paths.extend(
        containers
            .iter()
            .filter(|container| !container.log_path.is_empty())
            .map(|container| PathBuf::from(&container.log_path)),
    );

    let mut gaps = Vec::new();
    match not_inspected {
        0 => {}
        1 => gaps.push(
            "1 running container could not be inspected, so its log path is missing".to_string(),
        ),
        count => gaps.push(format!(
            "{count} running containers could not be inspected, so their log paths are missing"
        )),
    }
    if data_root.is_none() {
        gaps.push("the engine did not say where it keeps its data".to_string());
    }
    let report = if gaps.is_empty() {
        ScannerReport::complete()
    } else {
        ScannerReport::partial(gaps.join("; "))
    };

    DockerScan {
        containers,
        owned_paths,
        engine_answered: true,
        data_root,
        report,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Endpoint {
    /// A Unix socket or a named pipe of this host.
    Local(PathBuf),
    Remote {
        configured_by: &'static str,
        scheme: String,
    },
}

/// The first configured engine wins. The configuration of the Docker CLI is
/// not consulted: that file also holds registry credentials, and hostcensus
/// does not open it. If the engine is not local to this host it is refused; a
/// later local one is not used in its place, because the person asked for
/// the other engine.
fn choose_endpoint(
    docker_host: Option<&str>,
    container_host: Option<&str>,
    default_endpoint: Option<&str>,
    local_address: impl Fn(&str) -> Option<PathBuf>,
) -> Option<Endpoint> {
    let (configured_by, host) = [
        ("DOCKER_HOST", docker_host),
        ("CONTAINER_HOST", container_host),
        ("default", default_endpoint),
    ]
    .into_iter()
    .find_map(|(configured_by, host)| {
        let host = host?.trim();
        (!host.is_empty()).then_some((configured_by, host))
    })?;

    Some(match local_address(host) {
        Some(local) => Endpoint::Local(local),
        None => Endpoint::Remote {
            configured_by,
            scheme: scheme_of(host),
        },
    })
}

/// `unix:///run/docker.sock` or `/run/docker.sock`.
#[cfg(any(unix, test))]
fn local_unix_socket(host: &str) -> Option<PathBuf> {
    let path = host
        .strip_prefix("unix://")
        .or_else(|| host.starts_with('/').then_some(host))?;
    path.starts_with('/').then(|| PathBuf::from(path))
}

/// `npipe:////./pipe/docker_engine` or `\\.\pipe\docker_engine`. The dot is
/// what makes a pipe local: `//server/pipe/name` is a pipe on another machine
/// and would be reached over the network.
#[cfg(any(windows, test))]
fn local_named_pipe(host: &str) -> Option<PathBuf> {
    let path = host
        .strip_prefix("npipe://")
        .unwrap_or(host)
        .replace('\\', "/");
    let name = path.strip_prefix("//./pipe/")?;
    (!name.is_empty() && !name.contains('/')).then(|| PathBuf::from(path))
}

/// The scheme of an engine address and nothing more: the rest of the address
/// can hold a host name or credentials and does not belong in a bundle.
fn scheme_of(host: &str) -> String {
    host.split_once("://")
        .map(|(scheme, _)| scheme)
        .filter(|scheme| {
            !scheme.is_empty() && scheme.len() <= 10 && scheme.chars().all(char::is_alphanumeric)
        })
        .unwrap_or("unknown")
        .to_string()
}

fn remote_engine_refused(configured_by: &str, scheme: &str) -> ScannerReport {
    ScannerReport::unavailable(format!(
        "{configured_by} names an engine that is not local to this host ({scheme}), and \
         hostcensus opens no network connection"
    ))
}

/// The service a container belongs to, as far as its labels say: compose,
/// then swarm, then Kubernetes, then the container name.
fn service_name_from_labels(labels: &HashMap<String, String>, fallback_name: &str) -> String {
    [
        "com.docker.compose.service",
        "com.docker.swarm.service.name",
        "io.kubernetes.container.name",
    ]
    .iter()
    .find_map(|key| labels.get(*key))
    .cloned()
    .unwrap_or_else(|| fallback_name.to_string())
}

fn explicit_service_name(env: &[String]) -> Option<String> {
    env.iter()
        .find_map(|variable| variable.strip_prefix("LOGPACER_SERVICE_NAME="))
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::ScannerStatus;
    #[cfg(unix)]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A stand-in for the engine's API on a Unix socket. Each route is the
    /// end of a request path, a status and a JSON body.
    #[cfg(unix)]
    async fn fake_engine(
        routes: Vec<(&'static str, u16, serde_json::Value)>,
    ) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("docker.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let routes = routes.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => request.extend_from_slice(&chunk[..read]),
                        }
                    }
                    let request = String::from_utf8_lossy(&request);
                    let target = request.split_whitespace().nth(1).unwrap_or_default();
                    let path = target.split('?').next().unwrap_or_default();
                    let (status, body) = routes
                        .iter()
                        .find(|(end, _, _)| path.ends_with(end))
                        .map(|(_, status, body)| (*status, body.to_string()))
                        .unwrap_or((404, r#"{"message":"no such route"}"#.to_string()));
                    let response = format!(
                        "HTTP/1.1 {status} Fake\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        (dir, socket)
    }

    #[test]
    fn service_name_priority() {
        let mut labels = HashMap::new();
        assert_eq!(service_name_from_labels(&labels, "fallback"), "fallback");

        labels.insert("io.kubernetes.container.name".into(), "k8s-name".into());
        assert_eq!(service_name_from_labels(&labels, "fallback"), "k8s-name");

        labels.insert("com.docker.swarm.service.name".into(), "swarm-name".into());
        assert_eq!(service_name_from_labels(&labels, "fallback"), "swarm-name");

        labels.insert("com.docker.compose.service".into(), "compose-name".into());
        assert_eq!(
            service_name_from_labels(&labels, "fallback"),
            "compose-name"
        );
    }

    #[test]
    fn env_var_is_the_only_explicit_opt_in() {
        let env = vec!["LOGPACER_SERVICE_NAME=api".to_string()];
        assert_eq!(explicit_service_name(&env).as_deref(), Some("api"));

        let empty = vec!["LOGPACER_SERVICE_NAME=".to_string()];
        assert_eq!(explicit_service_name(&empty), None);

        let no_env: Vec<String> = vec!["LOGPACER_DEBUG=true".to_string()];
        assert_eq!(explicit_service_name(&no_env), None);
    }

    #[test]
    fn docker_connection_prefers_docker_host_when_set() {
        assert_eq!(
            choose_endpoint(
                Some("unix:///tmp/docker.sock"),
                Some("unix:///tmp/podman.sock"),
                Some(DEFAULT_SOCKET),
                local_unix_socket,
            ),
            Some(Endpoint::Local("/tmp/docker.sock".into()))
        );
    }

    #[test]
    fn docker_connection_uses_container_host_before_the_default_socket() {
        assert_eq!(
            choose_endpoint(
                None,
                Some("unix:///tmp/podman.sock"),
                Some(DEFAULT_SOCKET),
                local_unix_socket,
            ),
            Some(Endpoint::Local("/tmp/podman.sock".into()))
        );
    }

    #[test]
    fn docker_connection_falls_back_to_the_default_socket() {
        assert_eq!(
            choose_endpoint(None, Some("  "), Some(DEFAULT_SOCKET), local_unix_socket),
            Some(Endpoint::Local(DEFAULT_SOCKET.into()))
        );
    }

    #[test]
    fn docker_connection_returns_none_without_configured_endpoint() {
        assert_eq!(choose_endpoint(None, None, None, local_unix_socket), None);
        assert_eq!(choose_endpoint(None, None, None, local_named_pipe), None);
    }

    #[test]
    fn an_engine_on_the_network_is_refused_and_no_local_one_is_used_instead() {
        for (host, scheme) in [
            ("tcp://10.0.0.5:2375", "tcp"),
            ("http://localhost:2375", "http"),
            ("https://docker.example", "https"),
            ("ssh://admin:secret@docker.example", "ssh"),
            ("npipe:////./pipe/docker_engine", "npipe"),
            ("docker.example:2375", "unknown"),
            ("relative/docker.sock", "unknown"),
        ] {
            assert_eq!(
                choose_endpoint(Some(host), None, Some(DEFAULT_SOCKET), local_unix_socket),
                Some(Endpoint::Remote {
                    configured_by: "DOCKER_HOST",
                    scheme: scheme.into()
                }),
                "{host}"
            );
        }
    }

    #[test]
    fn on_windows_the_local_engine_is_a_named_pipe_of_this_machine() {
        for host in [
            "npipe:////./pipe/docker_engine",
            "//./pipe/docker_engine",
            r"\\.\pipe\docker_engine",
        ] {
            assert_eq!(
                choose_endpoint(Some(host), None, None, local_named_pipe),
                Some(Endpoint::Local(DEFAULT_PIPE.into())),
                "{host}"
            );
        }
        assert_eq!(
            choose_endpoint(None, None, Some(DEFAULT_PIPE), local_named_pipe),
            Some(Endpoint::Local(DEFAULT_PIPE.into()))
        );
        assert_eq!(
            choose_endpoint(
                Some("npipe:////./pipe/podman-machine-default"),
                None,
                Some(DEFAULT_PIPE),
                local_named_pipe
            ),
            Some(Endpoint::Local("//./pipe/podman-machine-default".into()))
        );
    }

    #[test]
    fn on_windows_a_pipe_on_another_machine_or_a_network_address_is_refused() {
        for (host, scheme) in [
            ("npipe:////buildhost/pipe/docker_engine", "npipe"),
            (r"\\buildhost\pipe\docker_engine", "unknown"),
            ("npipe:////./pipe/", "npipe"),
            ("npipe:////./pipe/a/b", "npipe"),
            ("tcp://127.0.0.1:2375", "tcp"),
            ("unix:///var/run/docker.sock", "unix"),
        ] {
            assert_eq!(
                choose_endpoint(Some(host), None, Some(DEFAULT_PIPE), local_named_pipe),
                Some(Endpoint::Remote {
                    configured_by: "DOCKER_HOST",
                    scheme: scheme.into()
                }),
                "{host}"
            );
        }
    }

    #[test]
    fn a_refusal_names_the_setting_and_never_the_address() {
        let Some(Endpoint::Remote {
            configured_by,
            scheme,
        }) = choose_endpoint(
            Some("ssh://admin:secret@docker.example"),
            None,
            None,
            local_unix_socket,
        )
        else {
            panic!("a remote engine must be refused");
        };

        let report = remote_engine_refused(configured_by, &scheme);

        assert_eq!(report.status, ScannerStatus::Unavailable);
        let reason = report.reason.unwrap();
        assert!(
            reason.starts_with("DOCKER_HOST names an engine"),
            "{reason}"
        );
        assert!(!reason.contains("secret"), "{reason}");
        assert!(!reason.contains("docker.example"), "{reason}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_socket_nothing_listens_on_makes_the_scan_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("docker.sock");

        let scan = scan_socket(&socket).await;

        assert!(!scan.engine_answered);
        assert_eq!(scan.report.status, ScannerStatus::Unavailable);
        assert!(
            scan.report
                .reason
                .unwrap()
                .starts_with("cannot connect to the Docker socket at")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_listing_counts_even_when_the_engine_keeps_its_data_root_to_itself() {
        let (_dir, socket) = fake_engine(vec![
            ("/info", 500, serde_json::json!({"message": "boom"})),
            ("/containers/json", 200, serde_json::json!([])),
        ])
        .await;

        let scan = scan_socket(&socket).await;

        assert!(scan.engine_answered);
        assert_eq!(scan.data_root, None);
        assert!(scan.owned_paths.is_empty());
        assert_eq!(
            scan.report,
            ScannerReport::partial("the engine did not say where it keeps its data")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_engine_that_cannot_list_containers_makes_the_scan_unavailable() {
        let (_dir, socket) = fake_engine(vec![(
            "/info",
            200,
            serde_json::json!({"DockerRootDir": "/var/lib/docker"}),
        )])
        .await;

        let scan = scan_socket(&socket).await;

        assert!(!scan.engine_answered);
        assert_eq!(scan.report.status, ScannerStatus::Unavailable);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_running_container_is_inspected_for_its_log_path_and_logpacer_variables() {
        let (_dir, socket) = fake_engine(vec![
            (
                "/info",
                200,
                serde_json::json!({"DockerRootDir": "/mnt/docker-data"}),
            ),
            (
                "/containers/json",
                200,
                serde_json::json!([
                    {
                        "Id": "abc123abc123abc123",
                        "Names": ["/shop-web-1"],
                        "Image": "shop/web:4",
                        "State": "running",
                        "Labels": {
                            "com.docker.compose.project": "shop",
                            "com.docker.compose.service": "web"
                        }
                    },
                    {"Id": "def456", "Names": ["/old-job"], "Image": "job", "State": "exited"},
                    {"Id": "999999", "Names": ["/vanished"], "Image": "x", "State": "running"}
                ]),
            ),
            (
                "/containers/abc123abc123abc123/json",
                200,
                serde_json::json!({
                    "Id": "abc123abc123abc123",
                    "LogPath": "/mnt/docker-data/containers/abc/abc-json.log",
                    "Config": {"Env": ["LOGPACER_SERVICE_NAME=storefront", "SECRET=hunter2"]}
                }),
            ),
        ])
        .await;

        let scan = scan_socket(&socket).await;

        assert!(scan.engine_answered);
        assert_eq!(scan.data_root, Some(PathBuf::from("/mnt/docker-data")));
        assert_eq!(scan.containers.len(), 3);

        let web = &scan.containers[0];
        assert_eq!(web.id, "abc123abc123");
        assert_eq!(web.container_id, "abc123abc123abc123");
        assert_eq!(web.name, "shop-web-1");
        assert_eq!(web.runtime, "docker");
        assert_eq!(web.service_name, "storefront");
        assert!(web.service_name_explicit);
        assert_eq!(
            web.env,
            ["LOGPACER_SERVICE_NAME=storefront", "SECRET=hunter2"]
        );
        let entry = web.clone().into_census_entry(false);
        assert_eq!(entry.env["LOGPACER_SERVICE_NAME"], "storefront");
        assert_eq!(entry.env_names_withheld, ["SECRET"]);
        assert_eq!(web.log_path, "/mnt/docker-data/containers/abc/abc-json.log");
        assert_eq!(web.stable_id(), "shop/web");

        let job = &scan.containers[1];
        assert_eq!(job.state, "exited");
        assert_eq!(job.service_name, "old-job");
        assert!(!job.service_name_explicit);
        assert_eq!(job.log_path, "");

        assert_eq!(
            scan.owned_paths,
            [
                PathBuf::from("/mnt/docker-data/containers"),
                PathBuf::from("/mnt/docker-data/containers/abc/abc-json.log"),
            ]
        );
        assert_eq!(
            scan.report,
            ScannerReport::partial(
                "1 running container could not be inspected, so its log path is missing"
            )
        );
    }
}
