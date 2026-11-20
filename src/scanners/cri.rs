//! Containers managed through the Container Runtime Interface, which is how
//! a Kubernetes node runs its pods. They are listed with `crictl`, over the
//! runtime's local socket only.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use super::command::{self, CommandError, Failure};
use super::container::ObservedContainer;
use super::files::POD_LOGS_DIR;
use crate::bundle::ScannerReport;

const CRI_SOCKET_PATHS: &[&str] = &[
    "/run/containerd/containerd.sock",
    "/run/crio/crio.sock",
    "/var/run/cri-dockerd.sock",
];

pub(crate) struct CriScan {
    pub containers: Vec<ObservedContainer>,
    /// Whether the runtime answered. When it did, pod log files are accounted
    /// for by the containers listed here.
    pub runtime_answered: bool,
    pub report: ScannerReport,
}

impl CriScan {
    fn nothing(report: ScannerReport) -> Self {
        Self {
            containers: Vec::new(),
            runtime_answered: false,
            report,
        }
    }
}

pub(crate) async fn scan() -> CriScan {
    let configured = std::env::var("CONTAINER_RUNTIME_ENDPOINT").ok();
    let Some(endpoint) = resolve_local_cri_endpoint(configured.as_deref(), is_local_unix_socket)
    else {
        // No runtime socket on this host.
        return CriScan::nothing(ScannerReport::complete());
    };

    let listing = match crictl(&endpoint, &["ps", "-a", "-o", "json"]).await {
        Ok(listing) => listing,
        Err(CommandError {
            failure: Failure::NotInstalled,
            ..
        }) => return CriScan::nothing(without_crictl(Path::new(POD_LOGS_DIR).is_dir())),
        Err(error) => return CriScan::nothing(ScannerReport::unavailable(error.to_string())),
    };
    let listed: CrictlOutput = match serde_json::from_str(&listing) {
        Ok(listed) => listed,
        Err(_) => {
            return CriScan::nothing(ScannerReport::unavailable(
                "crictl ps returned output that could not be read",
            ));
        }
    };

    let (sandboxes, report) = match pod_sandboxes(&endpoint).await {
        Ok(sandboxes) => (sandboxes, ScannerReport::complete()),
        Err(reason) => (
            HashMap::new(),
            ScannerReport::partial(format!(
                "pods could not be listed, so containers lack their pod and namespace: {reason}"
            )),
        ),
    };

    let runtime = runtime_name(&endpoint);
    let containers = listed
        .containers
        .unwrap_or_default()
        .into_iter()
        .map(|container| observed(container, &sandboxes, runtime))
        .collect();

    CriScan {
        containers,
        runtime_answered: true,
        report,
    }
}

/// A container engine keeps a containerd socket of its own, so a socket
/// without `crictl` only means missed containers on a host that runs pods.
fn without_crictl(host_runs_pods: bool) -> ScannerReport {
    if host_runs_pods {
        ScannerReport::unavailable(format!(
            "crictl is not installed, so the containers of the pods under {POD_LOGS_DIR} are not \
             listed"
        ))
    } else {
        ScannerReport::complete()
    }
}

fn observed(
    container: CrictlContainer,
    sandboxes: &HashMap<String, PodSandbox>,
    runtime: &str,
) -> ObservedContainer {
    let sandbox = container
        .pod_sandbox_id
        .as_deref()
        .and_then(|id| sandboxes.get(id));
    let (namespace, pod_name, pod_uid) = sandbox
        .map(|s| (s.namespace.clone(), s.pod_name.clone(), s.pod_uid.clone()))
        .unwrap_or_default();

    let name = container
        .metadata
        .and_then(|metadata| metadata.name)
        .unwrap_or_default();
    let labels = container.labels.unwrap_or_default();

    let explicit_service_name = labels
        .get("LOGPACER_SERVICE_NAME")
        .filter(|value| !value.is_empty())
        .cloned();
    let service_name_explicit = explicit_service_name.is_some();
    let service_name = explicit_service_name.unwrap_or_else(|| name.clone());

    let id = container.id.unwrap_or_default();
    let log_path = pod_log_directory(&namespace, &pod_name, &pod_uid, &name);

    ObservedContainer {
        id: id.clone(),
        name: name.clone(),
        service_name,
        service_name_explicit,
        image: container.image_ref.unwrap_or_default(),
        state: map_cri_state(&container.state.unwrap_or_default()),
        labels,
        runtime: runtime.to_string(),
        log_path,
        pod_uid,
        pod_name,
        namespace,
        container_id: id,
        container_name: name,
        ..ObservedContainer::default()
    }
}

/// Where the kubelet writes a pod container's log files. Derived from the
/// naming convention; the directory is not looked at.
fn pod_log_directory(namespace: &str, pod_name: &str, pod_uid: &str, container: &str) -> String {
    if namespace.is_empty() || pod_name.is_empty() || pod_uid.is_empty() || container.is_empty() {
        return String::new();
    }
    format!("{POD_LOGS_DIR}/{namespace}_{pod_name}_{pod_uid}/{container}")
}

fn runtime_name(endpoint: &str) -> &'static str {
    if endpoint.contains("crio") {
        "cri-o"
    } else {
        "containerd"
    }
}

/// The local socket to talk to. A configured endpoint is used only when it
/// names an existing Unix socket; a remote or missing one never falls back to
/// a default, and is never contacted.
fn resolve_local_cri_endpoint(
    configured: Option<&str>,
    is_socket: impl Fn(&Path) -> bool,
) -> Option<String> {
    if let Some(endpoint) = configured {
        let endpoint = endpoint.trim();
        let path = endpoint
            .strip_prefix("unix://")
            .or_else(|| endpoint.starts_with('/').then_some(endpoint))?;
        let path = Path::new(path);
        return (path.is_absolute() && is_socket(path))
            .then(|| format!("unix://{}", path.display()));
    }

    CRI_SOCKET_PATHS
        .iter()
        .map(Path::new)
        .find(|path| is_socket(path))
        .map(|path| format!("unix://{}", path.display()))
}

fn is_local_unix_socket(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;

    std::fs::metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket())
}

async fn crictl(endpoint: &str, args: &[&str]) -> Result<String, CommandError> {
    let mut full = vec!["--runtime-endpoint", endpoint];
    full.extend_from_slice(args);
    command::stdout_of("crictl", &full).await
}

async fn pod_sandboxes(endpoint: &str) -> Result<HashMap<String, PodSandbox>, String> {
    let listing = crictl(endpoint, &["pods", "-o", "json"])
        .await
        .map_err(|error| error.to_string())?;
    let listed: CrictlPodsOutput = serde_json::from_str(&listing)
        .map_err(|_| "crictl pods returned output that could not be read".to_string())?;

    Ok(listed
        .items
        .unwrap_or_default()
        .into_iter()
        .map(|sandbox| {
            let metadata = sandbox.metadata.unwrap_or_default();
            (
                sandbox.id.unwrap_or_default(),
                PodSandbox {
                    namespace: metadata.namespace.unwrap_or_default(),
                    pod_name: metadata.name.unwrap_or_default(),
                    pod_uid: metadata.uid.unwrap_or_default(),
                },
            )
        })
        .collect())
}

fn map_cri_state(state: &str) -> String {
    match state.to_uppercase().as_str() {
        "CONTAINER_RUNNING" | "RUNNING" => "running".into(),
        "CONTAINER_EXITED" | "EXITED" => "exited".into(),
        "CONTAINER_CREATED" | "CREATED" => "created".into(),
        "CONTAINER_UNKNOWN" | "UNKNOWN" => "unknown".into(),
        _ => state.to_lowercase(),
    }
}

#[derive(Debug, Deserialize)]
struct CrictlOutput {
    containers: Option<Vec<CrictlContainer>>,
}

#[derive(Debug, Deserialize)]
struct CrictlContainer {
    id: Option<String>,
    #[serde(rename = "podSandboxId")]
    pod_sandbox_id: Option<String>,
    metadata: Option<CrictlContainerMetadata>,
    #[serde(rename = "imageRef")]
    image_ref: Option<String>,
    state: Option<String>,
    labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct CrictlContainerMetadata {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CrictlPodsOutput {
    items: Option<Vec<CrictlPodSandbox>>,
}

#[derive(Debug, Deserialize)]
struct CrictlPodSandbox {
    id: Option<String>,
    metadata: Option<CrictlPodMetadata>,
}

#[derive(Debug, Deserialize, Default)]
struct CrictlPodMetadata {
    namespace: Option<String>,
    name: Option<String>,
    uid: Option<String>,
}

struct PodSandbox {
    namespace: String,
    pod_name: String,
    pod_uid: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::ScannerStatus;

    #[test]
    fn configured_local_endpoint_is_pinned_and_remote_configuration_never_falls_back() {
        let is_socket = |path: &Path| {
            path == Path::new("/custom/runtime.sock") || path == Path::new(CRI_SOCKET_PATHS[0])
        };

        assert_eq!(
            resolve_local_cri_endpoint(Some("unix:///custom/runtime.sock"), is_socket).as_deref(),
            Some("unix:///custom/runtime.sock")
        );
        for endpoint in [
            "tcp://runtime.example:1234",
            "npipe:////./pipe/containerd",
            "relative/runtime.sock",
            "unix:///missing/runtime.sock",
        ] {
            assert_eq!(
                resolve_local_cri_endpoint(Some(endpoint), is_socket),
                None,
                "configured endpoint {endpoint:?} must not fall back"
            );
        }
    }

    #[test]
    fn default_endpoint_selection_is_deterministic() {
        let selected = Path::new(CRI_SOCKET_PATHS[1]);
        assert_eq!(
            resolve_local_cri_endpoint(None, |path| path == selected).as_deref(),
            Some("unix:///run/crio/crio.sock")
        );
    }

    #[test]
    fn endpoint_requires_an_actual_unix_socket() {
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("runtime.sock");
        let file_path = dir.path().join("regular-file");
        let _listener = UnixListener::bind(&socket_path).unwrap();
        std::fs::write(&file_path, b"not a socket").unwrap();

        assert!(is_local_unix_socket(&socket_path));
        assert!(!is_local_unix_socket(&file_path));
        assert!(!is_local_unix_socket(&dir.path().join("missing")));
    }

    #[test]
    fn test_map_cri_state() {
        assert_eq!(map_cri_state("CONTAINER_RUNNING"), "running");
        assert_eq!(map_cri_state("RUNNING"), "running");
        assert_eq!(map_cri_state("CONTAINER_EXITED"), "exited");
        assert_eq!(map_cri_state("EXITED"), "exited");
        assert_eq!(map_cri_state("CONTAINER_CREATED"), "created");
        assert_eq!(map_cri_state("CREATED"), "created");
        assert_eq!(map_cri_state("CONTAINER_UNKNOWN"), "unknown");
        assert_eq!(map_cri_state("UNKNOWN"), "unknown");
        assert_eq!(map_cri_state("SomethingElse"), "somethingelse");
    }

    fn listed_container() -> CrictlContainer {
        let json = r#"{
            "containers": [
                {
                    "id": "abc123def456",
                    "podSandboxId": "pod-sandbox-1",
                    "metadata": {"name": "nginx"},
                    "imageRef": "docker.io/library/nginx:latest",
                    "state": "CONTAINER_RUNNING",
                    "labels": {"app": "web", "io.kubernetes.pod.name": "nginx-pod"}
                }
            ]
        }"#;
        let output: CrictlOutput = serde_json::from_str(json).unwrap();
        output.containers.unwrap().remove(0)
    }

    fn sandboxes() -> HashMap<String, PodSandbox> {
        HashMap::from([(
            "pod-sandbox-1".to_string(),
            PodSandbox {
                namespace: "default".into(),
                pod_name: "nginx-pod".into(),
                pod_uid: "uid-123".into(),
            },
        )])
    }

    #[test]
    fn test_parse_crictl_output() {
        let c = listed_container();
        assert_eq!(c.id.as_deref(), Some("abc123def456"));
        assert_eq!(c.pod_sandbox_id.as_deref(), Some("pod-sandbox-1"));
        assert_eq!(
            c.metadata.as_ref().and_then(|m| m.name.as_deref()),
            Some("nginx")
        );
        assert_eq!(
            c.image_ref.as_deref(),
            Some("docker.io/library/nginx:latest")
        );
        assert_eq!(c.state.as_deref(), Some("CONTAINER_RUNNING"));
        assert_eq!(
            c.labels
                .as_ref()
                .and_then(|l| l.get("app"))
                .map(|s| s.as_str()),
            Some("web")
        );
    }

    #[test]
    fn test_parse_crictl_pods_output() {
        let json = r#"{
            "items": [
                {
                    "id": "pod-sandbox-1",
                    "metadata": {
                        "name": "nginx-pod",
                        "namespace": "default",
                        "uid": "uid-123"
                    }
                }
            ]
        }"#;

        let output: CrictlPodsOutput = serde_json::from_str(json).unwrap();
        let items = output.items.unwrap();
        assert_eq!(items.len(), 1);

        let pod = &items[0];
        assert_eq!(pod.id.as_deref(), Some("pod-sandbox-1"));
        let metadata = pod.metadata.as_ref().unwrap();
        assert_eq!(metadata.name.as_deref(), Some("nginx-pod"));
        assert_eq!(metadata.namespace.as_deref(), Some("default"));
        assert_eq!(metadata.uid.as_deref(), Some("uid-123"));
    }

    #[test]
    fn a_pod_container_carries_its_pod_and_its_log_directory() {
        let container = observed(listed_container(), &sandboxes(), "containerd");

        assert_eq!(container.name, "nginx");
        assert_eq!(container.container_name, "nginx");
        assert_eq!(container.state, "running");
        assert_eq!(container.runtime, "containerd");
        assert_eq!(container.namespace, "default");
        assert_eq!(container.pod_name, "nginx-pod");
        assert_eq!(container.pod_uid, "uid-123");
        assert_eq!(
            container.log_path,
            "/var/log/pods/default_nginx-pod_uid-123/nginx"
        );
        assert_eq!(container.service_name, "nginx");
        assert!(!container.service_name_explicit);
    }

    #[test]
    fn a_container_without_a_known_pod_has_no_log_directory() {
        let container = observed(listed_container(), &HashMap::new(), "containerd");

        assert_eq!(container.log_path, "");
        assert_eq!(container.namespace, "");
    }

    #[test]
    fn the_runtime_is_named_after_its_socket() {
        assert_eq!(runtime_name("unix:///run/crio/crio.sock"), "cri-o");
        assert_eq!(
            runtime_name("unix:///run/containerd/containerd.sock"),
            "containerd"
        );
    }

    #[test]
    fn a_missing_crictl_only_matters_where_pods_run() {
        assert_eq!(without_crictl(false), ScannerReport::complete());
        let report = without_crictl(true);
        assert_eq!(report.status, ScannerStatus::Unavailable);
        assert!(report.reason.unwrap().contains("crictl is not installed"));
    }
}
