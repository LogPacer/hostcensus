//! A container as a scanner observes it, and the identity derived from it.
//!
//! The LogPacer collector follows the same identity rules on purpose, so a
//! container has the same identifiers in a census and in LogPacer. The tests
//! pin the rules. A change to them is made in both code bases, by hand.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::SystemTime;

use crate::inventory::Container;

/// Label values kept in a census by default. Any other label is listed by key
/// only, because label values can carry secrets.
const KEPT_LABEL_PREFIXES: &[&str] = &[
    "com.docker.compose.",
    "io.kubernetes.",
    "org.opencontainers.image.",
];
const KEPT_LABEL_KEYS: &[&str] = &["logpacer.com/service-name", "log.format"];

/// Variables whose value says what runs and how it logs, and is not a secret
/// by nature: the deployment environment, log settings, telemetry settings,
/// the service name and the time zone.
const KEPT_ENV_NAMES: &[&str] = &[
    "APP_ENV",
    "ASPNETCORE_ENVIRONMENT",
    "DOTNET_ENVIRONMENT",
    "ENVIRONMENT",
    "LOGLEVEL",
    "LOGPACER_SERVICE_NAME",
    "LOG_FORMAT",
    "LOG_LEVEL",
    "NODE_ENV",
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_LOGS_EXPORTER",
    "OTEL_METRICS_EXPORTER",
    "OTEL_SERVICE_NAME",
    "OTEL_TRACES_EXPORTER",
    "RACK_ENV",
    "RAILS_ENV",
    "SPRING_PROFILES_ACTIVE",
    "TZ",
];
/// Images state the version of what they run in variables named like this
/// (`PG_VERSION`, `NODE_VERSION`, `PG_MAJOR`).
const KEPT_ENV_SUFFIXES: &[&str] = &["_VERSION", "_MAJOR"];

#[derive(Debug, Clone, Default)]
pub(crate) struct ObservedContainer {
    pub id: String,
    pub name: String,
    pub service_name: String,
    pub service_name_explicit: bool,
    pub image: String,
    pub state: String,
    pub labels: HashMap<String, String>,
    /// The environment as the engine reports it, `NAME=value`. It stays in
    /// memory; `into_census_entry` decides what of it reaches the bundle.
    pub env: Vec<String>,
    pub runtime: String,
    pub log_path: String,
    pub log_driver: String,
    pub log_size: Option<u64>,
    pub log_modified: String,
    pub pod_uid: String,
    pub pod_name: String,
    pub namespace: String,
    pub node_name: String,
    pub deployment: String,
    pub workload_kind: String,
    pub container_id: String,
    pub container_name: String,
}

impl ObservedContainer {
    /// The census entry for this container. Identity is derived from every
    /// label first; only then are label values withheld.
    pub(crate) fn into_census_entry(self, keep_all_label_values: bool) -> Container {
        let stable_identifier = self.stable_id();
        let stable_instance_id = self.stable_instance_id();
        let identifiers = self
            .identifier_set()
            .into_iter()
            .map(|(kind, value)| (kind.to_string(), value))
            .collect();

        let mut labels = BTreeMap::new();
        let mut label_keys_withheld = Vec::new();
        for (key, value) in self.labels {
            if keep_all_label_values || keeps_label_value(&key) {
                labels.insert(key, value);
            } else {
                label_keys_withheld.push(key);
            }
        }
        label_keys_withheld.sort();

        let mut env = BTreeMap::new();
        let mut env_names_withheld = Vec::new();
        for variable in &self.env {
            let (name, value) = variable.split_once('=').unwrap_or((variable, ""));
            if name.is_empty() {
                continue;
            }
            // A later entry overrides an earlier one of the same name.
            env.remove(name);
            env_names_withheld.retain(|withheld| withheld != name);
            if keeps_env_value(name, value) {
                env.insert(name.to_string(), value.to_string());
            } else {
                env_names_withheld.push(name.to_string());
            }
        }
        env_names_withheld.sort();

        Container {
            id: self.id,
            name: self.name,
            image: self.image,
            state: self.state,
            runtime: self.runtime,
            service_name: self.service_name,
            service_name_explicit: self.service_name_explicit,
            stable_identifier,
            stable_instance_id,
            identifiers,
            labels,
            label_keys_withheld,
            env,
            env_names_withheld,
            log_path: self.log_path,
            log_driver: self.log_driver,
            log_size: self.log_size,
            log_modified: self.log_modified,
            container_id: self.container_id,
            container_name: self.container_name,
            namespace: self.namespace,
            pod_name: self.pod_name,
            pod_uid: self.pod_uid,
            deployment: self.deployment,
            workload_kind: self.workload_kind,
        }
    }

    /// Identity of the workload this container belongs to. It must survive
    /// restarts and rescheduling:
    /// - K8s: namespace/deployment/container_name (survives pod restarts)
    /// - Compose: project/service
    /// - Swarm: stack/service
    /// - Kamal: service-destination (role-agnostic; web + rpc share one workload)
    /// - Standalone Docker: container name
    pub(crate) fn stable_id(&self) -> String {
        // Kubernetes: namespace/deployment/container_name (spec name, not pod-prefixed)
        if !self.namespace.is_empty() && !self.deployment.is_empty() {
            let cn = if !self.container_name.is_empty() {
                self.container_name.as_str()
            } else {
                self.name.as_str()
            };
            return format!("{}/{}/{}", self.namespace, self.deployment, cn);
        }

        // Docker Compose: project/service
        if let (Some(project), Some(service)) = (
            self.labels.get("com.docker.compose.project"),
            self.labels.get("com.docker.compose.service"),
        ) {
            return format!("{}/{}", project, service);
        }
        if let Some(service) = self.labels.get("com.docker.compose.service") {
            return service.clone();
        }

        // Docker Swarm: stack/service
        if let (Some(stack), Some(service)) = (
            self.labels.get("com.docker.stack.namespace"),
            self.labels.get("com.docker.swarm.service.name"),
        ) {
            return format!("{}/{}", stack, service);
        }
        if let Some(service) = self.labels.get("com.docker.swarm.service.name") {
            return service.clone();
        }

        // Kamal: service-destination. Kamal always sets `service` + `destination`,
        // and the identity is role-agnostic so web + rpc collapse to one workload.
        // The container name embeds the deploy git SHA, so it can't be the id.
        if let (Some(service), Some(destination)) =
            (self.labels.get("service"), self.labels.get("destination"))
        {
            return format!("{}-{}", service, destination);
        }

        // Standalone Docker / other: container name
        self.name.clone()
    }

    /// Stable identity at instance/replica granularity. Where `stable_id` names
    /// the *workload*, this names the *instance* — and it must survive a
    /// redeploy, so a new container id or pod uid is never part of it.
    ///
    /// The K8s forms extend the workload `stable_id` (which already carries the
    /// container/spec name) with a replica discriminator, so sidecar containers
    /// sharing a pod never collide on one id:
    /// - K8s StatefulSet: `stable_id/<ordinal>` (ordinal from the stable pod name `<workload>-<N>`)
    /// - K8s DaemonSet: `stable_id/<node_name>` (one pod pinned per node)
    /// - K8s Deployment/Job/CronJob/other: pods are fungible — no stable per-pod
    ///   identity, so this is just the workload `stable_id`
    /// - Docker Compose: `project/service/<ordinal>` (compose container-number,
    ///   else parsed from the container name `project-service-N`)
    /// - Docker Swarm: `stack/service/<slot>` (slot from the swarm task name
    ///   `service.slot.taskid`)
    /// - Kamal: `service-role-destination` — stable across deploys (the container
    ///   name embeds the git SHA); falls back to `service-destination` without a role
    /// - Standalone Docker / other: the container name (a single instance)
    pub(crate) fn stable_instance_id(&self) -> String {
        // Kubernetes. The per-instance id extends stable_id (namespace/workload/
        // container_name) with the replica discriminator, so two containers in
        // the same pod (e.g. a sidecar) never share one stable_instance_id.
        if !self.namespace.is_empty() && !self.deployment.is_empty() {
            return match self.workload_kind.as_str() {
                "statefulset" => match pod_ordinal(&self.pod_name, &self.deployment) {
                    Some(ordinal) => format!("{}/{}", self.stable_id(), ordinal),
                    None => self.stable_id(),
                },
                "daemonset" if !self.node_name.is_empty() => {
                    format!("{}/{}", self.stable_id(), self.node_name)
                }
                // Deployment, Job, CronJob, bare pods, daemonset-without-node:
                // the pod is fungible, so the workload identity is all that's stable.
                _ => self.stable_id(),
            };
        }

        // Docker Compose: project/service/<ordinal>
        if let (Some(project), Some(service)) = (
            self.labels.get("com.docker.compose.project"),
            self.labels.get("com.docker.compose.service"),
        ) {
            if let Some(ordinal) = self
                .labels
                .get("com.docker.compose.container-number")
                .filter(|n| is_numeric(n))
                .cloned()
                .or_else(|| compose_ordinal(&self.name, project, service))
            {
                return format!("{}/{}/{}", project, service, ordinal);
            }
            return format!("{}/{}", project, service);
        }

        // Docker Swarm: stack/service/<slot>
        if let Some(service) = self.labels.get("com.docker.swarm.service.name") {
            let stack = self.labels.get("com.docker.stack.namespace");
            if let Some(slot) = self
                .labels
                .get("com.docker.swarm.task.name")
                .and_then(|task| swarm_slot(task))
            {
                return match stack {
                    Some(stack) => format!("{}/{}/{}", stack, service, slot),
                    None => format!("{}/{}", service, slot),
                };
            }
            return match stack {
                Some(stack) => format!("{}/{}", stack, service),
                None => service.clone(),
            };
        }

        // Kamal: service-role-destination — a per-role instance that survives a
        // redeploy, since the container name embeds the deploy git SHA. `service`
        // + `destination` are always set; `role` separates web from rpc, and when
        // it's absent the instance collapses to the `service-destination` workload.
        if let (Some(service), Some(destination)) =
            (self.labels.get("service"), self.labels.get("destination"))
        {
            return match self.labels.get("role") {
                Some(role) => format!("{}-{}-{}", service, role, destination),
                None => format!("{}-{}", service, destination),
            };
        }

        // Standalone Docker / other: the container name is the single instance.
        self.name.clone()
    }

    /// The normalized identifier atoms for this container — every stable,
    /// low-entropy fact the census observed, as `kind: value` pairs. Volatile
    /// handles (container_id, pod_uid, image tag) are never atoms: they
    /// identify an instance, not a service. `container.name` is the one
    /// high-entropy member (Kamal names embed the deploy SHA).
    pub(crate) fn identifier_set(&self) -> BTreeMap<&'static str, String> {
        let mut atoms = BTreeMap::new();

        // The explicit LOGPACER opt-in is the highest-confidence atom and the
        // only one carrying consent. Derived (non-explicit) service names are
        // label echoes and already appear as their own atoms below.
        if self.explicit_service() {
            atoms.insert("service_name", self.service_name.clone());
        }

        // Kamal sets `service` + `destination` together; gate on the pair so a
        // stray unprefixed `service` label on a non-Kamal container is not
        // misread as Kamal identity.
        if let (Some(service), Some(destination)) =
            (self.labels.get("service"), self.labels.get("destination"))
        {
            atoms.insert("kamal.service", service.clone());
            atoms.insert("kamal.destination", destination.clone());
            if let Some(role) = self.labels.get("role") {
                atoms.insert("kamal.role", role.clone());
            }
        }

        if let Some(project) = self.labels.get("com.docker.compose.project") {
            atoms.insert("compose.project", project.clone());
        }
        if let Some(service) = self.labels.get("com.docker.compose.service") {
            atoms.insert("compose.service", service.clone());
        }

        if let Some(stack) = self.labels.get("com.docker.stack.namespace") {
            atoms.insert("swarm.stack", stack.clone());
        }
        if let Some(service) = self.labels.get("com.docker.swarm.service.name") {
            atoms.insert("swarm.service", service.clone());
        }

        if !self.namespace.is_empty() {
            atoms.insert("k8s.namespace", self.namespace.clone());
        }
        if !self.deployment.is_empty() {
            atoms.insert("k8s.workload", self.deployment.clone());
        }
        if !self.container_name.is_empty() {
            atoms.insert("k8s.container", self.container_name.clone());
        }

        if let Some(repo) = image_repo(&self.image) {
            atoms.insert("image.repo", repo);
        }

        if !self.name.is_empty() {
            atoms.insert("container.name", self.name.clone());
        }

        atoms
    }

    pub(crate) fn has_service_name(&self) -> bool {
        !self.service_name.is_empty()
    }

    /// Whether the service name was set on purpose, not derived.
    pub(crate) fn explicit_service(&self) -> bool {
        self.service_name_explicit && self.has_service_name()
    }
}

/// A variable's value is kept only when its name says the value is one of
/// the plain facts above and the value itself is a short plain token. A name
/// alone is not enough: `APP_VERSION` can hold anything.
fn keeps_env_value(name: &str, value: &str) -> bool {
    let named_for_a_plain_fact = KEPT_ENV_NAMES.contains(&name)
        || KEPT_ENV_SUFFIXES
            .iter()
            .any(|suffix| name.len() > suffix.len() && name.ends_with(suffix));
    named_for_a_plain_fact && is_plain_token(value)
}

/// Letters, digits and `. _ + ~ , / -`, at most 64 of them: no address, no
/// credentials, no free text.
fn is_plain_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+~,/-".contains(&byte))
}

impl ObservedContainer {
    /// Looks at the log of the container from the outside: how large it is
    /// and when it was last written to. `log_path` is the log file itself,
    /// or the directory a CRI runtime keeps the log files of a container in,
    /// of which the newest counts. The log is never opened.
    pub(crate) fn with_log_seen_from_outside(mut self) -> Self {
        if let Some((size, modified)) = log_size_and_time(Path::new(&self.log_path)) {
            self.log_size = Some(size);
            self.log_modified = super::rfc3339(modified);
        }
        self
    }
}

fn log_size_and_time(log_path: &Path) -> Option<(u64, SystemTime)> {
    if log_path.as_os_str().is_empty() {
        return None;
    }
    let metadata = std::fs::metadata(log_path).ok()?;
    if metadata.is_file() {
        return Some((metadata.len(), metadata.modified().ok()?));
    }
    std::fs::read_dir(log_path)
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let metadata = entry.metadata().ok()?;
            metadata
                .is_file()
                .then_some((metadata.len(), metadata.modified().ok()?))
        })
        .max_by_key(|(_, modified)| *modified)
}

fn keeps_label_value(key: &str) -> bool {
    KEPT_LABEL_KEYS.contains(&key)
        || KEPT_LABEL_PREFIXES
            .iter()
            .any(|prefix| key.starts_with(prefix))
}

/// Image reference with the volatile parts stripped: the repo is a
/// service-level fact, the tag/digest move on every deploy. A `:` only counts
/// as a tag separator after the last `/`, so registry ports survive
/// (`registry:5000/app:v1` → `registry:5000/app`).
fn image_repo(image: &str) -> Option<String> {
    let without_digest = image.split('@').next().unwrap_or(image);
    let repo = match without_digest.rfind(':') {
        Some(idx) if idx > without_digest.rfind('/').unwrap_or(0) => &without_digest[..idx],
        _ => without_digest,
    };
    (!repo.is_empty()).then(|| repo.to_string())
}

/// Non-empty and all ASCII digits — a usable replica ordinal/slot.
fn is_numeric(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Ordinal of a StatefulSet pod: `pod_ordinal("postgres-0", "postgres") == Some("0")`.
/// StatefulSet pod names are `<workload>-<ordinal>` and survive restarts.
fn pod_ordinal(pod_name: &str, workload: &str) -> Option<String> {
    let ordinal = pod_name.strip_prefix(workload)?.strip_prefix('-')?;
    is_numeric(ordinal).then(|| ordinal.to_string())
}

/// Ordinal of a Compose replica from its container name. Compose v2 uses
/// hyphens (`shop-web-2`), v1 used underscores (`shop_web_2`); try both.
fn compose_ordinal(name: &str, project: &str, service: &str) -> Option<String> {
    let ordinal = name
        .strip_prefix(&format!("{project}-{service}-"))
        .or_else(|| name.strip_prefix(&format!("{project}_{service}_")))?;
    is_numeric(ordinal).then(|| ordinal.to_string())
}

/// Slot of a Swarm task from `com.docker.swarm.task.name` = `service.slot.taskid`:
/// `swarm_slot("web.2.abc123") == Some("2")`.
fn swarm_slot(task_name: &str) -> Option<String> {
    let slot = task_name.split('.').nth(1)?;
    is_numeric(slot).then(|| slot.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_container(name: &str) -> ObservedContainer {
        ObservedContainer {
            id: "abc123".into(),
            name: name.into(),
            image: "nginx:latest".into(),
            state: "running".into(),
            runtime: "docker".into(),
            container_id: "abc123".into(),
            ..ObservedContainer::default()
        }
    }

    #[test]
    fn stable_id_standalone_docker() {
        let c = make_container("my-nginx");
        assert_eq!(c.stable_id(), "my-nginx");
    }

    #[test]
    fn explicit_service_requires_the_env_var_flag() {
        // Plain docker: service_name fallback = container name, NOT explicit
        let mut c = make_container("web");
        c.service_name = "web".into();
        assert!(c.has_service_name());
        assert!(
            !c.explicit_service(),
            "inferred service names are not consent — only LOGPACER_SERVICE_NAME is"
        );

        c.service_name_explicit = true;
        assert!(c.explicit_service());

        // Flag without a name is meaningless
        c.service_name = String::new();
        assert!(!c.explicit_service());
    }

    #[test]
    fn stable_id_compose() {
        let mut c = make_container("myapp-web-1");
        c.labels
            .insert("com.docker.compose.project".into(), "myapp".into());
        c.labels
            .insert("com.docker.compose.service".into(), "web".into());
        assert_eq!(c.stable_id(), "myapp/web");
    }

    #[test]
    fn stable_id_swarm() {
        let mut c = make_container("web.1.abc");
        c.labels
            .insert("com.docker.stack.namespace".into(), "production".into());
        c.labels
            .insert("com.docker.swarm.service.name".into(), "web".into());
        assert_eq!(c.stable_id(), "production/web");
    }

    #[test]
    fn stable_id_kubernetes() {
        let mut c = make_container("nginx");
        c.namespace = "default".into();
        c.deployment = "nginx".into();
        assert_eq!(c.stable_id(), "default/nginx/nginx");
    }

    #[test]
    fn stable_id_k8s_takes_priority_over_compose_labels() {
        let mut c = make_container("nginx");
        c.namespace = "prod".into();
        c.deployment = "api".into();
        c.labels
            .insert("com.docker.compose.service".into(), "web".into());
        // K8s should win
        assert_eq!(c.stable_id(), "prod/api/nginx");
    }

    #[test]
    fn stable_instance_id_standalone_docker_is_the_name() {
        let c = make_container("my-nginx");
        assert_eq!(c.stable_instance_id(), "my-nginx");
    }

    #[test]
    fn stable_instance_id_compose_appends_container_number_label() {
        let mut c = make_container("shop-web-2");
        c.labels
            .insert("com.docker.compose.project".into(), "shop".into());
        c.labels
            .insert("com.docker.compose.service".into(), "web".into());
        c.labels
            .insert("com.docker.compose.container-number".into(), "2".into());
        assert_eq!(c.stable_instance_id(), "shop/web/2");
        // Workload-level identity is unchanged — replicas share it.
        assert_eq!(c.stable_id(), "shop/web");
    }

    #[test]
    fn stable_instance_id_compose_parses_ordinal_from_name_without_label() {
        let mut c = make_container("shop-web-3");
        c.labels
            .insert("com.docker.compose.project".into(), "shop".into());
        c.labels
            .insert("com.docker.compose.service".into(), "web".into());
        assert_eq!(c.stable_instance_id(), "shop/web/3");
    }

    #[test]
    fn stable_instance_id_compose_without_ordinal_falls_back_to_workload() {
        let mut c = make_container("weird-name");
        c.labels
            .insert("com.docker.compose.project".into(), "shop".into());
        c.labels
            .insert("com.docker.compose.service".into(), "web".into());
        assert_eq!(c.stable_instance_id(), "shop/web");
    }

    #[test]
    fn stable_instance_id_swarm_uses_task_slot() {
        let mut c = make_container("web.2.abc123xyz");
        c.labels
            .insert("com.docker.stack.namespace".into(), "production".into());
        c.labels
            .insert("com.docker.swarm.service.name".into(), "web".into());
        c.labels.insert(
            "com.docker.swarm.task.name".into(),
            "web.2.abc123xyz".into(),
        );
        assert_eq!(c.stable_instance_id(), "production/web/2");
    }

    #[test]
    fn stable_instance_id_statefulset_uses_pod_ordinal_per_container() {
        let mut db = make_container("postgres-0-db");
        db.runtime = "kubernetes".into();
        db.namespace = "default".into();
        db.deployment = "postgres".into();
        db.workload_kind = "statefulset".into();
        db.container_name = "db".into();
        db.pod_name = "postgres-0".into();
        assert_eq!(db.stable_instance_id(), "default/postgres/db/0");

        // A sidecar in the SAME pod (same ordinal) must get a DISTINCT id, or
        // both would collide on one key on the wire and in the cache.
        let mut metrics = db.clone();
        metrics.container_name = "metrics".into();
        metrics.name = "postgres-0-metrics".into();
        assert_eq!(metrics.stable_instance_id(), "default/postgres/metrics/0");
        assert_ne!(db.stable_instance_id(), metrics.stable_instance_id());
    }

    #[test]
    fn stable_instance_id_daemonset_uses_node_name() {
        let mut c = make_container("fluentbit-abc");
        c.runtime = "kubernetes".into();
        c.namespace = "logging".into();
        c.deployment = "fluentbit".into();
        c.workload_kind = "daemonset".into();
        c.container_name = "agent".into();
        c.pod_name = "fluentbit-abc".into();
        c.node_name = "node-7".into();
        assert_eq!(c.stable_instance_id(), "logging/fluentbit/agent/node-7");
    }

    #[test]
    fn stable_instance_id_deployment_is_fungible_workload_identity() {
        // Deployment pods are fungible — no stable per-pod identity, so the
        // instance id collapses to the workload stable_id.
        let mut c = make_container("api-7b4f9c8d5-xyz");
        c.runtime = "kubernetes".into();
        c.namespace = "prod".into();
        c.deployment = "api".into();
        c.workload_kind = "deployment".into();
        c.container_name = "api".into();
        c.pod_name = "api-7b4f9c8d5-xyz".into();
        assert_eq!(c.stable_instance_id(), "prod/api/api");
        assert_eq!(c.stable_instance_id(), c.stable_id());
    }

    fn make_kamal_container(role: &str, name: &str) -> ObservedContainer {
        let mut c = make_container(name);
        c.labels.insert("service".into(), "logpacer".into());
        c.labels.insert("role".into(), role.into());
        c.labels.insert("destination".into(), "prod".into());
        c
    }

    #[test]
    fn stable_id_kamal_is_service_destination() {
        let c = make_kamal_container("web", "logpacer-web-prod-1a2b3c4");
        assert_eq!(c.stable_id(), "logpacer-prod");
    }

    #[test]
    fn stable_instance_id_kamal_is_service_role_destination() {
        let c = make_kamal_container("web", "logpacer-web-prod-1a2b3c4");
        assert_eq!(c.stable_instance_id(), "logpacer-web-prod");
    }

    #[test]
    fn stable_kamal_ids_survive_a_redeploy_to_a_new_sha() {
        // Same labels, new container name (the git SHA moved) — ids must not move.
        let before = make_kamal_container("web", "logpacer-web-prod-1a2b3c4");
        let after = make_kamal_container("web", "logpacer-web-prod-9f8e7d6");
        assert_eq!(before.stable_id(), after.stable_id());
        assert_eq!(before.stable_instance_id(), after.stable_instance_id());
    }

    #[test]
    fn stable_instance_id_kamal_rpc_role() {
        let c = make_kamal_container("rpc", "logpacer-rpc-prod-1a2b3c4");
        assert_eq!(c.stable_instance_id(), "logpacer-rpc-prod");
    }

    #[test]
    fn kamal_web_and_rpc_share_workload_but_differ_per_role() {
        let web = make_kamal_container("web", "logpacer-web-prod-1a2b3c4");
        let rpc = make_kamal_container("rpc", "logpacer-rpc-prod-1a2b3c4");
        // Same workload — web + rpc collapse to one stable_id.
        assert_eq!(web.stable_id(), rpc.stable_id());
        // Distinct per-role instances.
        assert_ne!(web.stable_instance_id(), rpc.stable_instance_id());
    }

    #[test]
    fn stable_instance_id_kamal_without_role_falls_back_to_workload() {
        let mut c = make_kamal_container("web", "logpacer-prod-1a2b3c4");
        c.labels.remove("role");
        assert_eq!(c.stable_instance_id(), "logpacer-prod");
        assert_eq!(c.stable_instance_id(), c.stable_id());
    }

    #[test]
    fn identifier_set_kamal_atoms() {
        let c = make_kamal_container("web", "logpacer-web-prod-1a2b3c4");
        let atoms = c.identifier_set();
        assert_eq!(atoms.get("kamal.service").unwrap(), "logpacer");
        assert_eq!(atoms.get("kamal.role").unwrap(), "web");
        assert_eq!(atoms.get("kamal.destination").unwrap(), "prod");
        assert_eq!(atoms.get("image.repo").unwrap(), "nginx");
        assert_eq!(
            atoms.get("container.name").unwrap(),
            "logpacer-web-prod-1a2b3c4"
        );
        // No explicit opt-in — the derived service name is a label echo and
        // must not masquerade as the consent-carrying atom.
        assert!(!atoms.contains_key("service_name"));
    }

    #[test]
    fn identifier_set_survives_redeploy_except_container_name() {
        let before = make_kamal_container("web", "logpacer-web-prod-1a2b3c4");
        let after = make_kamal_container("web", "logpacer-web-prod-9f8e7d6");
        let (mut b, mut a) = (before.identifier_set(), after.identifier_set());
        assert_ne!(b.remove("container.name"), a.remove("container.name"));
        assert_eq!(b, a);
    }

    #[test]
    fn identifier_set_k8s_atoms() {
        let mut c = make_container("api-7b4f9c8d5-xyz");
        c.runtime = "kubernetes".into();
        c.namespace = "prod".into();
        c.deployment = "api".into();
        c.workload_kind = "deployment".into();
        c.container_name = "api".into();
        c.image = "ghcr.io/logpacer/api:v1.4.3".into();
        let atoms = c.identifier_set();
        assert_eq!(atoms.get("k8s.namespace").unwrap(), "prod");
        assert_eq!(atoms.get("k8s.workload").unwrap(), "api");
        assert_eq!(atoms.get("k8s.container").unwrap(), "api");
        assert_eq!(atoms.get("image.repo").unwrap(), "ghcr.io/logpacer/api");
    }

    #[test]
    fn identifier_set_compose_atoms() {
        let mut c = make_container("shop-web-1");
        c.labels
            .insert("com.docker.compose.project".into(), "shop".into());
        c.labels
            .insert("com.docker.compose.service".into(), "web".into());
        let atoms = c.identifier_set();
        assert_eq!(atoms.get("compose.project").unwrap(), "shop");
        assert_eq!(atoms.get("compose.service").unwrap(), "web");
        assert!(!atoms.contains_key("kamal.service"));
    }

    #[test]
    fn identifier_set_explicit_service_name_carries_consent() {
        let mut c = make_container("api-1");
        c.service_name = "api".into();
        c.service_name_explicit = true;
        assert_eq!(c.identifier_set().get("service_name").unwrap(), "api");

        c.service_name_explicit = false;
        assert!(!c.identifier_set().contains_key("service_name"));
    }

    #[test]
    fn identifier_set_stray_service_label_is_not_kamal() {
        let mut c = make_container("my-app");
        c.labels.insert("service".into(), "something".into());
        // No `destination` — the unpaired label must not be read as Kamal.
        assert!(!c.identifier_set().contains_key("kamal.service"));
    }

    #[test]
    fn image_repo_strips_tag_digest_and_keeps_registry_port() {
        assert_eq!(image_repo("nginx:latest").as_deref(), Some("nginx"));
        assert_eq!(image_repo("nginx").as_deref(), Some("nginx"));
        assert_eq!(
            image_repo("ghcr.io/logpacer/api:v1.4.3").as_deref(),
            Some("ghcr.io/logpacer/api")
        );
        assert_eq!(
            image_repo("registry:5000/app:v1").as_deref(),
            Some("registry:5000/app")
        );
        assert_eq!(
            image_repo("registry:5000/app").as_deref(),
            Some("registry:5000/app")
        );
        assert_eq!(
            image_repo("nginx@sha256:deadbeef").as_deref(),
            Some("nginx")
        );
        assert_eq!(image_repo(""), None);
    }

    #[test]
    fn label_values_are_withheld_unless_known_to_be_safe() {
        let mut c = make_container("shop-web-1");
        for (key, value) in [
            ("com.docker.compose.project", "shop"),
            ("com.docker.compose.service", "web"),
            ("io.kubernetes.pod.namespace", "default"),
            ("org.opencontainers.image.version", "4.2"),
            ("logpacer.com/service-name", "web"),
            ("log.format", "json"),
            (
                "traefik.http.middlewares.auth.basicauth.users",
                "admin:$apr1$secret",
            ),
            ("maintainer", "someone@example.net"),
        ] {
            c.labels.insert(key.into(), value.into());
        }

        let entry = c.into_census_entry(false);

        assert_eq!(
            entry.label_keys_withheld,
            [
                "maintainer",
                "traefik.http.middlewares.auth.basicauth.users"
            ]
        );
        assert_eq!(entry.labels.len(), 6);
        assert_eq!(entry.labels["log.format"], "json");
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("apr1"), "{json}");
        assert!(!json.contains("someone@example.net"), "{json}");
    }

    #[test]
    fn an_environment_value_is_kept_only_for_a_plain_fact_with_a_plain_value() {
        let mut c = make_container("shop-web-1");
        c.env = [
            "NODE_VERSION=22.11.0",
            "PG_MAJOR=16",
            "JAVA_VERSION=jdk-21.0.5+11",
            "NODE_ENV=production",
            "LOG_LEVEL=debug",
            "OTEL_SERVICE_NAME=storefront",
            "OTEL_LOGS_EXPORTER=otlp",
            "TZ=Europe/Copenhagen",
            "LOGPACER_SERVICE_NAME=storefront",
            // A secret, whatever its name starts with.
            "LOGPACER_INGEST_TOKEN=a-token-with-our-own-prefix",
            "DATABASE_URL=postgres://shop:a-database-password@db/shop",
            "OTEL_EXPORTER_OTLP_ENDPOINT=http://collector.example:4318",
            "SECRET_KEY=a-secret-key",
            // Named like a version, but the value is not a plain token.
            "APP_VERSION=postgres://shop:hidden@db/shop",
            "API_VERSION=a value with spaces",
            "TOO_LONG_VERSION=0123456789012345678901234567890123456789012345678901234567890123456789",
            "EMPTY_VERSION=",
            "_VERSION=1",
            "PATH=/usr/local/bin:/usr/bin",
            "NO_EQUALS_SIGN",
        ]
        .map(String::from)
        .to_vec();

        let entry = c.into_census_entry(false);

        let kept: Vec<(&str, &str)> = entry
            .env
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        assert_eq!(
            kept,
            [
                ("JAVA_VERSION", "jdk-21.0.5+11"),
                ("LOGPACER_SERVICE_NAME", "storefront"),
                ("LOG_LEVEL", "debug"),
                ("NODE_ENV", "production"),
                ("NODE_VERSION", "22.11.0"),
                ("OTEL_LOGS_EXPORTER", "otlp"),
                ("OTEL_SERVICE_NAME", "storefront"),
                ("PG_MAJOR", "16"),
                ("TZ", "Europe/Copenhagen"),
            ]
        );
        assert_eq!(
            entry.env_names_withheld,
            [
                "API_VERSION",
                "APP_VERSION",
                "DATABASE_URL",
                "EMPTY_VERSION",
                "LOGPACER_INGEST_TOKEN",
                "NO_EQUALS_SIGN",
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                "PATH",
                "SECRET_KEY",
                "TOO_LONG_VERSION",
                "_VERSION",
            ]
        );
        let json = serde_json::to_string(&entry).unwrap();
        for value in [
            "a-token-with-our-own-prefix",
            "a-database-password",
            "collector.example",
            "a-secret-key",
            "hidden",
        ] {
            assert!(!json.contains(value), "{value} is in {json}");
        }
    }

    #[test]
    fn a_later_variable_of_the_same_name_decides() {
        let mut c = make_container("web");
        c.env = ["NODE_ENV=production", "NODE_ENV=a value with spaces"]
            .map(String::from)
            .to_vec();
        let entry = c.into_census_entry(false);
        assert!(entry.env.is_empty());
        assert_eq!(entry.env_names_withheld, ["NODE_ENV"]);

        let mut c = make_container("web");
        c.env = ["NODE_ENV=a value with spaces", "NODE_ENV=production"]
            .map(String::from)
            .to_vec();
        let entry = c.into_census_entry(false);
        assert_eq!(entry.env["NODE_ENV"], "production");
        assert!(entry.env_names_withheld.is_empty());
    }

    #[test]
    fn every_label_value_is_kept_on_request() {
        let mut c = make_container("web");
        c.labels.insert("maintainer".into(), "someone".into());

        let entry = c.into_census_entry(true);

        assert_eq!(entry.labels["maintainer"], "someone");
        assert!(entry.label_keys_withheld.is_empty());
    }

    #[test]
    fn identity_is_derived_before_label_values_are_withheld() {
        // Kamal and Swarm identity come from labels whose values are withheld.
        let kamal =
            make_kamal_container("web", "logpacer-web-prod-1a2b3c4").into_census_entry(false);
        assert_eq!(kamal.stable_identifier, "logpacer-prod");
        assert_eq!(kamal.stable_instance_id, "logpacer-web-prod");
        assert_eq!(kamal.identifiers["kamal.service"], "logpacer");
        assert_eq!(
            kamal.label_keys_withheld,
            ["destination", "role", "service"]
        );
        assert!(kamal.labels.is_empty());

        let mut swarm = make_container("web.2.abc123xyz");
        swarm
            .labels
            .insert("com.docker.stack.namespace".into(), "production".into());
        swarm
            .labels
            .insert("com.docker.swarm.service.name".into(), "web".into());
        swarm.labels.insert(
            "com.docker.swarm.task.name".into(),
            "web.2.abc123xyz".into(),
        );
        let swarm = swarm.into_census_entry(false);
        assert_eq!(swarm.stable_identifier, "production/web");
        assert_eq!(swarm.stable_instance_id, "production/web/2");
    }

    #[test]
    fn the_census_entry_carries_the_identity_and_its_atoms() {
        let mut c = make_container("shop-web-2");
        c.labels
            .insert("com.docker.compose.project".into(), "shop".into());
        c.labels
            .insert("com.docker.compose.service".into(), "web".into());

        let entry = c.into_census_entry(false);

        assert_eq!(entry.stable_identifier, "shop/web");
        assert_eq!(entry.stable_instance_id, "shop/web/2");
        assert_eq!(
            entry.identifiers,
            BTreeMap::from([
                ("compose.project".to_string(), "shop".to_string()),
                ("compose.service".to_string(), "web".to_string()),
                ("container.name".to_string(), "shop-web-2".to_string()),
                ("image.repo".to_string(), "nginx".to_string()),
            ])
        );
    }
}
