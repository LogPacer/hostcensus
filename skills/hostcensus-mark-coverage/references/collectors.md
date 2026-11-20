# Log collectors: how to recognise them and where they say what they read

Locations are the usual ones. The service definition decides: read the configuration path from `systemctl cat <unit>`, the container's command, or the Windows service's command line, and follow any include directives from there.

Never copy credentials out of these files. Record a destination as a kind of system.

## Recognising a collector

| Collector | Process, unit, package or image name |
|---|---|
| Fluent Bit | `fluent-bit`, `td-agent-bit` |
| Fluentd | `fluentd`, `td-agent` |
| Vector | `vector` |
| Promtail | `promtail` |
| Grafana Alloy, Grafana Agent | `alloy`, `grafana-agent` |
| Filebeat, Winlogbeat | `filebeat`, `winlogbeat` |
| Elastic Agent | `elastic-agent` |
| Logstash | `logstash` |
| OpenTelemetry Collector | `otelcol`, `otelcol-contrib`, `otel-collector` |
| rsyslog, syslog-ng | `rsyslogd`, `syslog-ng` |
| systemd journal upload | `systemd-journal-upload` |
| Datadog Agent | `datadog-agent` |
| Splunk Universal Forwarder | `splunkd`, `SplunkForwarder` |
| Amazon CloudWatch agent | `amazon-cloudwatch-agent` |
| Google Cloud Ops Agent | `google-cloud-ops-agent` |
| Azure Monitor Agent | `azuremonitoragent`, `AzureMonitorAgent` |
| NXLog | `nxlog` |
| EdgePacer | `edgepacer` |

## Where inputs and outputs are defined

**Fluent Bit.** `/etc/fluent-bit/fluent-bit.conf` or `.yaml`, plus files it includes (`@INCLUDE` lines, or an `includes:` list in YAML). Inputs: `[INPUT]` sections; `Name tail` with `Path` (patterns, comma separated) and `Exclude_Path`; `Name systemd` with `Systemd_Filter`; `Name winevtlog` or `winlog` with `Channels`. Outputs: `[OUTPUT]` sections, `Name` with `Match` or `Match_Regex`. A tail input's `Tag` ending in `*` is completed with the file path, so `Tag nginx.*` is matched by `Match nginx.*`. The tag of any other input is matched as written, with `*` in `Match` as a wildcard. An input whose tag no output matches collects nothing, unless a filter rewrites the tag (`rewrite_tag`): then follow the new tag.

**Fluentd.** `/etc/fluent/fluent.conf` or `/etc/td-agent/td-agent.conf`. Inputs: `<source>` with `@type tail` and `path`, or `@type systemd` with `matches`. Outputs: `<match>` with `@type`.

**Vector.** `/etc/vector/vector.yaml` or `.toml`, and the files in `/etc/vector/`. Inputs: `sources` of `type: file` (`include`, `exclude`), `journald` (`include_units`, `exclude_units`), `docker_logs` (`include_containers`, `include_labels`), `kubernetes_logs`. Outputs: `sinks`, each with `type` and `inputs`. Follow `inputs` back through `transforms` to see which sources reach a sink.

**Promtail.** `/etc/promtail/config.yml`. Inputs: `scrape_configs`; `static_configs[].labels.__path__` for files, `journal`, `docker_sd_configs`. Output: `clients`.

**Grafana Alloy.** `/etc/alloy/config.alloy`. Inputs: `local.file_match` (`path_targets`), `loki.source.file`, `loki.source.journal`, `loki.source.docker`. Output: `loki.write`. Follow `forward_to` from source to writer.

**Filebeat.** `/etc/filebeat/filebeat.yml`, `inputs.d/`, `modules.d/*.yml` (only files without the `.disabled` suffix). Inputs: `filebeat.inputs[]` with `type` (`filestream`, `log`, `journald`, `container`) and `paths`, and `enabled`. Output: `output.<kind>`.

**Winlogbeat.** `winlogbeat.yml`. Inputs: `winlogbeat.event_logs[].name`.

**Elastic Agent.** Usually managed centrally, so the policy is not on the host. Ask the human which integrations the policy contains.

**Logstash.** `/etc/logstash/conf.d/*.conf`. Inputs: `input { file { path => ... } }` and others. Outputs: `output { ... }`.

**OpenTelemetry Collector.** `/etc/otelcol/config.yaml` or `/etc/otelcol-contrib/config.yaml`. Inputs: `receivers` of kind `filelog` (`include`, `exclude`), `journald` (`units`), `windowseventlog` (`channel`). Only receivers listed under `service.pipelines.logs.receivers` are in use. Outputs: the `exporters` of that pipeline.

**rsyslog.** `/etc/rsyslog.conf`, `/etc/rsyslog.d/*.conf`. File inputs: `imfile` with `File=`. Forwarding: actions with `@host`, `@@host` or `type="omfwd"`. When everything is forwarded, what reaches syslog is collected: that covers units logging to the journal only when the journal forwards to syslog.

**syslog-ng.** `/etc/syslog-ng/syslog-ng.conf`. Follow each `log { source(...); destination(...); }` path.

**systemd journal.** Check `/etc/systemd/journald.conf` and its drop-ins on every systemd host. Effective `ForwardToSyslog=yes` forwards journal records to syslog; trace the syslog daemon's active route. `/etc/systemd/journal-upload.conf` (`URL`) with an active `systemd-journal-upload` is another journal forwarding path. Neither covers a service's separate application files or direct telemetry. Record `journal only` in a service mark's evidence.

**Datadog Agent.** `/etc/datadog-agent/datadog.yaml` (`logs_enabled`, `logs_config.container_collect_all`) and `conf.d/*.d/conf.yaml`, key `logs:` with `type` and `path`.

**Splunk Universal Forwarder.** `inputs.conf` under `/opt/splunkforwarder/etc/system/local/` and `etc/apps/*/local/`. Inputs: `[monitor://<path>]`, `[WinEventLog://<channel>]`; `disabled` turns one off. Output: `outputs.conf`.

**Amazon CloudWatch agent.** `/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json`. Inputs: `logs.logs_collected.files.collect_list[].file_path` and `windows_events.collect_list[].event_name`.

**Google Cloud Ops Agent.** `/etc/google-cloud-ops-agent/config.yaml`, `logging.receivers` and the pipelines that use them. It also collects syslog by default.

**Azure Monitor Agent.** Configured by data collection rules in Azure, not on the host. Ask the human.

**NXLog.** `/etc/nxlog/nxlog.conf`. Inputs: `<Input>` with `Module im_file` and `File`, or `im_msvistalog`. `<Route>` says which inputs reach which outputs.

**EdgePacer.** What it collects is decided in LogPacer, not in a local file. Ask the human, or look in LogPacer.

## Collection that is not a collector

- **Telemetry configured in a container.** `inventory.containers[].env` and `env_names_withheld` list a running container's environment variables. Names such as `OTEL_EXPORTER_OTLP_ENDPOINT`, `DD_AGENT_HOST`, `SENTRY_DSN` or `FLUENT_HOST`, or a kept `OTEL_LOGS_EXPORTER=otlp`, are leads to configured telemetry. They do not establish that logs are sent or received. Endpoint values are withheld by default; ask the human what is enabled and where it sends.
- **Container log drivers.** Driver `none` disables runtime capture of stdout/stderr; it is not forwarding. `json-file`, `local` and `journald` describe local runtime logging, not confirmed onward delivery. Other drivers may forward; inspect the effective driver and route and ask the human to confirm the destination. `/etc/docker/daemon.json` (`log-driver`) sets the default, which a container can override. Application files and direct exports are separate paths.
- **Cluster-wide collectors.** On a Kubernetes node the collector usually runs as a pod and its configuration lives in the cluster. Ask the human.
- **Home-built collection.** Scheduled jobs (`/etc/cron.d`, `/etc/crontab`, user crontabs, systemd timers), log rotation scripts (`postrotate` or `lastaction` in `/etc/logrotate.d/`) and backup tools can copy logs away with `rsync`, `scp` or an object-store client. The census does not list scheduled jobs, so read these places on every host, and ask. A job collects only if its scheduler runs (`systemctl is-active cron` or `crond`, `systemctl list-timers`) and the tools it calls are installed. Record the job's name as the collector, the file and line that define it as the evidence, and the kind of transfer as the destination, such as `rsync to another host`.
- **Platform collection.** Cloud and hosting platforms can collect a machine's console or system log without anything on the host. Only the human knows.
