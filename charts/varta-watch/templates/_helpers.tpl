{{/*
Expand the chart fullname (release-aware).
*/}}
{{- define "varta-watch.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "varta-watch.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "varta-watch.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels (Helm standard set + the existing `varta-watch` labels
that the raw observability/examples/kubernetes/ manifests carry; the
helm-parity CI gate diffs the two and would catch any drift).
*/}}
{{- define "varta-watch.labels" -}}
helm.sh/chart: {{ include "varta-watch.chart" . }}
{{ include "varta-watch.selectorLabels" . }}
app.kubernetes.io/component: observer
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "varta-watch.selectorLabels" -}}
app.kubernetes.io/name: {{ include "varta-watch.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Resolve the namespace the chart's objects should land in.
*/}}
{{- define "varta-watch.namespace" -}}
{{- if .Values.namespace.create -}}
{{- .Values.namespace.name -}}
{{- else -}}
{{- .Release.Namespace -}}
{{- end -}}
{{- end -}}

{{/*
Resolve the ServiceAccount name.
*/}}
{{- define "varta-watch.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "varta-watch.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Resolve the Secret name that holds the bearer token.
*/}}
{{- define "varta-watch.tokenSecretName" -}}
{{- if .Values.prometheusToken.existingSecret.name -}}
{{- .Values.prometheusToken.existingSecret.name -}}
{{- else -}}
{{- printf "%s-prom-token" (include "varta-watch.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Resolve the bearer-token Secret key.
*/}}
{{- define "varta-watch.tokenSecretKey" -}}
{{- default "token" .Values.prometheusToken.existingSecret.key -}}
{{- end -}}

{{/*
Resolve the Secret name that holds the Alertmanager Slack webhook URL.
*/}}
{{- define "varta-watch.slackSecretName" -}}
{{- if .Values.alertmanager.slack.existingSecret.name -}}
{{- .Values.alertmanager.slack.existingSecret.name -}}
{{- else -}}
{{- printf "%s-alertmanager-slack" (include "varta-watch.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Resolve the Slack Secret key.
*/}}
{{- define "varta-watch.slackSecretKey" -}}
{{- default "slack-webhook-url" .Values.alertmanager.slack.existingSecret.key -}}
{{- end -}}

{{/*
Resolve image tag — values.image.tag wins; otherwise Chart.appVersion.
*/}}
{{- define "varta-watch.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/*
Init-container that stages the bearer token from the K8s Secret mount
(root-owned, mode 0400, immutable) into an in-memory emptyDir owned by
the runtime UID, so validate_secret_file() in varta-watch passes its
"file uid == observer uid" check.

Why: Kubernetes mounts Secret/ConfigMap/Projected volumes as root:root.
fsGroup can rewrite GID but never UID; defaultMode loose enough for a
non-root reader (0o4xx) gets rejected by validate_secret_file's
`mode & 0o077 != 0` check. The stage-then-chown init is the standard
escape hatch — see book/src/operations/helm.md for the full rationale.
*/}}
{{- define "varta-watch.tokenInitContainer" -}}
- name: token-stage
  image: {{ printf "%s:%s" .Values.tokenInit.image.repository .Values.tokenInit.image.tag | quote }}
  imagePullPolicy: {{ .Values.tokenInit.image.pullPolicy }}
  command: ["/bin/sh", "-c"]
  args:
    - |
      set -eu
      cp /token-source/prom.token /token/prom.token
      chown {{ .Values.podSecurityContext.runAsUser }}:{{ .Values.podSecurityContext.runAsGroup }} /token/prom.token
      chmod 0400 /token/prom.token
  securityContext:
    runAsUser: 0
    runAsGroup: 0
    runAsNonRoot: false
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: ["ALL"]
      add: ["CHOWN", "FOWNER", "DAC_OVERRIDE"]
    seccompProfile:
      type: RuntimeDefault
  resources:
    {{- toYaml .Values.tokenInit.resources | nindent 4 }}
  volumeMounts:
    - name: token-source
      mountPath: /token-source
      readOnly: true
    - name: token
      mountPath: /token
{{- end -}}

{{/*
Init-container that prepares the UDS parent directory before the observer
binds its socket. Kubernetes fsGroup may make writable volumes group-writable;
varta-watch rejects that unless the directory is sticky. Prefer the tighter
posture: make the directory observer-owned and not writable by group/other.
*/}}
{{- define "varta-watch.udsInitContainer" -}}
- name: uds-permissions
  image: {{ printf "%s:%s" .Values.udsInit.image.repository .Values.udsInit.image.tag | quote }}
  imagePullPolicy: {{ .Values.udsInit.image.pullPolicy }}
  command: ["/bin/sh", "-c"]
  args:
    - |
      set -eu
      chown {{ .Values.podSecurityContext.runAsUser }}:{{ .Values.podSecurityContext.runAsGroup }} {{ dir .Values.uds.path | quote }}
      chmod 0755 {{ dir .Values.uds.path | quote }}
  securityContext:
    runAsUser: 0
    runAsGroup: 0
    runAsNonRoot: false
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: ["ALL"]
      add: ["CHOWN", "FOWNER", "DAC_OVERRIDE"]
    seccompProfile:
      type: RuntimeDefault
  resources:
    {{- toYaml .Values.udsInit.resources | nindent 4 }}
  volumeMounts:
    - name: uds
      mountPath: {{ dir .Values.uds.path }}
{{- end -}}

{{/*
ExecStart-equivalent argv block — shared by daemonset and deployment
templates. Emitted as a YAML list under `args:`.

The varta-watch argv parser is whitespace-separated only ("--flag value");
it does NOT accept "--flag=value". Each flag and its value therefore
become two distinct list items so they land in argv as separate tokens.
*/}}
{{- define "varta-watch.args" -}}
- --socket
- {{ .Values.uds.path | quote }}
- --threshold-ms
- {{ .Values.thresholdMs | int | quote }}
{{- if .Values.prometheus.bindAddr }}
- --prom-addr
- {{ .Values.prometheus.bindAddr | quote }}
- --prom-token-file
- /etc/varta/prom.token
{{- end }}
{{- if .Values.selfWatchdogSecs }}
- --self-watchdog-secs
- {{ .Values.selfWatchdogSecs | int | quote }}
{{- end }}
{{- range .Values.extraArgs }}
- {{ . | quote }}
{{- end }}
{{- end -}}
