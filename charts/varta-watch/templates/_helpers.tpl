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
ExecStart-equivalent argv block — shared by daemonset and deployment
templates. Emitted as a YAML list under `args:`.
*/}}
{{- define "varta-watch.args" -}}
- --uds-path={{ .Values.uds.path }}
{{- if .Values.prometheus.bindAddr }}
- --prom-addr={{ .Values.prometheus.bindAddr }}
- --prom-token-file=/etc/varta/prom.token
{{- end }}
{{- if .Values.selfWatchdogSecs }}
- --self-watchdog-secs={{ .Values.selfWatchdogSecs }}
{{- end }}
{{- range .Values.extraArgs }}
- {{ . | quote }}
{{- end }}
{{- end -}}
