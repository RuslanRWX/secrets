{{/* Expand the name of the chart. */}}
{{- define "secrets.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "secrets.fullname" -}}
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

{{- define "secrets.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "secrets.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "secrets.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "secrets.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Name of the Secret holding the master and session keys. */}}
{{- define "secrets.keySecretName" -}}
{{- if .Values.encryption.existingSecret -}}
{{- .Values.encryption.existingSecret -}}
{{- else -}}
{{- printf "%s-keys" (include "secrets.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "secrets.postgresqlFullname" -}}
{{- printf "%s-postgresql" (include "secrets.fullname" .) -}}
{{- end -}}

{{/*
Resolve the master key. Precedence: an explicit value, then whatever is already
in the cluster, then a freshly generated key. Reading the existing Secret is
what keeps an upgrade from rotating the key and orphaning every stored secret.
*/}}
{{- define "secrets.masterKey" -}}
{{- if .Values.encryption.masterKey -}}
{{- .Values.encryption.masterKey -}}
{{- else -}}
{{- $existing := lookup "v1" "Secret" .Release.Namespace (printf "%s-keys" (include "secrets.fullname" .)) -}}
{{- if and $existing (index $existing.data "master-key") -}}
{{- index $existing.data "master-key" | b64dec -}}
{{- else -}}
{{- randAlphaNum 44 -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "secrets.jwtSecret" -}}
{{- if .Values.encryption.jwtSecret -}}
{{- .Values.encryption.jwtSecret -}}
{{- else -}}
{{- $existing := lookup "v1" "Secret" .Release.Namespace (printf "%s-keys" (include "secrets.fullname" .)) -}}
{{- if and $existing (index $existing.data "jwt-secret") -}}
{{- index $existing.data "jwt-secret" | b64dec -}}
{{- else -}}
{{- randAlphaNum 44 -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "secrets.postgresqlPassword" -}}
{{- if .Values.postgresql.password -}}
{{- .Values.postgresql.password -}}
{{- else -}}
{{- $existing := lookup "v1" "Secret" .Release.Namespace (printf "%s-postgresql" (include "secrets.fullname" .)) -}}
{{- if and $existing (index $existing.data "password") -}}
{{- index $existing.data "password" | b64dec -}}
{{- else -}}
{{- randAlphaNum 24 -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Resolve the tag for one component. Precedence: the component's own tag, then
the shared image.tag, then the chart's appVersion. Pass the component values as
"component" and the root context as "root".
*/}}
{{- define "secrets.tag" -}}
{{- .component.tag | default .root.Values.image.tag | default .root.Chart.AppVersion -}}
{{- end -}}

{{/*
A moving tag points at different content over time, so it needs pulling on
every start and a rollout on every upgrade. A pinned version does not.
*/}}
{{- define "secrets.isMovingTag" -}}
{{- if has . (list "latest" "main" "edge" "nightly") -}}true{{- end -}}
{{- end -}}

{{/*
Pull policy. An explicit setting always wins; otherwise a moving tag is pulled
every time and a pinned one is cached. Getting this wrong is why "latest"
usually fails to update anything.
*/}}
{{- define "secrets.pullPolicy" -}}
{{- if .policy -}}
{{- .policy -}}
{{- else if include "secrets.isMovingTag" .tag -}}
Always
{{- else -}}
IfNotPresent
{{- end -}}
{{- end -}}

{{- define "secrets.apiTag" -}}
{{- include "secrets.tag" (dict "component" .Values.image.api "root" .) -}}
{{- end -}}

{{- define "secrets.uiTag" -}}
{{- include "secrets.tag" (dict "component" .Values.image.ui "root" .) -}}
{{- end -}}

{{- define "secrets.apiImage" -}}
{{- printf "%s/%s:%s" .Values.image.registry .Values.image.api.repository (include "secrets.apiTag" .) -}}
{{- end -}}

{{- define "secrets.uiImage" -}}
{{- printf "%s/%s:%s" .Values.image.registry .Values.image.ui.repository (include "secrets.uiTag" .) -}}
{{- end -}}

{{- define "secrets.apiPullPolicy" -}}
{{- include "secrets.pullPolicy" (dict
      "policy" (.Values.image.api.pullPolicy | default .Values.image.pullPolicy)
      "tag" (include "secrets.apiTag" .)) -}}
{{- end -}}

{{- define "secrets.uiPullPolicy" -}}
{{- include "secrets.pullPolicy" (dict
      "policy" (.Values.image.ui.pullPolicy | default .Values.image.pullPolicy)
      "tag" (include "secrets.uiTag" .)) -}}
{{- end -}}

{{/*
On a moving tag, emit the release revision as a pod annotation. Without it a
`helm upgrade` that changes nothing in the manifest leaves the old pods running
and the new image is never pulled.
*/}}
{{- define "secrets.rolloutAnnotation" -}}
{{- if include "secrets.isMovingTag" .tag -}}
rollout/revision: {{ .revision | quote }}
{{- end -}}
{{- end -}}
