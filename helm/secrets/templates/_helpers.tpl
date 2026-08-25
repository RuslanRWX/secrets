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
