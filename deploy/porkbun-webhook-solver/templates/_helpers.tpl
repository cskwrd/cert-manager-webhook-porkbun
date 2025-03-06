{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "porkbun-webhook-solver.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "porkbun-webhook-solver.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "porkbun-webhook-solver.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "porkbun-webhook-solver.selfSignedIssuer" -}}
{{ printf "%s-selfsign" (include "porkbun-webhook-solver.fullname" .) }}
{{- end -}}

{{- define "porkbun-webhook-solver.rootCAIssuer" -}}
{{ printf "%s-ca" (include "porkbun-webhook-solver.fullname" .) }}
{{- end -}}

{{- define "porkbun-webhook-solver.rootCACertificate" -}}
{{ printf "%s-ca" (include "porkbun-webhook-solver.fullname" .) }}
{{- end -}}

{{- define "porkbun-webhook-solver.servingCertificate" -}}
{{ printf "%s-webhook-tls" (include "porkbun-webhook-solver.fullname" .) }}
{{- end -}}
