{{/* Common labels: the Kubernetes recommended set plus Helm's. */}}
{{- define "platform.labels" -}}
app.kubernetes.io/part-of: secure-platform
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end }}

{{/* An image reference: registry/repository@digest when a digest is set, else :tag. */}}
{{- define "platform.image" -}}
{{- $root := index . 0 -}}
{{- $image := index . 1 -}}
{{- if $image.digest -}}
{{ printf "%s/%s@%s" $root.Values.imageRegistry $image.repository $image.digest }}
{{- else -}}
{{ printf "%s/%s:%s" $root.Values.imageRegistry $image.repository $image.tag }}
{{- end -}}
{{- end }}

{{/* Pod and container hardening shared by every workload (restricted Pod Security). */}}
{{- define "platform.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: [ALL]
{{- end }}
