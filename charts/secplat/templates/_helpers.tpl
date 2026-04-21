{{- define "secplat.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "secplat.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- include "secplat.name" . -}}
{{- end -}}
{{- end -}}

{{- define "secplat.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride -}}
{{- end -}}

{{- define "secplat.labels" -}}
app.kubernetes.io/part-of: {{ include "secplat.name" . }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "secplat.serviceAccountName" -}}
{{- if .Values.serviceAccount.name -}}
{{- .Values.serviceAccount.name -}}
{{- else -}}
{{- printf "%s-workload" (include "secplat.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "secplat.apiServiceName" -}}
{{- printf "%s-api" (include "secplat.fullname" .) -}}
{{- end -}}

{{- define "secplat.postgresServiceName" -}}
{{- printf "%s-postgres" (include "secplat.fullname" .) -}}
{{- end -}}

{{- define "secplat.redisServiceName" -}}
{{- printf "%s-redis" (include "secplat.fullname" .) -}}
{{- end -}}

{{- define "secplat.opensearchServiceName" -}}
{{- printf "%s-opensearch" (include "secplat.fullname" .) -}}
{{- end -}}

{{- define "secplat.apiUrl" -}}
{{- printf "http://%s:%v" (include "secplat.apiServiceName" .) .Values.api.service.port -}}
{{- end -}}

{{- define "secplat.redisUrl" -}}
{{- if .Values.dependencies.redis.enabled -}}
{{- printf "redis://%s:%v/0" (include "secplat.redisServiceName" .) .Values.dependencies.redis.service.port -}}
{{- else -}}
{{- .Values.config.REDIS_URL -}}
{{- end -}}
{{- end -}}

{{- define "secplat.opensearchUrl" -}}
{{- if .Values.dependencies.opensearch.enabled -}}
{{- printf "http://%s:%v" (include "secplat.opensearchServiceName" .) .Values.dependencies.opensearch.service.port -}}
{{- else -}}
{{- .Values.config.OPENSEARCH_URL -}}
{{- end -}}
{{- end -}}

{{- define "secplat.apiPostgresDsn" -}}
{{- if .Values.dependencies.postgres.enabled -}}
{{- printf "postgresql+psycopg://%s:%s@%s:%v/%s" .Values.dependencies.postgres.auth.runtimeUser .Values.dependencies.postgres.auth.runtimePassword (include "secplat.postgresServiceName" .) .Values.dependencies.postgres.service.port .Values.dependencies.postgres.auth.database -}}
{{- else -}}
{{- .Values.secretData.API_POSTGRES_DSN -}}
{{- end -}}
{{- end -}}

{{- define "secplat.migrationsPostgresDsn" -}}
{{- if .Values.dependencies.postgres.enabled -}}
{{- printf "postgresql+psycopg://%s:%s@%s:%v/%s" .Values.dependencies.postgres.auth.username .Values.dependencies.postgres.auth.password (include "secplat.postgresServiceName" .) .Values.dependencies.postgres.service.port .Values.dependencies.postgres.auth.database -}}
{{- else -}}
{{- .Values.secretData.API_MIGRATIONS_POSTGRES_DSN -}}
{{- end -}}
{{- end -}}
