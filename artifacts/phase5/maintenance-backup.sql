--
-- PostgreSQL database dump
--

\restrict 7dJALW4X1I7DIl3LMt23D9X3VK43fvqtNUwXvTgZVxrst9wYNSf5h95ydfhyaxE

-- Dumped from database version 16.11 (Debian 16.11-1.pgdg13+1)
-- Dumped by pg_dump version 16.11 (Debian 16.11-1.pgdg13+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: set_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.set_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: ai_feedback; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ai_feedback (
    feedback_id bigint NOT NULL,
    entity_type text NOT NULL,
    entity_key text NOT NULL,
    version_id bigint,
    feedback text NOT NULL,
    comment text,
    context_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_feedback_feedback_check CHECK ((feedback = ANY (ARRAY['up'::text, 'down'::text])))
);


--
-- Name: ai_feedback_feedback_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ai_feedback_feedback_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ai_feedback_feedback_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ai_feedback_feedback_id_seq OWNED BY public.ai_feedback.feedback_id;


--
-- Name: ai_summary_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ai_summary_versions (
    version_id bigint NOT NULL,
    entity_type text NOT NULL,
    entity_key text NOT NULL,
    version_no integer NOT NULL,
    content_text text NOT NULL,
    provider text,
    model text,
    generated_by text,
    source_type text DEFAULT 'generated'::text NOT NULL,
    context_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    evidence_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: ai_summary_versions_version_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ai_summary_versions_version_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ai_summary_versions_version_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ai_summary_versions_version_id_seq OWNED BY public.ai_summary_versions.version_id;


--
-- Name: alert_ai_guidance; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alert_ai_guidance (
    id integer NOT NULL,
    asset_key text NOT NULL,
    guidance_text text NOT NULL,
    recommended_action text,
    urgency text,
    provider text NOT NULL,
    model text NOT NULL,
    generated_by text,
    generated_at timestamp with time zone DEFAULT now() NOT NULL,
    context_signature text DEFAULT ''::text NOT NULL,
    context_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    org_id text DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id'::text, true), ''::text), 'default'::text) NOT NULL
);

ALTER TABLE ONLY public.alert_ai_guidance FORCE ROW LEVEL SECURITY;


--
-- Name: alert_ai_guidance_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.alert_ai_guidance_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: alert_ai_guidance_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.alert_ai_guidance_id_seq OWNED BY public.alert_ai_guidance.id;


--
-- Name: alert_states; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alert_states (
    asset_key text NOT NULL,
    state text DEFAULT 'firing'::text NOT NULL,
    ack_reason text,
    acked_by text,
    acked_at timestamp with time zone,
    suppressed_until timestamp with time zone,
    assigned_to text,
    resolved_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: asset_ai_diagnoses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.asset_ai_diagnoses (
    id integer NOT NULL,
    asset_key text NOT NULL,
    diagnosis_text text NOT NULL,
    provider text NOT NULL,
    model text NOT NULL,
    generated_by text,
    generated_at timestamp with time zone DEFAULT now() NOT NULL,
    context_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    org_id text DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id'::text, true), ''::text), 'default'::text) NOT NULL
);

ALTER TABLE ONLY public.asset_ai_diagnoses FORCE ROW LEVEL SECURITY;


--
-- Name: asset_ai_diagnoses_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.asset_ai_diagnoses_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: asset_ai_diagnoses_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.asset_ai_diagnoses_id_seq OWNED BY public.asset_ai_diagnoses.id;


--
-- Name: asset_anomaly_scores; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.asset_anomaly_scores (
    id bigint NOT NULL,
    asset_key text NOT NULL,
    computed_at timestamp with time zone DEFAULT now() NOT NULL,
    anomaly_score double precision NOT NULL,
    baseline_mean double precision,
    baseline_std double precision,
    current_value double precision,
    source_breakdown jsonb DEFAULT '{}'::jsonb NOT NULL,
    context_json jsonb DEFAULT '{}'::jsonb NOT NULL
);


--
-- Name: asset_anomaly_scores_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.asset_anomaly_scores_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: asset_anomaly_scores_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.asset_anomaly_scores_id_seq OWNED BY public.asset_anomaly_scores.id;


--
-- Name: assets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.assets (
    asset_id integer NOT NULL,
    asset_key text NOT NULL,
    type text NOT NULL,
    name text NOT NULL,
    owner text,
    owner_team text,
    owner_email text,
    asset_type text DEFAULT 'service'::text NOT NULL,
    environment text DEFAULT 'dev'::text NOT NULL,
    criticality text DEFAULT 'medium'::text NOT NULL,
    verified boolean DEFAULT false,
    verification_method text,
    verification_token text,
    address text,
    port integer,
    is_active boolean DEFAULT true NOT NULL,
    tags text[] DEFAULT ARRAY[]::text[] NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    org_id text DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id'::text, true), ''::text), 'default'::text) NOT NULL
);

ALTER TABLE ONLY public.assets FORCE ROW LEVEL SECURITY;


--
-- Name: assets_asset_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.assets_asset_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: assets_asset_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.assets_asset_id_seq OWNED BY public.assets.asset_id;


--
-- Name: attack_lab_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attack_lab_runs (
    run_id bigint NOT NULL,
    task_type text NOT NULL,
    target_asset_id integer,
    target_asset_key text,
    target text,
    status text DEFAULT 'queued'::text NOT NULL,
    requested_by text,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    error text,
    output_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT attack_lab_runs_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'running'::text, 'done'::text, 'failed'::text])))
);


--
-- Name: attack_lab_runs_run_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.attack_lab_runs_run_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: attack_lab_runs_run_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.attack_lab_runs_run_id_seq OWNED BY public.attack_lab_runs.run_id;


--
-- Name: attack_surface_certificates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attack_surface_certificates (
    cert_id bigint NOT NULL,
    run_id bigint NOT NULL,
    host_id bigint NOT NULL,
    asset_key text,
    hostname text,
    common_name text,
    issuer text,
    serial_number text,
    fingerprint_sha256 text,
    not_before timestamp with time zone,
    not_after timestamp with time zone,
    discovered_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: attack_surface_certificates_cert_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.attack_surface_certificates_cert_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: attack_surface_certificates_cert_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.attack_surface_certificates_cert_id_seq OWNED BY public.attack_surface_certificates.cert_id;


--
-- Name: attack_surface_discovery_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attack_surface_discovery_runs (
    run_id bigint NOT NULL,
    status text DEFAULT 'running'::text NOT NULL,
    requested_by text,
    source_job_id integer,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    error text,
    metadata_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    summary_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT attack_surface_discovery_runs_status_check CHECK ((status = ANY (ARRAY['running'::text, 'done'::text, 'failed'::text])))
);


--
-- Name: attack_surface_discovery_runs_run_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.attack_surface_discovery_runs_run_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: attack_surface_discovery_runs_run_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.attack_surface_discovery_runs_run_id_seq OWNED BY public.attack_surface_discovery_runs.run_id;


--
-- Name: attack_surface_drift_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attack_surface_drift_events (
    event_id bigint NOT NULL,
    run_id bigint NOT NULL,
    event_type text NOT NULL,
    severity text DEFAULT 'medium'::text NOT NULL,
    asset_key text,
    hostname text,
    domain text,
    port integer,
    details_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT attack_surface_drift_events_event_type_check CHECK ((event_type = ANY (ARRAY['new_host'::text, 'new_port'::text, 'new_subdomain'::text, 'unexpected_cert_change'::text]))),
    CONSTRAINT attack_surface_drift_events_severity_check CHECK ((severity = ANY (ARRAY['critical'::text, 'high'::text, 'medium'::text, 'low'::text, 'info'::text])))
);


--
-- Name: attack_surface_drift_events_event_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.attack_surface_drift_events_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: attack_surface_drift_events_event_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.attack_surface_drift_events_event_id_seq OWNED BY public.attack_surface_drift_events.event_id;


--
-- Name: attack_surface_exposures; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attack_surface_exposures (
    asset_key text NOT NULL,
    run_id bigint,
    internet_exposed boolean DEFAULT false NOT NULL,
    open_port_count integer DEFAULT 0 NOT NULL,
    open_management_ports text[] DEFAULT ARRAY[]::text[] NOT NULL,
    service_risk integer DEFAULT 0 NOT NULL,
    exposure_score integer DEFAULT 0 NOT NULL,
    exposure_level text DEFAULT 'low'::text NOT NULL,
    details_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT attack_surface_exposures_exposure_level_check CHECK ((exposure_level = ANY (ARRAY['critical'::text, 'high'::text, 'medium'::text, 'low'::text])))
);


--
-- Name: attack_surface_hosts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attack_surface_hosts (
    host_id bigint NOT NULL,
    run_id bigint NOT NULL,
    asset_key text,
    hostname text NOT NULL,
    ip_address text,
    internet_exposed boolean DEFAULT false NOT NULL,
    source text DEFAULT 'asset_inventory'::text NOT NULL,
    discovered_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: attack_surface_hosts_host_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.attack_surface_hosts_host_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: attack_surface_hosts_host_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.attack_surface_hosts_host_id_seq OWNED BY public.attack_surface_hosts.host_id;


--
-- Name: attack_surface_relationships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attack_surface_relationships (
    relationship_id bigint NOT NULL,
    source_asset_key text NOT NULL,
    target_asset_key text NOT NULL,
    relation_type text NOT NULL,
    confidence double precision DEFAULT 0.8 NOT NULL,
    details_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    updated_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: attack_surface_relationships_relationship_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.attack_surface_relationships_relationship_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: attack_surface_relationships_relationship_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.attack_surface_relationships_relationship_id_seq OWNED BY public.attack_surface_relationships.relationship_id;


--
-- Name: attack_surface_services; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attack_surface_services (
    service_id bigint NOT NULL,
    run_id bigint NOT NULL,
    host_id bigint NOT NULL,
    asset_key text,
    hostname text,
    port integer NOT NULL,
    protocol text DEFAULT 'tcp'::text NOT NULL,
    service_name text,
    service_version text,
    discovered_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: attack_surface_services_service_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.attack_surface_services_service_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: attack_surface_services_service_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.attack_surface_services_service_id_seq OWNED BY public.attack_surface_services.service_id;


--
-- Name: audit_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_events (
    id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    action text NOT NULL,
    user_name text,
    asset_key text,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    request_id text
);


--
-- Name: audit_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_events_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_events_id_seq OWNED BY public.audit_events.id;


--
-- Name: auth_refresh_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_refresh_tokens (
    id bigint NOT NULL,
    token_hash text NOT NULL,
    username text NOT NULL,
    role text DEFAULT 'viewer'::text NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    replaced_by_hash text,
    revoked_at timestamp with time zone,
    revoked_reason text,
    client_ip text,
    user_agent text
);


--
-- Name: auth_refresh_tokens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.auth_refresh_tokens_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: auth_refresh_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.auth_refresh_tokens_id_seq OWNED BY public.auth_refresh_tokens.id;


--
-- Name: automation_approvals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.automation_approvals (
    approval_id bigint NOT NULL,
    run_action_id bigint NOT NULL,
    required_role text NOT NULL,
    risk_tier text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    requested_by text,
    approved_by text,
    rejected_by text,
    reason text,
    decision_note text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    decided_at timestamp with time zone,
    CONSTRAINT automation_approvals_required_role_check CHECK ((required_role = ANY (ARRAY['analyst'::text, 'admin'::text]))),
    CONSTRAINT automation_approvals_risk_tier_check CHECK ((risk_tier = ANY (ARRAY['medium'::text, 'high'::text]))),
    CONSTRAINT automation_approvals_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'rejected'::text])))
);


--
-- Name: automation_approvals_approval_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.automation_approvals_approval_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: automation_approvals_approval_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.automation_approvals_approval_id_seq OWNED BY public.automation_approvals.approval_id;


--
-- Name: automation_playbooks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.automation_playbooks (
    playbook_id integer NOT NULL,
    title text NOT NULL,
    description text,
    trigger text NOT NULL,
    conditions_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    actions_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    approval_required boolean DEFAULT false NOT NULL,
    rollback_steps_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: automation_playbooks_playbook_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.automation_playbooks_playbook_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: automation_playbooks_playbook_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.automation_playbooks_playbook_id_seq OWNED BY public.automation_playbooks.playbook_id;


--
-- Name: automation_rollbacks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.automation_rollbacks (
    rollback_id bigint NOT NULL,
    run_action_id bigint NOT NULL,
    rollback_type text NOT NULL,
    rollback_payload_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    requested_by text,
    executed_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    executed_at timestamp with time zone,
    error text,
    CONSTRAINT automation_rollbacks_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'executed'::text, 'failed'::text])))
);


--
-- Name: automation_rollbacks_rollback_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.automation_rollbacks_rollback_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: automation_rollbacks_rollback_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.automation_rollbacks_rollback_id_seq OWNED BY public.automation_rollbacks.rollback_id;


--
-- Name: automation_run_actions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.automation_run_actions (
    run_action_id bigint NOT NULL,
    run_id bigint NOT NULL,
    action_index integer NOT NULL,
    action_type text NOT NULL,
    risk_tier text DEFAULT 'low'::text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    params_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    result_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    CONSTRAINT automation_run_actions_risk_tier_check CHECK ((risk_tier = ANY (ARRAY['low'::text, 'medium'::text, 'high'::text]))),
    CONSTRAINT automation_run_actions_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'pending_approval'::text, 'approved'::text, 'rejected'::text, 'running'::text, 'done'::text, 'failed'::text, 'rolled_back'::text])))
);


--
-- Name: automation_run_actions_run_action_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.automation_run_actions_run_action_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: automation_run_actions_run_action_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.automation_run_actions_run_action_id_seq OWNED BY public.automation_run_actions.run_action_id;


--
-- Name: automation_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.automation_runs (
    run_id bigint NOT NULL,
    playbook_id integer NOT NULL,
    trigger_source text NOT NULL,
    trigger_payload_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    matched boolean DEFAULT true NOT NULL,
    status text DEFAULT 'running'::text NOT NULL,
    requested_by text,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    error text,
    summary_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT automation_runs_status_check CHECK ((status = ANY (ARRAY['running'::text, 'pending_approval'::text, 'done'::text, 'failed'::text, 'rejected'::text])))
);


--
-- Name: automation_runs_run_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.automation_runs_run_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: automation_runs_run_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.automation_runs_run_id_seq OWNED BY public.automation_runs.run_id;


--
-- Name: detection_correlation_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.detection_correlation_rules (
    correlation_rule_id integer NOT NULL,
    name text NOT NULL,
    description text,
    severity text DEFAULT 'high'::text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    group_by text DEFAULT 'asset_key'::text NOT NULL,
    window_minutes integer DEFAULT 60 NOT NULL,
    min_distinct_sources integer DEFAULT 1 NOT NULL,
    mitre_tactic text,
    mitre_technique text,
    definition_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_run_at timestamp with time zone,
    last_match_count integer,
    CONSTRAINT detection_correlation_rules_group_by_check CHECK ((group_by = ANY (ARRAY['asset_key'::text, 'source_ip'::text, 'none'::text]))),
    CONSTRAINT detection_correlation_rules_severity_check CHECK ((severity = ANY (ARRAY['critical'::text, 'high'::text, 'medium'::text, 'low'::text, 'info'::text])))
);


--
-- Name: detection_correlation_rules_correlation_rule_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.detection_correlation_rules_correlation_rule_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: detection_correlation_rules_correlation_rule_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.detection_correlation_rules_correlation_rule_id_seq OWNED BY public.detection_correlation_rules.correlation_rule_id;


--
-- Name: detection_correlation_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.detection_correlation_runs (
    run_id bigint NOT NULL,
    correlation_rule_id integer NOT NULL,
    executed_by text,
    run_mode text DEFAULT 'manual'::text NOT NULL,
    trigger_source text DEFAULT 'manual'::text NOT NULL,
    schedule_ref text,
    lookback_minutes integer DEFAULT 60 NOT NULL,
    window_start timestamp with time zone NOT NULL,
    window_end timestamp with time zone NOT NULL,
    matched_chains integer DEFAULT 0 NOT NULL,
    alerts_created integer DEFAULT 0 NOT NULL,
    snapshot_hash text,
    snapshot_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    error text,
    CONSTRAINT detection_correlation_runs_run_mode_check CHECK ((run_mode = ANY (ARRAY['manual'::text, 'job'::text, 'scheduled'::text])))
);


--
-- Name: detection_correlation_runs_run_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.detection_correlation_runs_run_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: detection_correlation_runs_run_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.detection_correlation_runs_run_id_seq OWNED BY public.detection_correlation_runs.run_id;


--
-- Name: detection_rule_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.detection_rule_runs (
    run_id bigint NOT NULL,
    rule_id integer NOT NULL,
    executed_by text,
    lookback_hours integer DEFAULT 24 NOT NULL,
    status text DEFAULT 'done'::text NOT NULL,
    matches integer DEFAULT 0 NOT NULL,
    run_mode text DEFAULT 'test'::text NOT NULL,
    trigger_source text DEFAULT 'manual'::text NOT NULL,
    schedule_ref text,
    create_alerts boolean DEFAULT false NOT NULL,
    snapshot_hash text,
    snapshot_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    rule_version integer,
    rule_stage text,
    window_start timestamp with time zone,
    window_end timestamp with time zone,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    error text,
    results_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT detection_rule_runs_run_mode_check CHECK ((run_mode = ANY (ARRAY['test'::text, 'simulate'::text, 'scheduled'::text]))),
    CONSTRAINT detection_rule_runs_status_check CHECK ((status = ANY (ARRAY['running'::text, 'done'::text, 'failed'::text])))
);


--
-- Name: detection_rule_runs_run_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.detection_rule_runs_run_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: detection_rule_runs_run_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.detection_rule_runs_run_id_seq OWNED BY public.detection_rule_runs.run_id;


--
-- Name: detection_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.detection_rules (
    rule_id integer NOT NULL,
    name text NOT NULL,
    description text,
    source text,
    rule_key text,
    version integer DEFAULT 1 NOT NULL,
    mitre_tactic text,
    mitre_technique text,
    parent_rule_id integer,
    stage text DEFAULT 'active'::text NOT NULL,
    rule_format text DEFAULT 'json'::text NOT NULL,
    severity text DEFAULT 'medium'::text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    definition_yaml text,
    definition_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_tested_at timestamp with time zone,
    last_test_matches integer,
    CONSTRAINT detection_rules_rule_format_check CHECK ((rule_format = ANY (ARRAY['json'::text, 'yaml'::text, 'sigma'::text]))),
    CONSTRAINT detection_rules_severity_check CHECK ((severity = ANY (ARRAY['critical'::text, 'high'::text, 'medium'::text, 'low'::text, 'info'::text]))),
    CONSTRAINT detection_rules_stage_check CHECK ((stage = ANY (ARRAY['draft'::text, 'canary'::text, 'active'::text])))
);


--
-- Name: detection_rules_rule_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.detection_rules_rule_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: detection_rules_rule_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.detection_rules_rule_id_seq OWNED BY public.detection_rules.rule_id;


--
-- Name: finding_ai_explanations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_ai_explanations (
    id integer NOT NULL,
    finding_id integer NOT NULL,
    explanation_text text NOT NULL,
    remediation_patch text,
    provider text NOT NULL,
    model text NOT NULL,
    generated_by text,
    generated_at timestamp with time zone DEFAULT now() NOT NULL,
    context_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    org_id text DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id'::text, true), ''::text), 'default'::text) NOT NULL
);

ALTER TABLE ONLY public.finding_ai_explanations FORCE ROW LEVEL SECURITY;


--
-- Name: finding_ai_explanations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.finding_ai_explanations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: finding_ai_explanations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.finding_ai_explanations_id_seq OWNED BY public.finding_ai_explanations.id;


--
-- Name: finding_risk_labels; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_risk_labels (
    id integer NOT NULL,
    finding_id integer NOT NULL,
    label text NOT NULL,
    source text DEFAULT 'analyst'::text NOT NULL,
    note text,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT finding_risk_labels_label_check CHECK ((label = ANY (ARRAY['incident_worthy'::text, 'benign'::text]))),
    CONSTRAINT finding_risk_labels_source_check CHECK ((source = ANY (ARRAY['analyst'::text, 'incident_linked'::text, 'accepted_risk'::text, 'imported'::text])))
);


--
-- Name: finding_risk_labels_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.finding_risk_labels_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: finding_risk_labels_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.finding_risk_labels_id_seq OWNED BY public.finding_risk_labels.id;


--
-- Name: findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.findings (
    finding_id integer NOT NULL,
    asset_id integer,
    "time" timestamp with time zone DEFAULT now(),
    category text,
    title text NOT NULL,
    severity text NOT NULL,
    confidence text NOT NULL,
    evidence text,
    remediation text,
    finding_key text,
    first_seen timestamp with time zone,
    last_seen timestamp with time zone,
    status text DEFAULT 'open'::text,
    source text,
    vulnerability_id text,
    package_ecosystem text,
    package_name text,
    package_version text,
    fixed_version text,
    scanner_metadata_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    accepted_risk_at timestamp with time zone,
    accepted_risk_expires_at timestamp with time zone,
    accepted_risk_reason text,
    accepted_risk_by text,
    risk_score integer,
    risk_level text,
    risk_factors_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    org_id text DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id'::text, true), ''::text), 'default'::text) NOT NULL
);

ALTER TABLE ONLY public.findings FORCE ROW LEVEL SECURITY;


--
-- Name: findings_finding_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.findings_finding_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: findings_finding_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.findings_finding_id_seq OWNED BY public.findings.finding_id;


--
-- Name: incident_ai_summaries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.incident_ai_summaries (
    id integer NOT NULL,
    incident_id integer NOT NULL,
    summary_text text NOT NULL,
    provider text NOT NULL,
    model text NOT NULL,
    generated_by text,
    generated_at timestamp with time zone DEFAULT now() NOT NULL,
    context_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    org_id text DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id'::text, true), ''::text), 'default'::text) NOT NULL
);

ALTER TABLE ONLY public.incident_ai_summaries FORCE ROW LEVEL SECURITY;


--
-- Name: incident_ai_summaries_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.incident_ai_summaries_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: incident_ai_summaries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.incident_ai_summaries_id_seq OWNED BY public.incident_ai_summaries.id;


--
-- Name: incident_alerts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.incident_alerts (
    incident_id integer NOT NULL,
    asset_key text NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    added_by text,
    alert_id bigint,
    org_id text DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id'::text, true), ''::text), 'default'::text) NOT NULL
);

ALTER TABLE ONLY public.incident_alerts FORCE ROW LEVEL SECURITY;


--
-- Name: incident_auto_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.incident_auto_rules (
    auto_rule_id integer NOT NULL,
    name text NOT NULL,
    description text,
    enabled boolean DEFAULT true NOT NULL,
    severity_threshold text DEFAULT 'high'::text NOT NULL,
    window_minutes integer DEFAULT 15 NOT NULL,
    min_alerts integer DEFAULT 2 NOT NULL,
    require_distinct_sources boolean DEFAULT false NOT NULL,
    incident_severity text DEFAULT 'high'::text NOT NULL,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT incident_auto_rules_incident_severity_check CHECK ((incident_severity = ANY (ARRAY['critical'::text, 'high'::text, 'medium'::text, 'low'::text, 'info'::text]))),
    CONSTRAINT incident_auto_rules_severity_threshold_check CHECK ((severity_threshold = ANY (ARRAY['critical'::text, 'high'::text, 'medium'::text, 'low'::text, 'info'::text])))
);


--
-- Name: incident_auto_rules_auto_rule_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.incident_auto_rules_auto_rule_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: incident_auto_rules_auto_rule_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.incident_auto_rules_auto_rule_id_seq OWNED BY public.incident_auto_rules.auto_rule_id;


--
-- Name: incident_checklist_items; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.incident_checklist_items (
    item_id integer NOT NULL,
    incident_id integer NOT NULL,
    title text NOT NULL,
    done boolean DEFAULT false NOT NULL,
    done_by text,
    done_at timestamp with time zone,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: incident_checklist_items_item_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.incident_checklist_items_item_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: incident_checklist_items_item_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.incident_checklist_items_item_id_seq OWNED BY public.incident_checklist_items.item_id;


--
-- Name: incident_decisions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.incident_decisions (
    decision_id integer NOT NULL,
    incident_id integer NOT NULL,
    decision text NOT NULL,
    rationale text,
    decided_by text,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: incident_decisions_decision_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.incident_decisions_decision_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: incident_decisions_decision_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.incident_decisions_decision_id_seq OWNED BY public.incident_decisions.decision_id;


--
-- Name: incident_evidence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.incident_evidence (
    evidence_id integer NOT NULL,
    incident_id integer NOT NULL,
    evidence_type text NOT NULL,
    ref_id text NOT NULL,
    relation text DEFAULT 'linked'::text NOT NULL,
    summary text,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    added_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT incident_evidence_evidence_type_check CHECK ((evidence_type = ANY (ARRAY['alert'::text, 'finding'::text, 'asset'::text, 'job'::text, 'ticket'::text, 'note'::text, 'event'::text, 'other'::text])))
);


--
-- Name: incident_evidence_evidence_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.incident_evidence_evidence_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: incident_evidence_evidence_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.incident_evidence_evidence_id_seq OWNED BY public.incident_evidence.evidence_id;


--
-- Name: incident_notes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.incident_notes (
    id integer NOT NULL,
    incident_id integer NOT NULL,
    event_type text NOT NULL,
    author text,
    body text,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    org_id text DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id'::text, true), ''::text), 'default'::text) NOT NULL
);

ALTER TABLE ONLY public.incident_notes FORCE ROW LEVEL SECURITY;


--
-- Name: incident_notes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.incident_notes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: incident_notes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.incident_notes_id_seq OWNED BY public.incident_notes.id;


--
-- Name: incident_watchers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.incident_watchers (
    incident_id integer NOT NULL,
    username text NOT NULL,
    added_by text,
    added_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: incidents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.incidents (
    id integer NOT NULL,
    incident_key text,
    title text NOT NULL,
    severity text DEFAULT 'medium'::text NOT NULL,
    status text DEFAULT 'new'::text NOT NULL,
    assigned_to text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    closed_at timestamp with time zone,
    sla_due_at timestamp with time zone,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    org_id text DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id'::text, true), ''::text), 'default'::text) NOT NULL
);

ALTER TABLE ONLY public.incidents FORCE ROW LEVEL SECURITY;


--
-- Name: incidents_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.incidents_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: incidents_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.incidents_id_seq OWNED BY public.incidents.id;


--
-- Name: job_ai_triages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.job_ai_triages (
    id integer NOT NULL,
    job_id integer NOT NULL,
    triage_text text NOT NULL,
    provider text NOT NULL,
    model text NOT NULL,
    generated_by text,
    generated_at timestamp with time zone DEFAULT now() NOT NULL,
    context_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    org_id text DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id'::text, true), ''::text), 'default'::text) NOT NULL
);

ALTER TABLE ONLY public.job_ai_triages FORCE ROW LEVEL SECURITY;


--
-- Name: job_ai_triages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.job_ai_triages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: job_ai_triages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.job_ai_triages_id_seq OWNED BY public.job_ai_triages.id;


--
-- Name: maintenance_windows; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.maintenance_windows (
    id integer NOT NULL,
    asset_key text NOT NULL,
    start_at timestamp with time zone NOT NULL,
    end_at timestamp with time zone NOT NULL,
    reason text,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: maintenance_windows_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.maintenance_windows_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: maintenance_windows_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.maintenance_windows_id_seq OWNED BY public.maintenance_windows.id;


--
-- Name: platform_api_runtime_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.platform_api_runtime_snapshots (
    snapshot_id bigint NOT NULL,
    captured_at timestamp with time zone DEFAULT now() NOT NULL,
    source text DEFAULT 'api_runtime'::text NOT NULL,
    service_name text DEFAULT 'secplat-api'::text NOT NULL,
    service_instance_id text NOT NULL,
    request_count bigint DEFAULT 0 NOT NULL,
    server_error_count bigint DEFAULT 0 NOT NULL,
    api_availability double precision,
    api_p95_latency_ms double precision
);


--
-- Name: platform_api_runtime_snapshots_snapshot_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.platform_api_runtime_snapshots_snapshot_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: platform_api_runtime_snapshots_snapshot_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.platform_api_runtime_snapshots_snapshot_id_seq OWNED BY public.platform_api_runtime_snapshots.snapshot_id;


--
-- Name: platform_sli_samples; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.platform_sli_samples (
    sample_id bigint NOT NULL,
    captured_at timestamp with time zone DEFAULT now() NOT NULL,
    window_hours integer DEFAULT 24 NOT NULL,
    source text DEFAULT 'platform_runtime'::text NOT NULL,
    api_availability double precision,
    api_p95_latency_ms double precision,
    ingestion_visibility_seconds double precision,
    alert_creation_seconds double precision,
    background_job_freshness_minutes double precision
);


--
-- Name: platform_sli_samples_sample_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.platform_sli_samples_sample_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: platform_sli_samples_sample_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.platform_sli_samples_sample_id_seq OWNED BY public.platform_sli_samples.sample_id;


--
-- Name: policy_bundles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.policy_bundles (
    id integer NOT NULL,
    name text NOT NULL,
    description text,
    definition text NOT NULL,
    status text DEFAULT 'draft'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    approved_at timestamp with time zone,
    approved_by text,
    org_id text DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id'::text, true), ''::text), 'default'::text) NOT NULL,
    CONSTRAINT policy_bundles_status_check CHECK ((status = ANY (ARRAY['draft'::text, 'approved'::text])))
);

ALTER TABLE ONLY public.policy_bundles FORCE ROW LEVEL SECURITY;


--
-- Name: policy_bundles_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.policy_bundles_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: policy_bundles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.policy_bundles_id_seq OWNED BY public.policy_bundles.id;


--
-- Name: policy_evaluation_ai_summaries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.policy_evaluation_ai_summaries (
    id integer NOT NULL,
    evaluation_id integer NOT NULL,
    summary_text text NOT NULL,
    provider text NOT NULL,
    model text NOT NULL,
    generated_by text,
    generated_at timestamp with time zone DEFAULT now() NOT NULL,
    context_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    org_id text DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id'::text, true), ''::text), 'default'::text) NOT NULL
);

ALTER TABLE ONLY public.policy_evaluation_ai_summaries FORCE ROW LEVEL SECURITY;


--
-- Name: policy_evaluation_ai_summaries_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.policy_evaluation_ai_summaries_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: policy_evaluation_ai_summaries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.policy_evaluation_ai_summaries_id_seq OWNED BY public.policy_evaluation_ai_summaries.id;


--
-- Name: policy_evaluation_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.policy_evaluation_runs (
    id integer NOT NULL,
    bundle_id integer NOT NULL,
    evaluated_at timestamp with time zone DEFAULT now() NOT NULL,
    evaluated_by text,
    bundle_approved_by text,
    score double precision,
    violations_count integer DEFAULT 0 NOT NULL,
    result_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    org_id text DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id'::text, true), ''::text), 'default'::text) NOT NULL
);

ALTER TABLE ONLY public.policy_evaluation_runs FORCE ROW LEVEL SECURITY;


--
-- Name: policy_evaluation_runs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.policy_evaluation_runs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: policy_evaluation_runs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.policy_evaluation_runs_id_seq OWNED BY public.policy_evaluation_runs.id;


--
-- Name: posture_anomalies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.posture_anomalies (
    id integer NOT NULL,
    detected_at timestamp with time zone DEFAULT now() NOT NULL,
    metric text NOT NULL,
    severity text NOT NULL,
    current_value double precision,
    baseline_mean double precision,
    baseline_std double precision,
    z_score double precision,
    window_size integer DEFAULT 0 NOT NULL,
    context_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT posture_anomalies_severity_check CHECK ((severity = ANY (ARRAY['low'::text, 'medium'::text, 'high'::text])))
);


--
-- Name: posture_anomalies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.posture_anomalies_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: posture_anomalies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.posture_anomalies_id_seq OWNED BY public.posture_anomalies.id;


--
-- Name: posture_report_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.posture_report_snapshots (
    id integer NOT NULL,
    period text DEFAULT '24h'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    uptime_pct double precision DEFAULT 0 NOT NULL,
    posture_score_avg double precision,
    avg_latency_ms double precision,
    total_assets integer DEFAULT 0 NOT NULL,
    green integer DEFAULT 0 NOT NULL,
    amber integer DEFAULT 0 NOT NULL,
    red integer DEFAULT 0 NOT NULL,
    top_incidents jsonb DEFAULT '[]'::jsonb NOT NULL
);


--
-- Name: posture_report_snapshots_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.posture_report_snapshots_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: posture_report_snapshots_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.posture_report_snapshots_id_seq OWNED BY public.posture_report_snapshots.id;


--
-- Name: risk_entity_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.risk_entity_snapshots (
    snapshot_id bigint NOT NULL,
    entity_type text NOT NULL,
    entity_key text NOT NULL,
    entity_name text,
    snapshot_date date NOT NULL,
    score integer NOT NULL,
    level text NOT NULL,
    drivers_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    metadata_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT risk_entity_snapshots_entity_type_check CHECK ((entity_type = ANY (ARRAY['asset'::text, 'incident'::text, 'environment'::text]))),
    CONSTRAINT risk_entity_snapshots_level_check CHECK ((level = ANY (ARRAY['critical'::text, 'high'::text, 'medium'::text, 'low'::text]))),
    CONSTRAINT risk_entity_snapshots_score_check CHECK (((score >= 0) AND (score <= 100)))
);


--
-- Name: risk_entity_snapshots_snapshot_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.risk_entity_snapshots_snapshot_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: risk_entity_snapshots_snapshot_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.risk_entity_snapshots_snapshot_id_seq OWNED BY public.risk_entity_snapshots.snapshot_id;


--
-- Name: risk_model_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.risk_model_snapshots (
    id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text,
    event_type text DEFAULT 'manual'::text NOT NULL,
    model_signature text,
    artifact_path text NOT NULL,
    threshold double precision NOT NULL,
    recommended_threshold double precision,
    dataset_size integer,
    positive_labels integer,
    negative_labels integer,
    accuracy double precision,
    "precision" double precision,
    recall double precision,
    f1 double precision,
    auc double precision,
    brier_score double precision,
    test_auc double precision,
    drift_psi double precision,
    summary_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT risk_model_snapshots_event_type_check CHECK ((event_type = ANY (ARRAY['train'::text, 'manual'::text])))
);


--
-- Name: risk_model_snapshots_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.risk_model_snapshots_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: risk_model_snapshots_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.risk_model_snapshots_id_seq OWNED BY public.risk_model_snapshots.id;


--
-- Name: scan_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scan_jobs (
    job_id integer NOT NULL,
    job_type text NOT NULL,
    target_asset_id integer,
    requested_by text,
    status text DEFAULT 'queued'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    error text,
    log_output text,
    retry_count integer DEFAULT 0 NOT NULL,
    claimed_by text,
    claim_token text,
    last_heartbeat_at timestamp with time zone,
    job_params_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    org_id text DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id'::text, true), ''::text), 'default'::text) NOT NULL,
    CONSTRAINT scan_jobs_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'running'::text, 'done'::text, 'failed'::text])))
);

ALTER TABLE ONLY public.scan_jobs FORCE ROW LEVEL SECURITY;


--
-- Name: scan_jobs_job_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.scan_jobs_job_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: scan_jobs_job_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.scan_jobs_job_id_seq OWNED BY public.scan_jobs.job_id;


--
-- Name: security_alerts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.security_alerts (
    alert_id bigint NOT NULL,
    alert_key text NOT NULL,
    dedupe_key text NOT NULL,
    source text NOT NULL,
    alert_type text DEFAULT 'detection'::text NOT NULL,
    asset_id integer,
    asset_key text,
    severity text DEFAULT 'medium'::text NOT NULL,
    status text DEFAULT 'firing'::text NOT NULL,
    title text NOT NULL,
    description text,
    event_count integer DEFAULT 1 NOT NULL,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    acknowledged_by text,
    acknowledged_at timestamp with time zone,
    suppression_reason text,
    suppressed_until timestamp with time zone,
    resolved_by text,
    resolved_at timestamp with time zone,
    assigned_to text,
    ti_match boolean DEFAULT false NOT NULL,
    ti_source text,
    mitre_techniques jsonb DEFAULT '[]'::jsonb NOT NULL,
    payload_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    context_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    org_id text DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id'::text, true), ''::text), 'default'::text) NOT NULL,
    CONSTRAINT security_alerts_severity_check CHECK ((severity = ANY (ARRAY['critical'::text, 'high'::text, 'medium'::text, 'low'::text, 'info'::text]))),
    CONSTRAINT security_alerts_status_check CHECK ((status = ANY (ARRAY['firing'::text, 'acked'::text, 'suppressed'::text, 'resolved'::text])))
);

ALTER TABLE ONLY public.security_alerts FORCE ROW LEVEL SECURITY;


--
-- Name: security_alerts_alert_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.security_alerts_alert_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: security_alerts_alert_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.security_alerts_alert_id_seq OWNED BY public.security_alerts.alert_id;


--
-- Name: security_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.security_events (
    event_id bigint NOT NULL,
    source text NOT NULL,
    event_type text DEFAULT 'event'::text NOT NULL,
    asset_id integer,
    asset_key text,
    collector text,
    ingest_job_id integer,
    raw_offset bigint,
    raw_path text,
    severity integer,
    src_ip text,
    src_port integer,
    dst_ip text,
    dst_port integer,
    domain text,
    url text,
    protocol text,
    event_time timestamp with time zone DEFAULT now() NOT NULL,
    ingest_lag_seconds double precision,
    ti_match boolean DEFAULT false NOT NULL,
    ti_source text,
    mitre_techniques jsonb DEFAULT '[]'::jsonb NOT NULL,
    anomaly_score double precision,
    payload_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    org_id text DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id'::text, true), ''::text), 'default'::text) NOT NULL
);

ALTER TABLE ONLY public.security_events FORCE ROW LEVEL SECURITY;


--
-- Name: security_events_event_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.security_events_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: security_events_event_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.security_events_event_id_seq OWNED BY public.security_events.event_id;


--
-- Name: suppression_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.suppression_rules (
    id integer NOT NULL,
    scope text NOT NULL,
    scope_value text,
    starts_at timestamp with time zone NOT NULL,
    ends_at timestamp with time zone NOT NULL,
    reason text,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT suppression_rules_scope_check CHECK ((scope = ANY (ARRAY['asset'::text, 'finding'::text, 'all'::text])))
);


--
-- Name: suppression_rules_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.suppression_rules_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: suppression_rules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.suppression_rules_id_seq OWNED BY public.suppression_rules.id;


--
-- Name: threat_ioc_asset_matches; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_ioc_asset_matches (
    id integer NOT NULL,
    threat_ioc_id integer NOT NULL,
    asset_id integer NOT NULL,
    asset_key text NOT NULL,
    match_field text NOT NULL,
    matched_value text NOT NULL,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL
);


--
-- Name: threat_ioc_asset_matches_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.threat_ioc_asset_matches_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: threat_ioc_asset_matches_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.threat_ioc_asset_matches_id_seq OWNED BY public.threat_ioc_asset_matches.id;


--
-- Name: threat_ioc_campaigns; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_ioc_campaigns (
    campaign_id bigint NOT NULL,
    campaign_tag text NOT NULL,
    title text NOT NULL,
    description text,
    confidence_weight double precision DEFAULT 1.0 NOT NULL,
    source_priority integer DEFAULT 50 NOT NULL,
    confidence_label text DEFAULT 'medium'::text NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: threat_ioc_campaigns_campaign_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.threat_ioc_campaigns_campaign_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: threat_ioc_campaigns_campaign_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.threat_ioc_campaigns_campaign_id_seq OWNED BY public.threat_ioc_campaigns.campaign_id;


--
-- Name: threat_ioc_sightings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_ioc_sightings (
    sighting_id bigint NOT NULL,
    threat_ioc_id integer NOT NULL,
    asset_id integer,
    asset_key text NOT NULL,
    match_field text NOT NULL,
    matched_value text NOT NULL,
    source_event_id bigint,
    source_event_ref text,
    source_tool text,
    sighted_at timestamp with time zone DEFAULT now() NOT NULL,
    context_json jsonb DEFAULT '{}'::jsonb NOT NULL
);


--
-- Name: threat_ioc_sightings_sighting_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.threat_ioc_sightings_sighting_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: threat_ioc_sightings_sighting_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.threat_ioc_sightings_sighting_id_seq OWNED BY public.threat_ioc_sightings.sighting_id;


--
-- Name: threat_iocs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_iocs (
    id integer NOT NULL,
    source text NOT NULL,
    indicator text NOT NULL,
    indicator_type text NOT NULL,
    feed_url text,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    confidence_score double precision DEFAULT 0.6 NOT NULL,
    confidence_label text DEFAULT 'medium'::text NOT NULL,
    source_priority integer DEFAULT 50 NOT NULL,
    campaign_tag text,
    expires_at timestamp with time zone,
    last_match_count integer DEFAULT 0 NOT NULL,
    CONSTRAINT threat_iocs_indicator_type_check CHECK ((indicator_type = ANY (ARRAY['ip'::text, 'domain'::text])))
);


--
-- Name: threat_iocs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.threat_iocs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: threat_iocs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.threat_iocs_id_seq OWNED BY public.threat_iocs.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id integer NOT NULL,
    username text NOT NULL,
    role text DEFAULT 'viewer'::text NOT NULL,
    password_hash text,
    disabled boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT users_role_check CHECK ((role = ANY (ARRAY['viewer'::text, 'analyst'::text, 'admin'::text])))
);


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: ai_feedback feedback_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_feedback ALTER COLUMN feedback_id SET DEFAULT nextval('public.ai_feedback_feedback_id_seq'::regclass);


--
-- Name: ai_summary_versions version_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_summary_versions ALTER COLUMN version_id SET DEFAULT nextval('public.ai_summary_versions_version_id_seq'::regclass);


--
-- Name: alert_ai_guidance id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_ai_guidance ALTER COLUMN id SET DEFAULT nextval('public.alert_ai_guidance_id_seq'::regclass);


--
-- Name: asset_ai_diagnoses id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_ai_diagnoses ALTER COLUMN id SET DEFAULT nextval('public.asset_ai_diagnoses_id_seq'::regclass);


--
-- Name: asset_anomaly_scores id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_anomaly_scores ALTER COLUMN id SET DEFAULT nextval('public.asset_anomaly_scores_id_seq'::regclass);


--
-- Name: assets asset_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets ALTER COLUMN asset_id SET DEFAULT nextval('public.assets_asset_id_seq'::regclass);


--
-- Name: attack_lab_runs run_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_lab_runs ALTER COLUMN run_id SET DEFAULT nextval('public.attack_lab_runs_run_id_seq'::regclass);


--
-- Name: attack_surface_certificates cert_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_certificates ALTER COLUMN cert_id SET DEFAULT nextval('public.attack_surface_certificates_cert_id_seq'::regclass);


--
-- Name: attack_surface_discovery_runs run_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_discovery_runs ALTER COLUMN run_id SET DEFAULT nextval('public.attack_surface_discovery_runs_run_id_seq'::regclass);


--
-- Name: attack_surface_drift_events event_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_drift_events ALTER COLUMN event_id SET DEFAULT nextval('public.attack_surface_drift_events_event_id_seq'::regclass);


--
-- Name: attack_surface_hosts host_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_hosts ALTER COLUMN host_id SET DEFAULT nextval('public.attack_surface_hosts_host_id_seq'::regclass);


--
-- Name: attack_surface_relationships relationship_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_relationships ALTER COLUMN relationship_id SET DEFAULT nextval('public.attack_surface_relationships_relationship_id_seq'::regclass);


--
-- Name: attack_surface_services service_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_services ALTER COLUMN service_id SET DEFAULT nextval('public.attack_surface_services_service_id_seq'::regclass);


--
-- Name: audit_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events ALTER COLUMN id SET DEFAULT nextval('public.audit_events_id_seq'::regclass);


--
-- Name: auth_refresh_tokens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_refresh_tokens ALTER COLUMN id SET DEFAULT nextval('public.auth_refresh_tokens_id_seq'::regclass);


--
-- Name: automation_approvals approval_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.automation_approvals ALTER COLUMN approval_id SET DEFAULT nextval('public.automation_approvals_approval_id_seq'::regclass);


--
-- Name: automation_playbooks playbook_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.automation_playbooks ALTER COLUMN playbook_id SET DEFAULT nextval('public.automation_playbooks_playbook_id_seq'::regclass);


--
-- Name: automation_rollbacks rollback_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.automation_rollbacks ALTER COLUMN rollback_id SET DEFAULT nextval('public.automation_rollbacks_rollback_id_seq'::regclass);


--
-- Name: automation_run_actions run_action_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.automation_run_actions ALTER COLUMN run_action_id SET DEFAULT nextval('public.automation_run_actions_run_action_id_seq'::regclass);


--
-- Name: automation_runs run_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.automation_runs ALTER COLUMN run_id SET DEFAULT nextval('public.automation_runs_run_id_seq'::regclass);


--
-- Name: detection_correlation_rules correlation_rule_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_correlation_rules ALTER COLUMN correlation_rule_id SET DEFAULT nextval('public.detection_correlation_rules_correlation_rule_id_seq'::regclass);


--
-- Name: detection_correlation_runs run_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_correlation_runs ALTER COLUMN run_id SET DEFAULT nextval('public.detection_correlation_runs_run_id_seq'::regclass);


--
-- Name: detection_rule_runs run_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rule_runs ALTER COLUMN run_id SET DEFAULT nextval('public.detection_rule_runs_run_id_seq'::regclass);


--
-- Name: detection_rules rule_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rules ALTER COLUMN rule_id SET DEFAULT nextval('public.detection_rules_rule_id_seq'::regclass);


--
-- Name: finding_ai_explanations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_ai_explanations ALTER COLUMN id SET DEFAULT nextval('public.finding_ai_explanations_id_seq'::regclass);


--
-- Name: finding_risk_labels id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_risk_labels ALTER COLUMN id SET DEFAULT nextval('public.finding_risk_labels_id_seq'::regclass);


--
-- Name: findings finding_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings ALTER COLUMN finding_id SET DEFAULT nextval('public.findings_finding_id_seq'::regclass);


--
-- Name: incident_ai_summaries id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_ai_summaries ALTER COLUMN id SET DEFAULT nextval('public.incident_ai_summaries_id_seq'::regclass);


--
-- Name: incident_auto_rules auto_rule_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_auto_rules ALTER COLUMN auto_rule_id SET DEFAULT nextval('public.incident_auto_rules_auto_rule_id_seq'::regclass);


--
-- Name: incident_checklist_items item_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_checklist_items ALTER COLUMN item_id SET DEFAULT nextval('public.incident_checklist_items_item_id_seq'::regclass);


--
-- Name: incident_decisions decision_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_decisions ALTER COLUMN decision_id SET DEFAULT nextval('public.incident_decisions_decision_id_seq'::regclass);


--
-- Name: incident_evidence evidence_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_evidence ALTER COLUMN evidence_id SET DEFAULT nextval('public.incident_evidence_evidence_id_seq'::regclass);


--
-- Name: incident_notes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_notes ALTER COLUMN id SET DEFAULT nextval('public.incident_notes_id_seq'::regclass);


--
-- Name: incidents id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incidents ALTER COLUMN id SET DEFAULT nextval('public.incidents_id_seq'::regclass);


--
-- Name: job_ai_triages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.job_ai_triages ALTER COLUMN id SET DEFAULT nextval('public.job_ai_triages_id_seq'::regclass);


--
-- Name: maintenance_windows id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.maintenance_windows ALTER COLUMN id SET DEFAULT nextval('public.maintenance_windows_id_seq'::regclass);


--
-- Name: platform_api_runtime_snapshots snapshot_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_api_runtime_snapshots ALTER COLUMN snapshot_id SET DEFAULT nextval('public.platform_api_runtime_snapshots_snapshot_id_seq'::regclass);


--
-- Name: platform_sli_samples sample_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_sli_samples ALTER COLUMN sample_id SET DEFAULT nextval('public.platform_sli_samples_sample_id_seq'::regclass);


--
-- Name: policy_bundles id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policy_bundles ALTER COLUMN id SET DEFAULT nextval('public.policy_bundles_id_seq'::regclass);


--
-- Name: policy_evaluation_ai_summaries id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policy_evaluation_ai_summaries ALTER COLUMN id SET DEFAULT nextval('public.policy_evaluation_ai_summaries_id_seq'::regclass);


--
-- Name: policy_evaluation_runs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policy_evaluation_runs ALTER COLUMN id SET DEFAULT nextval('public.policy_evaluation_runs_id_seq'::regclass);


--
-- Name: posture_anomalies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.posture_anomalies ALTER COLUMN id SET DEFAULT nextval('public.posture_anomalies_id_seq'::regclass);


--
-- Name: posture_report_snapshots id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.posture_report_snapshots ALTER COLUMN id SET DEFAULT nextval('public.posture_report_snapshots_id_seq'::regclass);


--
-- Name: risk_entity_snapshots snapshot_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.risk_entity_snapshots ALTER COLUMN snapshot_id SET DEFAULT nextval('public.risk_entity_snapshots_snapshot_id_seq'::regclass);


--
-- Name: risk_model_snapshots id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.risk_model_snapshots ALTER COLUMN id SET DEFAULT nextval('public.risk_model_snapshots_id_seq'::regclass);


--
-- Name: scan_jobs job_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_jobs ALTER COLUMN job_id SET DEFAULT nextval('public.scan_jobs_job_id_seq'::regclass);


--
-- Name: security_alerts alert_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_alerts ALTER COLUMN alert_id SET DEFAULT nextval('public.security_alerts_alert_id_seq'::regclass);


--
-- Name: security_events event_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events ALTER COLUMN event_id SET DEFAULT nextval('public.security_events_event_id_seq'::regclass);


--
-- Name: suppression_rules id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.suppression_rules ALTER COLUMN id SET DEFAULT nextval('public.suppression_rules_id_seq'::regclass);


--
-- Name: threat_ioc_asset_matches id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_ioc_asset_matches ALTER COLUMN id SET DEFAULT nextval('public.threat_ioc_asset_matches_id_seq'::regclass);


--
-- Name: threat_ioc_campaigns campaign_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_ioc_campaigns ALTER COLUMN campaign_id SET DEFAULT nextval('public.threat_ioc_campaigns_campaign_id_seq'::regclass);


--
-- Name: threat_ioc_sightings sighting_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_ioc_sightings ALTER COLUMN sighting_id SET DEFAULT nextval('public.threat_ioc_sightings_sighting_id_seq'::regclass);


--
-- Name: threat_iocs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_iocs ALTER COLUMN id SET DEFAULT nextval('public.threat_iocs_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Data for Name: ai_feedback; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.ai_feedback (feedback_id, entity_type, entity_key, version_id, feedback, comment, context_json, created_by, created_at) FROM stdin;
\.


--
-- Data for Name: ai_summary_versions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.ai_summary_versions (version_id, entity_type, entity_key, version_no, content_text, provider, model, generated_by, source_type, context_json, evidence_json, created_at) FROM stdin;
\.


--
-- Data for Name: alert_ai_guidance; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.alert_ai_guidance (id, asset_key, guidance_text, recommended_action, urgency, provider, model, generated_by, generated_at, context_signature, context_json, org_id) FROM stdin;
\.


--
-- Data for Name: alert_states; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.alert_states (asset_key, state, ack_reason, acked_by, acked_at, suppressed_until, assigned_to, resolved_at, updated_at) FROM stdin;
\.


--
-- Data for Name: asset_ai_diagnoses; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.asset_ai_diagnoses (id, asset_key, diagnosis_text, provider, model, generated_by, generated_at, context_json, org_id) FROM stdin;
\.


--
-- Data for Name: asset_anomaly_scores; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.asset_anomaly_scores (id, asset_key, computed_at, anomaly_score, baseline_mean, baseline_std, current_value, source_breakdown, context_json) FROM stdin;
\.


--
-- Data for Name: assets; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.assets (asset_id, asset_key, type, name, owner, owner_team, owner_email, asset_type, environment, criticality, verified, verification_method, verification_token, address, port, is_active, tags, metadata, created_at, updated_at, org_id) FROM stdin;
\.


--
-- Data for Name: attack_lab_runs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.attack_lab_runs (run_id, task_type, target_asset_id, target_asset_key, target, status, requested_by, started_at, finished_at, error, output_json, created_at) FROM stdin;
\.


--
-- Data for Name: attack_surface_certificates; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.attack_surface_certificates (cert_id, run_id, host_id, asset_key, hostname, common_name, issuer, serial_number, fingerprint_sha256, not_before, not_after, discovered_at) FROM stdin;
\.


--
-- Data for Name: attack_surface_discovery_runs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.attack_surface_discovery_runs (run_id, status, requested_by, source_job_id, started_at, finished_at, error, metadata_json, summary_json) FROM stdin;
\.


--
-- Data for Name: attack_surface_drift_events; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.attack_surface_drift_events (event_id, run_id, event_type, severity, asset_key, hostname, domain, port, details_json, created_at) FROM stdin;
\.


--
-- Data for Name: attack_surface_exposures; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.attack_surface_exposures (asset_key, run_id, internet_exposed, open_port_count, open_management_ports, service_risk, exposure_score, exposure_level, details_json, updated_at) FROM stdin;
\.


--
-- Data for Name: attack_surface_hosts; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.attack_surface_hosts (host_id, run_id, asset_key, hostname, ip_address, internet_exposed, source, discovered_at) FROM stdin;
\.


--
-- Data for Name: attack_surface_relationships; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.attack_surface_relationships (relationship_id, source_asset_key, target_asset_key, relation_type, confidence, details_json, updated_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: attack_surface_services; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.attack_surface_services (service_id, run_id, host_id, asset_key, hostname, port, protocol, service_name, service_version, discovered_at) FROM stdin;
\.


--
-- Data for Name: audit_events; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.audit_events (id, created_at, action, user_name, asset_key, details, request_id) FROM stdin;
1	2026-04-04 13:01:54.869395+00	login	admin	\N	{"method": "password", "success": true, "actor_type": "user"}	b18b9d78-e8c4-4fe1-b7ee-93d56ebb532e
2	2026-04-04 13:03:57.661032+00	login	admin	\N	{"method": "password", "success": true, "actor_type": "user"}	7fb2b11d-783e-4bef-9452-90cb8f368999
3	2026-04-04 13:04:36.436423+00	login	admin	\N	{"method": "password", "success": true, "actor_type": "user"}	b6772a3c-0bbe-444d-af36-23ec7a68a19e
4	2026-04-04 13:04:45.422512+00	login	scanner-service	\N	{"method": "password", "success": true, "actor_type": "service"}	75a017da-9e51-4d64-8422-dfc3027cbcc8
5	2026-04-04 13:04:54.161933+00	job.create	admin	\N	{"job_id": 2, "job_type": "score_recompute", "requested_by": "phase5-maintenance", "target_asset_id": null}	04889e07-1236-4125-9da3-62649c40dba4
6	2026-04-04 13:04:54.402094+00	login	scanner-service	\N	{"method": "password", "success": true, "actor_type": "service"}	d26e1818-af1d-4fb1-9c55-0de9575d96dd
7	2026-04-04 13:04:53.233271+00	job.execute	scanner-service	\N	{"job_id": 2, "job_type": "score_recompute", "requested_by": "phase5-maintenance"}	04889e07-1236-4125-9da3-62649c40dba4
8	2026-04-04 13:08:07.124655+00	login	admin	\N	{"method": "password", "success": true, "actor_type": "user"}	9232c158-6c9e-4788-8d68-376cdc52e101
9	2026-04-04 13:08:07.173971+00	login	scanner-service	\N	{"method": "password", "success": true, "actor_type": "service"}	23270176-c94a-4e14-9285-8e321d70a6ca
10	2026-04-04 13:08:07.998656+00	job.create	admin	\N	{"job_id": 3, "job_type": "score_recompute", "requested_by": "manual-phase5-debug", "target_asset_id": null}	45872d1f-8025-4997-9280-bd1ab5d05611
11	2026-04-04 13:08:08.043232+00	login	scanner-service	\N	{"method": "password", "success": true, "actor_type": "service"}	f6ab25df-2d40-4bef-acaa-f31262f6707c
12	2026-04-04 13:08:08.693548+00	job.recover_stale	admin	\N	{"job_ids": [3], "recovered_count": 1, "running_stale_minutes": 30}	f5d7e973-d0c8-4e92-b337-11de7027bec0
13	2026-04-04 13:08:08.724256+00	job.execute	scanner-service	\N	{"job_id": 3, "job_type": "score_recompute", "requested_by": "manual-phase5-debug"}	f5d7e973-d0c8-4e92-b337-11de7027bec0
14	2026-04-04 13:08:28.786313+00	login	admin	\N	{"method": "password", "success": true, "actor_type": "user"}	7e8a73e5-e634-4a95-a5df-82f9efae2e98
15	2026-04-04 13:08:34.760691+00	login	scanner-service	\N	{"method": "password", "success": true, "actor_type": "service"}	44a16374-2091-4913-8fc6-86ac64192946
16	2026-04-04 13:08:42.501627+00	job.create	admin	\N	{"job_id": 5, "job_type": "score_recompute", "requested_by": "phase5-maintenance", "target_asset_id": null}	750a8e5b-0055-459b-b408-178e8765e50e
17	2026-04-04 13:08:42.549763+00	job.execute	scanner-service	\N	{"job_id": 5, "job_type": "score_recompute", "requested_by": "phase5-maintenance"}	750a8e5b-0055-459b-b408-178e8765e50e
18	2026-04-04 13:12:48.088465+00	login	admin	\N	{"method": "password", "success": true, "actor_type": "user"}	19e2872a-fd3b-4968-aa7f-0128252acb5f
19	2026-04-04 13:12:57.021303+00	login	scanner-service	\N	{"method": "password", "success": true, "actor_type": "service"}	5b72f4d5-2aea-44e4-82c8-f4f9fa904d3c
20	2026-04-04 13:15:55.319645+00	login	admin	\N	{"method": "password", "success": true, "actor_type": "user"}	80472933-3013-464e-8acb-19aaaa39d6d0
21	2026-04-04 13:16:02.494911+00	login	scanner-service	\N	{"method": "password", "success": true, "actor_type": "service"}	d8ffd0e5-c732-40b7-a785-38db55f58839
\.


--
-- Data for Name: auth_refresh_tokens; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.auth_refresh_tokens (id, token_hash, username, role, issued_at, expires_at, replaced_by_hash, revoked_at, revoked_reason, client_ip, user_agent) FROM stdin;
1	4ce03a5252ed79a135fcf6c7b02cfceff659d27a900f4afe7785db721a3d3278	admin	admin	2026-04-04 13:01:54.869395+00	2026-05-04 13:01:55.093532+00	\N	\N	\N	127.0.0.1	Python-urllib/3.13
2	e135b8e5f6c3301d1508a3308204ed34ef0b2018c6d2f7e8104a419b34e18417	admin	admin	2026-04-04 13:03:57.661032+00	2026-05-04 13:03:57.696117+00	\N	\N	\N	127.0.0.1	Python-urllib/3.13
3	2f3f7b1f9db2049d5f8610b6d0e2456ed2d81b77e3557868cadd6f2fd9c65984	admin	admin	2026-04-04 13:04:36.436423+00	2026-05-04 13:04:36.447257+00	\N	\N	\N	127.0.0.1	Python-urllib/3.13
4	5d39187b68371acb4f98fd3b42be6ba68d4b0d0065cca09e443f3f017954fdf4	scanner-service	analyst	2026-04-04 13:04:45.422512+00	2026-05-04 13:04:45.970953+00	\N	\N	\N	127.0.0.1	Python-urllib/3.13
5	d361f2f50e4ecf8f03938521abe5ac9af8cab66f7b974b2b4fc487c8f1606d68	scanner-service	analyst	2026-04-04 13:04:54.402094+00	2026-05-04 13:04:53.096531+00	\N	\N	\N	10.1.16.181	python-requests/2.32.4
6	d15ee5277760e9fc6817355c6cc76b6ab0085d59e0f8aca68a05479303d42207	admin	admin	2026-04-04 13:08:07.124655+00	2026-05-04 13:08:07.134845+00	\N	\N	\N	127.0.0.1	Python-urllib/3.13
7	d24ee05d7b49ca5eb5f2895dedd6892173d3863b2d40c8ea5e3614285dc611d5	scanner-service	analyst	2026-04-04 13:08:07.173971+00	2026-05-04 13:08:07.576398+00	\N	\N	\N	127.0.0.1	Python-urllib/3.13
8	186ee8a0c5ddf8963d0dda2e3ba33514cc134b5c43a6866289680af371cd5f30	scanner-service	analyst	2026-04-04 13:08:08.043232+00	2026-05-04 13:08:08.447711+00	\N	\N	\N	10.1.16.193	python-requests/2.32.4
9	20572b283596d930a4ba9fb53d1f2f85d37feb55bec99c8ff74cf02d0c702fa0	admin	admin	2026-04-04 13:08:28.786313+00	2026-05-04 13:08:28.796439+00	\N	\N	\N	127.0.0.1	Python-urllib/3.13
10	d6f4a2b84bf3f49e09d49be4c1549a3f72082418e07bad0ca52d85038a178e04	scanner-service	analyst	2026-04-04 13:08:34.760691+00	2026-05-04 13:08:35.17321+00	\N	\N	\N	127.0.0.1	Python-urllib/3.13
11	aa8b8b23e1b53ab3dd4bc5f100c5da77b92e055962ab59bffe8005ec653b91c8	admin	admin	2026-04-04 13:12:48.088465+00	2026-05-04 13:12:48.097233+00	\N	\N	\N	127.0.0.1	Python-urllib/3.13
12	2f4c0a499627f27067f4946f6677ffd4c753dd3fb89cd1f8663c5f1a9968aab4	scanner-service	analyst	2026-04-04 13:12:57.021303+00	2026-05-04 13:12:57.438975+00	\N	\N	\N	127.0.0.1	Python-urllib/3.13
13	66d830ae30a5c0e9e052cea207fabc6df443280f2a63fdf435c57c59f2425148	admin	admin	2026-04-04 13:15:55.319645+00	2026-05-04 13:15:55.337612+00	\N	\N	\N	127.0.0.1	Python-urllib/3.13
14	3a0d257907ab01c12aafa25424f1e44200c07be3e10a148ae4c614494e4c9200	scanner-service	analyst	2026-04-04 13:16:02.494911+00	2026-05-04 13:16:03.30817+00	\N	\N	\N	127.0.0.1	Python-urllib/3.13
\.


--
-- Data for Name: automation_approvals; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.automation_approvals (approval_id, run_action_id, required_role, risk_tier, status, requested_by, approved_by, rejected_by, reason, decision_note, created_at, decided_at) FROM stdin;
\.


--
-- Data for Name: automation_playbooks; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.automation_playbooks (playbook_id, title, description, trigger, conditions_json, actions_json, approval_required, rollback_steps_json, enabled, created_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: automation_rollbacks; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.automation_rollbacks (rollback_id, run_action_id, rollback_type, rollback_payload_json, status, requested_by, executed_by, created_at, executed_at, error) FROM stdin;
\.


--
-- Data for Name: automation_run_actions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.automation_run_actions (run_action_id, run_id, action_index, action_type, risk_tier, status, params_json, result_json, error, created_at, started_at, finished_at) FROM stdin;
\.


--
-- Data for Name: automation_runs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.automation_runs (run_id, playbook_id, trigger_source, trigger_payload_json, matched, status, requested_by, started_at, finished_at, error, summary_json) FROM stdin;
\.


--
-- Data for Name: detection_correlation_rules; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.detection_correlation_rules (correlation_rule_id, name, description, severity, enabled, group_by, window_minutes, min_distinct_sources, mitre_tactic, mitre_technique, definition_json, created_by, created_at, updated_at, last_run_at, last_match_count) FROM stdin;
\.


--
-- Data for Name: detection_correlation_runs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.detection_correlation_runs (run_id, correlation_rule_id, executed_by, run_mode, trigger_source, schedule_ref, lookback_minutes, window_start, window_end, matched_chains, alerts_created, snapshot_hash, snapshot_json, started_at, finished_at, error) FROM stdin;
\.


--
-- Data for Name: detection_rule_runs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.detection_rule_runs (run_id, rule_id, executed_by, lookback_hours, status, matches, run_mode, trigger_source, schedule_ref, create_alerts, snapshot_hash, snapshot_json, rule_version, rule_stage, window_start, window_end, started_at, finished_at, error, results_json) FROM stdin;
\.


--
-- Data for Name: detection_rules; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.detection_rules (rule_id, name, description, source, rule_key, version, mitre_tactic, mitre_technique, parent_rule_id, stage, rule_format, severity, enabled, definition_yaml, definition_json, created_by, created_at, updated_at, last_tested_at, last_test_matches) FROM stdin;
\.


--
-- Data for Name: finding_ai_explanations; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.finding_ai_explanations (id, finding_id, explanation_text, remediation_patch, provider, model, generated_by, generated_at, context_json, org_id) FROM stdin;
\.


--
-- Data for Name: finding_risk_labels; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.finding_risk_labels (id, finding_id, label, source, note, created_by, created_at) FROM stdin;
\.


--
-- Data for Name: findings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.findings (finding_id, asset_id, "time", category, title, severity, confidence, evidence, remediation, finding_key, first_seen, last_seen, status, source, vulnerability_id, package_ecosystem, package_name, package_version, fixed_version, scanner_metadata_json, accepted_risk_at, accepted_risk_expires_at, accepted_risk_reason, accepted_risk_by, risk_score, risk_level, risk_factors_json, org_id) FROM stdin;
\.


--
-- Data for Name: incident_ai_summaries; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.incident_ai_summaries (id, incident_id, summary_text, provider, model, generated_by, generated_at, context_json, org_id) FROM stdin;
\.


--
-- Data for Name: incident_alerts; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.incident_alerts (incident_id, asset_key, added_at, added_by, alert_id, org_id) FROM stdin;
\.


--
-- Data for Name: incident_auto_rules; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.incident_auto_rules (auto_rule_id, name, description, enabled, severity_threshold, window_minutes, min_alerts, require_distinct_sources, incident_severity, created_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: incident_checklist_items; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.incident_checklist_items (item_id, incident_id, title, done, done_by, done_at, created_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: incident_decisions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.incident_decisions (decision_id, incident_id, decision, rationale, decided_by, details, created_at) FROM stdin;
\.


--
-- Data for Name: incident_evidence; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.incident_evidence (evidence_id, incident_id, evidence_type, ref_id, relation, summary, details, added_by, created_at) FROM stdin;
\.


--
-- Data for Name: incident_notes; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.incident_notes (id, incident_id, event_type, author, body, details, created_at, org_id) FROM stdin;
\.


--
-- Data for Name: incident_watchers; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.incident_watchers (incident_id, username, added_by, added_at) FROM stdin;
\.


--
-- Data for Name: incidents; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.incidents (id, incident_key, title, severity, status, assigned_to, created_at, updated_at, resolved_at, closed_at, sla_due_at, metadata, org_id) FROM stdin;
\.


--
-- Data for Name: job_ai_triages; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.job_ai_triages (id, job_id, triage_text, provider, model, generated_by, generated_at, context_json, org_id) FROM stdin;
\.


--
-- Data for Name: maintenance_windows; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.maintenance_windows (id, asset_key, start_at, end_at, reason, created_by, created_at) FROM stdin;
\.


--
-- Data for Name: platform_api_runtime_snapshots; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.platform_api_runtime_snapshots (snapshot_id, captured_at, source, service_name, service_instance_id, request_count, server_error_count, api_availability, api_p95_latency_ms) FROM stdin;
1	2026-04-04 12:56:38.837185+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	2	1	0.5	110.356
2	2026-04-04 12:57:34.296536+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	16	3	0.8125	84.552
3	2026-04-04 12:58:29.821617+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	34	3	0.911765	163.498
4	2026-04-04 12:59:25.29752+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	52	3	0.942308	133.827
5	2026-04-04 13:00:20.759731+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	70	3	0.957143	114.902
6	2026-04-04 13:01:16.692451+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	88	3	0.965909	115.165
7	2026-04-04 13:02:12.420394+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	290	3	0.989655	114.902
8	2026-04-04 13:03:07.836153+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	309	7	0.977346	117.736
9	2026-04-04 13:04:03.256701+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	334	13	0.961078	119.983
10	2026-04-04 13:04:46.080791+00	platform_sli_current_capture	secplat-api	secplat-api-7648574685-kd6lx:1	352	13	0.963068	120.31
11	2026-04-04 13:04:48.693622+00	platform_sli_current_capture	secplat-api	secplat-api-7648574685-kd6lx:1	413	13	0.968523	112.422
12	2026-04-04 13:04:50.394566+00	platform_release_gate_capture	secplat-api	secplat-api-7648574685-kd6lx:1	414	13	0.968599	112.336
13	2026-04-04 13:04:58.709395+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	430	13	0.969767	114.902
14	2026-04-04 13:05:54.141744+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	448	13	0.970982	112.854
15	2026-04-04 13:06:49.553805+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	466	13	0.972103	110.936
16	2026-04-04 13:07:45.011299+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	484	13	0.97314	107.872
17	2026-04-04 13:08:35.541545+00	platform_sli_current_capture	secplat-api	secplat-api-7648574685-kd6lx:1	516	13	0.974806	112.163
18	2026-04-04 13:08:38.661186+00	platform_sli_current_capture	secplat-api	secplat-api-7648574685-kd6lx:1	577	13	0.97747	103.848
19	2026-04-04 13:08:40.424487+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	578	13	0.977509	103.837
20	2026-04-04 13:08:40.583266+00	platform_release_gate_capture	secplat-api	secplat-api-7648574685-kd6lx:1	578	13	0.977509	103.837
21	2026-04-04 13:09:35.823886+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	605	13	0.978512	101.557
22	2026-04-04 13:10:31.250589+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	623	13	0.979133	99.497
23	2026-04-04 13:11:26.675851+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	641	13	0.979719	99.692
24	2026-04-04 13:12:22.082794+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	659	13	0.980273	97.937
25	2026-04-04 13:12:57.550009+00	platform_sli_current_capture	secplat-api	secplat-api-7648574685-kd6lx:1	675	13	0.980741	100.831
26	2026-04-04 13:13:01.154665+00	platform_sli_current_capture	secplat-api	secplat-api-7648574685-kd6lx:1	738	13	0.982385	97.916
27	2026-04-04 13:13:01.313369+00	platform_sli_current_capture	secplat-api	secplat-api-7648574685-kd6lx:1	739	13	0.982409	97.858
28	2026-04-04 13:13:12.080134+00	platform_sli_current_capture	secplat-api	secplat-api-7648574685-kd6lx:1	982	13	0.986762	85.232
29	2026-04-04 13:13:12.204257+00	platform_sli_current_capture	secplat-api	secplat-api-7648574685-kd6lx:1	983	13	0.986775	85.213
30	2026-04-04 13:13:17.493532+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	1130	13	0.988496	81.346
31	2026-04-04 13:13:40.961224+00	platform_sli_current_capture	secplat-api	secplat-api-7648574685-kd6lx:1	1594	13	0.991844	73.236
32	2026-04-04 13:14:12.896446+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	1605	13	0.9919	73.493
33	2026-04-04 13:15:08.319134+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	1623	13	0.99199	72.917
34	2026-04-04 13:16:03.627046+00	platform_sli_current_capture	secplat-api	secplat-api-7648574685-kd6lx:1	1645	13	0.992097	72.797
35	2026-04-04 13:16:03.681469+00	platform_runtime_loop_capture	secplat-api	secplat-api-7648574685-kd6lx:1	1646	13	0.992102	72.737
36	2026-04-04 13:16:06.713775+00	platform_sli_current_capture	secplat-api	secplat-api-7648574685-kd6lx:1	1708	13	0.992389	70.844
37	2026-04-04 13:16:09.410711+00	platform_release_gate_capture	secplat-api	secplat-api-7648574685-kd6lx:1	1709	13	0.992393	70.797
\.


--
-- Data for Name: platform_sli_samples; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.platform_sli_samples (sample_id, captured_at, window_hours, source, api_availability, api_p95_latency_ms, ingestion_visibility_seconds, alert_creation_seconds, background_job_freshness_minutes) FROM stdin;
1	2026-04-04 12:56:38.857872+00	24	platform_runtime_loop	0.5	110.356	\N	\N	\N
2	2026-04-04 12:57:34.329263+00	24	platform_runtime_loop	0.857143	84.552	\N	\N	\N
3	2026-04-04 12:58:29.864988+00	24	platform_runtime_loop	0.9375	163.498	\N	\N	\N
4	2026-04-04 12:59:25.311201+00	24	platform_runtime_loop	0.96	133.827	\N	\N	\N
5	2026-04-04 13:00:20.766459+00	24	platform_runtime_loop	0.970588	114.902	\N	\N	\N
6	2026-04-04 13:01:16.813963+00	24	platform_runtime_loop	0.976744	115.165	\N	\N	\N
7	2026-04-04 13:02:12.4292+00	24	platform_runtime_loop	1	114.902	\N	\N	\N
8	2026-04-04 13:03:07.845516+00	24	platform_runtime_loop	0.985455	117.736	\N	\N	\N
9	2026-04-04 13:04:03.271099+00	24	platform_runtime_loop	0.964539	119.983	\N	\N	\N
10	2026-04-04 13:04:46.091597+00	1	platform_sli_current	0.964539	120.31	1	0	0.14889555
11	2026-04-04 13:04:50.404138+00	24	platform_release_gate_current	0.97093	112.336	1	0	0.22077123333333334
12	2026-04-04 13:04:58.726635+00	24	platform_runtime_loop	0.972222	114.902	1	0	0.35947951666666667
13	2026-04-04 13:05:54.151254+00	24	platform_runtime_loop	0.972222	112.854	1	0	1.2832231666666667
14	2026-04-04 13:06:49.570347+00	24	platform_runtime_loop	0.943182	110.936	1	0	2.206874716666667
15	2026-04-04 13:07:45.018829+00	24	platform_runtime_loop	0.965714	107.872	1	0	3.1310160833333334
16	2026-04-04 13:08:35.561948+00	1	platform_sli_current	1	112.163	1	0	0.10311008333333334
17	2026-04-04 13:08:40.431251+00	24	platform_runtime_loop	1	103.837	1	0	0.18426513333333333
18	2026-04-04 13:08:40.592437+00	24	platform_release_gate_current	1	103.837	1	0	0.18695156666666668
19	2026-04-04 13:09:35.835063+00	24	platform_runtime_loop	1	101.557	1	0	1.107662
20	2026-04-04 13:10:31.260696+00	24	platform_runtime_loop	1	99.497	1	0	2.03142255
21	2026-04-04 13:11:26.68193+00	24	platform_runtime_loop	1	99.692	1	0	2.9551097833333335
22	2026-04-04 13:12:22.097041+00	24	platform_runtime_loop	1	97.937	1	0	3.8786949666666666
23	2026-04-04 13:12:57.559018+00	1	platform_sli_current	1	100.831	1	0	0.14982855
24	2026-04-04 13:13:17.4996+00	24	platform_runtime_loop	1	81.346	1	0	0.4821715833333333
25	2026-04-04 13:13:40.967589+00	1	platform_sli_current	1	73.236	1	0	0.8733047333333334
26	2026-04-04 13:14:12.903482+00	24	platform_runtime_loop	1	73.493	1	0	1.4055696166666667
27	2026-04-04 13:15:08.323728+00	24	platform_runtime_loop	1	72.917	1	0	2.3292403833333335
28	2026-04-04 13:16:03.638045+00	1	platform_sli_current	1	72.797	1	0	0.12903986666666667
29	2026-04-04 13:16:03.690619+00	24	platform_runtime_loop	1	72.737	1	0	0.1299161
30	2026-04-04 13:16:06.724676+00	1	platform_sli_current	1	70.844	1	0	0.18048371666666665
31	2026-04-04 13:16:09.419139+00	24	platform_release_gate_current	1	70.797	1	0	0.22539143333333334
\.


--
-- Data for Name: policy_bundles; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.policy_bundles (id, name, description, definition, status, created_at, updated_at, approved_at, approved_by, org_id) FROM stdin;
\.


--
-- Data for Name: policy_evaluation_ai_summaries; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.policy_evaluation_ai_summaries (id, evaluation_id, summary_text, provider, model, generated_by, generated_at, context_json, org_id) FROM stdin;
\.


--
-- Data for Name: policy_evaluation_runs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.policy_evaluation_runs (id, bundle_id, evaluated_at, evaluated_by, bundle_approved_by, score, violations_count, result_json, org_id) FROM stdin;
\.


--
-- Data for Name: posture_anomalies; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.posture_anomalies (id, detected_at, metric, severity, current_value, baseline_mean, baseline_std, z_score, window_size, context_json) FROM stdin;
\.


--
-- Data for Name: posture_report_snapshots; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.posture_report_snapshots (id, period, created_at, uptime_pct, posture_score_avg, avg_latency_ms, total_assets, green, amber, red, top_incidents) FROM stdin;
\.


--
-- Data for Name: risk_entity_snapshots; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.risk_entity_snapshots (snapshot_id, entity_type, entity_key, entity_name, snapshot_date, score, level, drivers_json, metadata_json, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: risk_model_snapshots; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.risk_model_snapshots (id, created_at, created_by, event_type, model_signature, artifact_path, threshold, recommended_threshold, dataset_size, positive_labels, negative_labels, accuracy, "precision", recall, f1, auc, brier_score, test_auc, drift_psi, summary_json) FROM stdin;
\.


--
-- Data for Name: scan_jobs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.scan_jobs (job_id, job_type, target_asset_id, requested_by, status, created_at, started_at, finished_at, error, log_output, retry_count, claimed_by, claim_token, last_heartbeat_at, job_params_json, org_id) FROM stdin;
1	telemetry_import	\N	phase5-release-gate-primer	done	2026-04-04 13:04:37.157864+00	2026-04-04 13:04:37.157864+00	2026-04-04 13:04:37.157864+00	\N	\N	0	\N	\N	\N	{}	default
2	score_recompute	\N	phase5-maintenance	done	2026-04-04 13:04:54.140822+00	2026-04-04 13:04:53.265802+00	2026-04-04 13:04:53.27485+00	\N	[2026-04-04 13:04:54] claimed by phase5-maintenance-worker timeout=960s\n[2026-04-04 13:04:53] claimed by worker-secplat-worker-web-768f48b474-jhbz5-1 timeout=960s\nRecomputed risk for all findings count=0\n	1	\N	\N	\N	{}	default
3	score_recompute	\N	manual-phase5-debug	done	2026-04-04 13:08:07.988065+00	2026-04-04 13:08:08.737678+00	2026-04-04 13:08:08.745504+00	\N	[2026-04-04 13:08:08] claimed by phase5-maintenance-worker timeout=960s\n[2026-04-04 13:08:08] recovered stale running job via maintenance runbook by admin\n[2026-04-04 13:08:08] claimed by worker-secplat-worker-web-768f48b474-vcmc5-1 timeout=960s\nRecomputed risk for all findings count=0\n	1	\N	\N	\N	{}	default
4	telemetry_import	\N	phase5-release-gate-primer	done	2026-04-04 13:08:29.375343+00	2026-04-04 13:08:29.375343+00	2026-04-04 13:08:29.375343+00	\N	\N	0	\N	\N	\N	{}	default
5	score_recompute	\N	phase5-maintenance	done	2026-04-04 13:08:42.491196+00	2026-04-04 13:08:42.572969+00	2026-04-04 13:08:42.589684+00	\N	[2026-04-04 13:08:42] claimed by worker-secplat-worker-web-768f48b474-vcmc5-1 timeout=960s\nRecomputed risk for all findings count=0\n	0	\N	\N	\N	{}	default
6	telemetry_import	\N	phase5-release-gate-primer	done	2026-04-04 13:12:48.569305+00	2026-04-04 13:12:48.569305+00	2026-04-04 13:12:48.569305+00	\N	\N	0	\N	\N	\N	{}	default
7	telemetry_import	\N	phase5-release-gate-primer	done	2026-04-04 13:15:55.895653+00	2026-04-04 13:15:55.895653+00	2026-04-04 13:15:55.895653+00	\N	\N	0	\N	\N	\N	{}	default
\.


--
-- Data for Name: security_alerts; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.security_alerts (alert_id, alert_key, dedupe_key, source, alert_type, asset_id, asset_key, severity, status, title, description, event_count, first_seen_at, last_seen_at, acknowledged_by, acknowledged_at, suppression_reason, suppressed_until, resolved_by, resolved_at, assigned_to, ti_match, ti_source, mitre_techniques, payload_json, context_json, created_at, updated_at, org_id) FROM stdin;
1	phase5-primer-1775307880	phase5-primer-1775307880	cowrie	detection	\N	phase5-release-gate-1775307880	high	firing	Phase 5 release gate primer	Phase 5 release gate primer 1775307880	1	2026-04-04 13:04:40+00	2026-04-04 13:04:40+00	\N	\N	\N	\N	\N	\N	\N	f	\N	["TA0006"]	{}	{}	2026-04-04 13:04:40+00	2026-04-04 13:04:40+00	default
2	phase5-primer-1775308112	phase5-primer-1775308112	cowrie	detection	\N	phase5-release-gate-1775308112	high	firing	Phase 5 release gate primer	Phase 5 release gate primer 1775308112	1	2026-04-04 13:08:32+00	2026-04-04 13:08:32+00	\N	\N	\N	\N	\N	\N	\N	f	\N	["TA0006"]	{}	{}	2026-04-04 13:08:32+00	2026-04-04 13:08:32+00	default
3	phase5-primer-1775308372	phase5-primer-1775308372	cowrie	detection	\N	phase5-release-gate-1775308372	high	firing	Phase 5 release gate primer	Phase 5 release gate primer 1775308372	1	2026-04-04 13:12:52+00	2026-04-04 13:12:52+00	\N	\N	\N	\N	\N	\N	\N	f	\N	["TA0006"]	{}	{}	2026-04-04 13:12:52+00	2026-04-04 13:12:52+00	default
4	phase5-primer-1775308558	phase5-primer-1775308558	cowrie	detection	\N	phase5-release-gate-1775308558	high	firing	Phase 5 release gate primer	Phase 5 release gate primer 1775308558	1	2026-04-04 13:15:58+00	2026-04-04 13:15:58+00	\N	\N	\N	\N	\N	\N	\N	f	\N	["TA0006"]	{}	{}	2026-04-04 13:15:58+00	2026-04-04 13:15:58+00	default
\.


--
-- Data for Name: security_events; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.security_events (event_id, source, event_type, asset_id, asset_key, collector, ingest_job_id, raw_offset, raw_path, severity, src_ip, src_port, dst_ip, dst_port, domain, url, protocol, event_time, ingest_lag_seconds, ti_match, ti_source, mitre_techniques, anomaly_score, payload_json, created_at, org_id) FROM stdin;
1	cowrie	cowrie.login.failed	\N	phase5-release-gate-1775307880	phase5.release-gate.primer	\N	\N	\N	2	203.0.113.90	\N	\N	\N	\N	\N	ssh	2026-04-04 13:04:40+00	1	f	\N	["TA0006"]	\N	{"src_ip": "203.0.113.90", "eventid": "cowrie.login.failed", "message": "Phase 5 release gate primer 1775307880", "session": "phase5-1775307880", "username": "root", "timestamp": "2026-04-04T13:04:40Z"}	2026-04-04 13:04:37.040739+00	default
2	cowrie	cowrie.login.failed	\N	phase5-release-gate-1775308112	phase5.release-gate.primer	\N	\N	\N	2	203.0.113.122	\N	\N	\N	\N	\N	ssh	2026-04-04 13:08:32+00	1	f	\N	["TA0006"]	\N	{"src_ip": "203.0.113.122", "eventid": "cowrie.login.failed", "message": "Phase 5 release gate primer 1775308112", "session": "phase5-1775308112", "username": "root", "timestamp": "2026-04-04T13:08:32Z"}	2026-04-04 13:08:29.289427+00	default
3	cowrie	cowrie.login.failed	\N	phase5-release-gate-1775308372	phase5.release-gate.primer	\N	\N	\N	2	203.0.113.182	\N	\N	\N	\N	\N	ssh	2026-04-04 13:12:52+00	1	f	\N	["TA0006"]	\N	{"src_ip": "203.0.113.182", "eventid": "cowrie.login.failed", "message": "Phase 5 release gate primer 1775308372", "session": "phase5-1775308372", "username": "root", "timestamp": "2026-04-04T13:12:52Z"}	2026-04-04 13:12:48.479214+00	default
4	cowrie	cowrie.login.failed	\N	phase5-release-gate-1775308558	phase5.release-gate.primer	\N	\N	\N	2	203.0.113.168	\N	\N	\N	\N	\N	ssh	2026-04-04 13:15:58+00	1	f	\N	["TA0006"]	\N	{"src_ip": "203.0.113.168", "eventid": "cowrie.login.failed", "message": "Phase 5 release gate primer 1775308558", "session": "phase5-1775308558", "username": "root", "timestamp": "2026-04-04T13:15:58Z"}	2026-04-04 13:15:55.805241+00	default
\.


--
-- Data for Name: suppression_rules; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.suppression_rules (id, scope, scope_value, starts_at, ends_at, reason, created_by, created_at) FROM stdin;
\.


--
-- Data for Name: threat_ioc_asset_matches; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.threat_ioc_asset_matches (id, threat_ioc_id, asset_id, asset_key, match_field, matched_value, first_seen_at, last_seen_at, metadata) FROM stdin;
\.


--
-- Data for Name: threat_ioc_campaigns; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.threat_ioc_campaigns (campaign_id, campaign_tag, title, description, confidence_weight, source_priority, confidence_label, is_active, created_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: threat_ioc_sightings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.threat_ioc_sightings (sighting_id, threat_ioc_id, asset_id, asset_key, match_field, matched_value, source_event_id, source_event_ref, source_tool, sighted_at, context_json) FROM stdin;
\.


--
-- Data for Name: threat_iocs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.threat_iocs (id, source, indicator, indicator_type, feed_url, first_seen_at, last_seen_at, is_active, metadata, created_at, updated_at, confidence_score, confidence_label, source_priority, campaign_tag, expires_at, last_match_count) FROM stdin;
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.users (id, username, role, password_hash, disabled, created_at) FROM stdin;
1	admin	admin	\N	f	2026-04-04 12:56:19.773252+00
2	viewer	viewer	$2b$12$wITIujVXwHS5q4g/TLizOeTTDFWkpEC9/sAz6h20H5x4GXzz37WGW	f	2026-04-04 12:56:19.773252+00
3	scanner-service	analyst	$2b$12$v3Efy43lzbgaYortdOmBJOwAJFVDzeZtwYGgNHcUTLLQVbU9rjMei	f	2026-04-04 12:56:19.773252+00
4	ingestion-service	analyst	$2b$12$ALnaz8IUNLMysttdGpjPOOZU0zvelP5oHHA57svZoSbascpGu97/i	f	2026-04-04 12:56:19.773252+00
5	correlator-service	analyst	$2b$12$rKzUm1MpudBFS149EpPdlO//SJoOaZZynPvHGYXGeFpunz/zuCUL6	f	2026-04-04 12:56:19.773252+00
\.


--
-- Name: ai_feedback_feedback_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.ai_feedback_feedback_id_seq', 1, false);


--
-- Name: ai_summary_versions_version_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.ai_summary_versions_version_id_seq', 1, false);


--
-- Name: alert_ai_guidance_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.alert_ai_guidance_id_seq', 1, false);


--
-- Name: asset_ai_diagnoses_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.asset_ai_diagnoses_id_seq', 1, false);


--
-- Name: asset_anomaly_scores_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.asset_anomaly_scores_id_seq', 1, false);


--
-- Name: assets_asset_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.assets_asset_id_seq', 1, false);


--
-- Name: attack_lab_runs_run_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.attack_lab_runs_run_id_seq', 1, false);


--
-- Name: attack_surface_certificates_cert_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.attack_surface_certificates_cert_id_seq', 1, false);


--
-- Name: attack_surface_discovery_runs_run_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.attack_surface_discovery_runs_run_id_seq', 1, false);


--
-- Name: attack_surface_drift_events_event_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.attack_surface_drift_events_event_id_seq', 1, false);


--
-- Name: attack_surface_hosts_host_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.attack_surface_hosts_host_id_seq', 1, false);


--
-- Name: attack_surface_relationships_relationship_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.attack_surface_relationships_relationship_id_seq', 1, false);


--
-- Name: attack_surface_services_service_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.attack_surface_services_service_id_seq', 1, false);


--
-- Name: audit_events_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.audit_events_id_seq', 21, true);


--
-- Name: auth_refresh_tokens_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.auth_refresh_tokens_id_seq', 14, true);


--
-- Name: automation_approvals_approval_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.automation_approvals_approval_id_seq', 1, false);


--
-- Name: automation_playbooks_playbook_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.automation_playbooks_playbook_id_seq', 1, false);


--
-- Name: automation_rollbacks_rollback_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.automation_rollbacks_rollback_id_seq', 1, false);


--
-- Name: automation_run_actions_run_action_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.automation_run_actions_run_action_id_seq', 1, false);


--
-- Name: automation_runs_run_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.automation_runs_run_id_seq', 1, false);


--
-- Name: detection_correlation_rules_correlation_rule_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.detection_correlation_rules_correlation_rule_id_seq', 1, false);


--
-- Name: detection_correlation_runs_run_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.detection_correlation_runs_run_id_seq', 1, false);


--
-- Name: detection_rule_runs_run_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.detection_rule_runs_run_id_seq', 1, false);


--
-- Name: detection_rules_rule_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.detection_rules_rule_id_seq', 1, false);


--
-- Name: finding_ai_explanations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.finding_ai_explanations_id_seq', 1, false);


--
-- Name: finding_risk_labels_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.finding_risk_labels_id_seq', 1, false);


--
-- Name: findings_finding_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.findings_finding_id_seq', 1, false);


--
-- Name: incident_ai_summaries_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.incident_ai_summaries_id_seq', 1, false);


--
-- Name: incident_auto_rules_auto_rule_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.incident_auto_rules_auto_rule_id_seq', 1, false);


--
-- Name: incident_checklist_items_item_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.incident_checklist_items_item_id_seq', 1, false);


--
-- Name: incident_decisions_decision_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.incident_decisions_decision_id_seq', 1, false);


--
-- Name: incident_evidence_evidence_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.incident_evidence_evidence_id_seq', 1, false);


--
-- Name: incident_notes_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.incident_notes_id_seq', 1, false);


--
-- Name: incidents_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.incidents_id_seq', 1, false);


--
-- Name: job_ai_triages_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.job_ai_triages_id_seq', 1, false);


--
-- Name: maintenance_windows_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.maintenance_windows_id_seq', 1, false);


--
-- Name: platform_api_runtime_snapshots_snapshot_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.platform_api_runtime_snapshots_snapshot_id_seq', 37, true);


--
-- Name: platform_sli_samples_sample_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.platform_sli_samples_sample_id_seq', 31, true);


--
-- Name: policy_bundles_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.policy_bundles_id_seq', 1, false);


--
-- Name: policy_evaluation_ai_summaries_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.policy_evaluation_ai_summaries_id_seq', 1, false);


--
-- Name: policy_evaluation_runs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.policy_evaluation_runs_id_seq', 1, false);


--
-- Name: posture_anomalies_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.posture_anomalies_id_seq', 1, false);


--
-- Name: posture_report_snapshots_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.posture_report_snapshots_id_seq', 1, false);


--
-- Name: risk_entity_snapshots_snapshot_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.risk_entity_snapshots_snapshot_id_seq', 1, false);


--
-- Name: risk_model_snapshots_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.risk_model_snapshots_id_seq', 1, false);


--
-- Name: scan_jobs_job_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.scan_jobs_job_id_seq', 7, true);


--
-- Name: security_alerts_alert_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.security_alerts_alert_id_seq', 4, true);


--
-- Name: security_events_event_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.security_events_event_id_seq', 4, true);


--
-- Name: suppression_rules_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.suppression_rules_id_seq', 1, false);


--
-- Name: threat_ioc_asset_matches_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.threat_ioc_asset_matches_id_seq', 1, false);


--
-- Name: threat_ioc_campaigns_campaign_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.threat_ioc_campaigns_campaign_id_seq', 1, false);


--
-- Name: threat_ioc_sightings_sighting_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.threat_ioc_sightings_sighting_id_seq', 1, false);


--
-- Name: threat_iocs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.threat_iocs_id_seq', 1, false);


--
-- Name: users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.users_id_seq', 5, true);


--
-- Name: ai_feedback ai_feedback_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_feedback
    ADD CONSTRAINT ai_feedback_pkey PRIMARY KEY (feedback_id);


--
-- Name: ai_summary_versions ai_summary_versions_entity_type_entity_key_version_no_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_summary_versions
    ADD CONSTRAINT ai_summary_versions_entity_type_entity_key_version_no_key UNIQUE (entity_type, entity_key, version_no);


--
-- Name: ai_summary_versions ai_summary_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_summary_versions
    ADD CONSTRAINT ai_summary_versions_pkey PRIMARY KEY (version_id);


--
-- Name: alert_ai_guidance alert_ai_guidance_asset_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_ai_guidance
    ADD CONSTRAINT alert_ai_guidance_asset_key_key UNIQUE (asset_key);


--
-- Name: alert_ai_guidance alert_ai_guidance_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_ai_guidance
    ADD CONSTRAINT alert_ai_guidance_pkey PRIMARY KEY (id);


--
-- Name: alert_states alert_states_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_states
    ADD CONSTRAINT alert_states_pkey PRIMARY KEY (asset_key);


--
-- Name: asset_ai_diagnoses asset_ai_diagnoses_asset_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_ai_diagnoses
    ADD CONSTRAINT asset_ai_diagnoses_asset_key_key UNIQUE (asset_key);


--
-- Name: asset_ai_diagnoses asset_ai_diagnoses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_ai_diagnoses
    ADD CONSTRAINT asset_ai_diagnoses_pkey PRIMARY KEY (id);


--
-- Name: asset_anomaly_scores asset_anomaly_scores_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_anomaly_scores
    ADD CONSTRAINT asset_anomaly_scores_pkey PRIMARY KEY (id);


--
-- Name: assets assets_asset_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_asset_key_key UNIQUE (asset_key);


--
-- Name: assets assets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_pkey PRIMARY KEY (asset_id);


--
-- Name: attack_lab_runs attack_lab_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_lab_runs
    ADD CONSTRAINT attack_lab_runs_pkey PRIMARY KEY (run_id);


--
-- Name: attack_surface_certificates attack_surface_certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_certificates
    ADD CONSTRAINT attack_surface_certificates_pkey PRIMARY KEY (cert_id);


--
-- Name: attack_surface_discovery_runs attack_surface_discovery_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_discovery_runs
    ADD CONSTRAINT attack_surface_discovery_runs_pkey PRIMARY KEY (run_id);


--
-- Name: attack_surface_drift_events attack_surface_drift_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_drift_events
    ADD CONSTRAINT attack_surface_drift_events_pkey PRIMARY KEY (event_id);


--
-- Name: attack_surface_exposures attack_surface_exposures_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_exposures
    ADD CONSTRAINT attack_surface_exposures_pkey PRIMARY KEY (asset_key);


--
-- Name: attack_surface_hosts attack_surface_hosts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_hosts
    ADD CONSTRAINT attack_surface_hosts_pkey PRIMARY KEY (host_id);


--
-- Name: attack_surface_relationships attack_surface_relationships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_relationships
    ADD CONSTRAINT attack_surface_relationships_pkey PRIMARY KEY (relationship_id);


--
-- Name: attack_surface_relationships attack_surface_relationships_source_asset_key_target_asset__key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_relationships
    ADD CONSTRAINT attack_surface_relationships_source_asset_key_target_asset__key UNIQUE (source_asset_key, target_asset_key, relation_type);


--
-- Name: attack_surface_services attack_surface_services_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_services
    ADD CONSTRAINT attack_surface_services_pkey PRIMARY KEY (service_id);


--
-- Name: audit_events audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id);


--
-- Name: auth_refresh_tokens auth_refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_refresh_tokens
    ADD CONSTRAINT auth_refresh_tokens_pkey PRIMARY KEY (id);


--
-- Name: auth_refresh_tokens auth_refresh_tokens_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_refresh_tokens
    ADD CONSTRAINT auth_refresh_tokens_token_hash_key UNIQUE (token_hash);


--
-- Name: automation_approvals automation_approvals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.automation_approvals
    ADD CONSTRAINT automation_approvals_pkey PRIMARY KEY (approval_id);


--
-- Name: automation_approvals automation_approvals_run_action_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.automation_approvals
    ADD CONSTRAINT automation_approvals_run_action_id_key UNIQUE (run_action_id);


--
-- Name: automation_playbooks automation_playbooks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.automation_playbooks
    ADD CONSTRAINT automation_playbooks_pkey PRIMARY KEY (playbook_id);


--
-- Name: automation_playbooks automation_playbooks_title_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.automation_playbooks
    ADD CONSTRAINT automation_playbooks_title_key UNIQUE (title);


--
-- Name: automation_rollbacks automation_rollbacks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.automation_rollbacks
    ADD CONSTRAINT automation_rollbacks_pkey PRIMARY KEY (rollback_id);


--
-- Name: automation_rollbacks automation_rollbacks_run_action_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.automation_rollbacks
    ADD CONSTRAINT automation_rollbacks_run_action_id_key UNIQUE (run_action_id);


--
-- Name: automation_run_actions automation_run_actions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.automation_run_actions
    ADD CONSTRAINT automation_run_actions_pkey PRIMARY KEY (run_action_id);


--
-- Name: automation_run_actions automation_run_actions_run_id_action_index_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.automation_run_actions
    ADD CONSTRAINT automation_run_actions_run_id_action_index_key UNIQUE (run_id, action_index);


--
-- Name: automation_runs automation_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.automation_runs
    ADD CONSTRAINT automation_runs_pkey PRIMARY KEY (run_id);


--
-- Name: detection_correlation_rules detection_correlation_rules_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_correlation_rules
    ADD CONSTRAINT detection_correlation_rules_name_key UNIQUE (name);


--
-- Name: detection_correlation_rules detection_correlation_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_correlation_rules
    ADD CONSTRAINT detection_correlation_rules_pkey PRIMARY KEY (correlation_rule_id);


--
-- Name: detection_correlation_runs detection_correlation_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_correlation_runs
    ADD CONSTRAINT detection_correlation_runs_pkey PRIMARY KEY (run_id);


--
-- Name: detection_rule_runs detection_rule_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rule_runs
    ADD CONSTRAINT detection_rule_runs_pkey PRIMARY KEY (run_id);


--
-- Name: detection_rules detection_rules_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rules
    ADD CONSTRAINT detection_rules_name_key UNIQUE (name);


--
-- Name: detection_rules detection_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rules
    ADD CONSTRAINT detection_rules_pkey PRIMARY KEY (rule_id);


--
-- Name: finding_ai_explanations finding_ai_explanations_finding_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_ai_explanations
    ADD CONSTRAINT finding_ai_explanations_finding_id_key UNIQUE (finding_id);


--
-- Name: finding_ai_explanations finding_ai_explanations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_ai_explanations
    ADD CONSTRAINT finding_ai_explanations_pkey PRIMARY KEY (id);


--
-- Name: finding_risk_labels finding_risk_labels_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_risk_labels
    ADD CONSTRAINT finding_risk_labels_pkey PRIMARY KEY (id);


--
-- Name: findings findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_pkey PRIMARY KEY (finding_id);


--
-- Name: incident_ai_summaries incident_ai_summaries_incident_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_ai_summaries
    ADD CONSTRAINT incident_ai_summaries_incident_id_key UNIQUE (incident_id);


--
-- Name: incident_ai_summaries incident_ai_summaries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_ai_summaries
    ADD CONSTRAINT incident_ai_summaries_pkey PRIMARY KEY (id);


--
-- Name: incident_alerts incident_alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_alerts
    ADD CONSTRAINT incident_alerts_pkey PRIMARY KEY (incident_id, asset_key);


--
-- Name: incident_auto_rules incident_auto_rules_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_auto_rules
    ADD CONSTRAINT incident_auto_rules_name_key UNIQUE (name);


--
-- Name: incident_auto_rules incident_auto_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_auto_rules
    ADD CONSTRAINT incident_auto_rules_pkey PRIMARY KEY (auto_rule_id);


--
-- Name: incident_checklist_items incident_checklist_items_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_checklist_items
    ADD CONSTRAINT incident_checklist_items_pkey PRIMARY KEY (item_id);


--
-- Name: incident_decisions incident_decisions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_decisions
    ADD CONSTRAINT incident_decisions_pkey PRIMARY KEY (decision_id);


--
-- Name: incident_evidence incident_evidence_incident_id_evidence_type_ref_id_relation_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_evidence
    ADD CONSTRAINT incident_evidence_incident_id_evidence_type_ref_id_relation_key UNIQUE (incident_id, evidence_type, ref_id, relation);


--
-- Name: incident_evidence incident_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_evidence
    ADD CONSTRAINT incident_evidence_pkey PRIMARY KEY (evidence_id);


--
-- Name: incident_notes incident_notes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_notes
    ADD CONSTRAINT incident_notes_pkey PRIMARY KEY (id);


--
-- Name: incident_watchers incident_watchers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_watchers
    ADD CONSTRAINT incident_watchers_pkey PRIMARY KEY (incident_id, username);


--
-- Name: incidents incidents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incidents
    ADD CONSTRAINT incidents_pkey PRIMARY KEY (id);


--
-- Name: job_ai_triages job_ai_triages_job_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.job_ai_triages
    ADD CONSTRAINT job_ai_triages_job_id_key UNIQUE (job_id);


--
-- Name: job_ai_triages job_ai_triages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.job_ai_triages
    ADD CONSTRAINT job_ai_triages_pkey PRIMARY KEY (id);


--
-- Name: maintenance_windows maintenance_windows_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.maintenance_windows
    ADD CONSTRAINT maintenance_windows_pkey PRIMARY KEY (id);


--
-- Name: platform_api_runtime_snapshots platform_api_runtime_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_api_runtime_snapshots
    ADD CONSTRAINT platform_api_runtime_snapshots_pkey PRIMARY KEY (snapshot_id);


--
-- Name: platform_sli_samples platform_sli_samples_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_sli_samples
    ADD CONSTRAINT platform_sli_samples_pkey PRIMARY KEY (sample_id);


--
-- Name: policy_bundles policy_bundles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policy_bundles
    ADD CONSTRAINT policy_bundles_pkey PRIMARY KEY (id);


--
-- Name: policy_evaluation_ai_summaries policy_evaluation_ai_summaries_evaluation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policy_evaluation_ai_summaries
    ADD CONSTRAINT policy_evaluation_ai_summaries_evaluation_id_key UNIQUE (evaluation_id);


--
-- Name: policy_evaluation_ai_summaries policy_evaluation_ai_summaries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policy_evaluation_ai_summaries
    ADD CONSTRAINT policy_evaluation_ai_summaries_pkey PRIMARY KEY (id);


--
-- Name: policy_evaluation_runs policy_evaluation_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policy_evaluation_runs
    ADD CONSTRAINT policy_evaluation_runs_pkey PRIMARY KEY (id);


--
-- Name: posture_anomalies posture_anomalies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.posture_anomalies
    ADD CONSTRAINT posture_anomalies_pkey PRIMARY KEY (id);


--
-- Name: posture_report_snapshots posture_report_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.posture_report_snapshots
    ADD CONSTRAINT posture_report_snapshots_pkey PRIMARY KEY (id);


--
-- Name: risk_entity_snapshots risk_entity_snapshots_entity_type_entity_key_snapshot_date_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.risk_entity_snapshots
    ADD CONSTRAINT risk_entity_snapshots_entity_type_entity_key_snapshot_date_key UNIQUE (entity_type, entity_key, snapshot_date);


--
-- Name: risk_entity_snapshots risk_entity_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.risk_entity_snapshots
    ADD CONSTRAINT risk_entity_snapshots_pkey PRIMARY KEY (snapshot_id);


--
-- Name: risk_model_snapshots risk_model_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.risk_model_snapshots
    ADD CONSTRAINT risk_model_snapshots_pkey PRIMARY KEY (id);


--
-- Name: scan_jobs scan_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_jobs
    ADD CONSTRAINT scan_jobs_pkey PRIMARY KEY (job_id);


--
-- Name: security_alerts security_alerts_alert_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_alerts
    ADD CONSTRAINT security_alerts_alert_key_key UNIQUE (alert_key);


--
-- Name: security_alerts security_alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_alerts
    ADD CONSTRAINT security_alerts_pkey PRIMARY KEY (alert_id);


--
-- Name: security_events security_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events
    ADD CONSTRAINT security_events_pkey PRIMARY KEY (event_id);


--
-- Name: suppression_rules suppression_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.suppression_rules
    ADD CONSTRAINT suppression_rules_pkey PRIMARY KEY (id);


--
-- Name: threat_ioc_asset_matches threat_ioc_asset_matches_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_ioc_asset_matches
    ADD CONSTRAINT threat_ioc_asset_matches_pkey PRIMARY KEY (id);


--
-- Name: threat_ioc_asset_matches threat_ioc_asset_matches_threat_ioc_id_asset_id_match_field_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_ioc_asset_matches
    ADD CONSTRAINT threat_ioc_asset_matches_threat_ioc_id_asset_id_match_field_key UNIQUE (threat_ioc_id, asset_id, match_field, matched_value);


--
-- Name: threat_ioc_campaigns threat_ioc_campaigns_campaign_tag_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_ioc_campaigns
    ADD CONSTRAINT threat_ioc_campaigns_campaign_tag_key UNIQUE (campaign_tag);


--
-- Name: threat_ioc_campaigns threat_ioc_campaigns_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_ioc_campaigns
    ADD CONSTRAINT threat_ioc_campaigns_pkey PRIMARY KEY (campaign_id);


--
-- Name: threat_ioc_sightings threat_ioc_sightings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_ioc_sightings
    ADD CONSTRAINT threat_ioc_sightings_pkey PRIMARY KEY (sighting_id);


--
-- Name: threat_iocs threat_iocs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_iocs
    ADD CONSTRAINT threat_iocs_pkey PRIMARY KEY (id);


--
-- Name: threat_iocs threat_iocs_source_indicator_type_indicator_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_iocs
    ADD CONSTRAINT threat_iocs_source_indicator_type_indicator_key UNIQUE (source, indicator_type, indicator);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: idx_ai_feedback_entity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_feedback_entity ON public.ai_feedback USING btree (entity_type, entity_key, created_at DESC);


--
-- Name: idx_ai_feedback_feedback; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_feedback_feedback ON public.ai_feedback USING btree (feedback, created_at DESC);


--
-- Name: idx_ai_summary_versions_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_summary_versions_created_at ON public.ai_summary_versions USING btree (created_at DESC);


--
-- Name: idx_ai_summary_versions_entity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_summary_versions_entity ON public.ai_summary_versions USING btree (entity_type, entity_key, version_no DESC);


--
-- Name: idx_alert_ai_guidance_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_ai_guidance_action ON public.alert_ai_guidance USING btree (recommended_action, generated_at DESC);


--
-- Name: idx_alert_ai_guidance_generated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_ai_guidance_generated_at ON public.alert_ai_guidance USING btree (generated_at DESC);


--
-- Name: idx_alert_ai_guidance_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_ai_guidance_org_id ON public.alert_ai_guidance USING btree (org_id);


--
-- Name: idx_alert_states_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_states_state ON public.alert_states USING btree (state);


--
-- Name: idx_alert_states_suppressed_until; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_states_suppressed_until ON public.alert_states USING btree (suppressed_until) WHERE (suppressed_until IS NOT NULL);


--
-- Name: idx_asset_ai_diagnoses_generated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_ai_diagnoses_generated_at ON public.asset_ai_diagnoses USING btree (generated_at DESC);


--
-- Name: idx_asset_ai_diagnoses_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_ai_diagnoses_org_id ON public.asset_ai_diagnoses USING btree (org_id);


--
-- Name: idx_asset_anomaly_scores_asset_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_anomaly_scores_asset_time ON public.asset_anomaly_scores USING btree (asset_key, computed_at DESC);


--
-- Name: idx_assets_asset_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_asset_key ON public.assets USING btree (asset_key);


--
-- Name: idx_assets_criticality; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_criticality ON public.assets USING btree (criticality);


--
-- Name: idx_assets_env; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_env ON public.assets USING btree (environment);


--
-- Name: idx_assets_metadata; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_metadata ON public.assets USING gin (metadata);


--
-- Name: idx_assets_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_org_id ON public.assets USING btree (org_id);


--
-- Name: idx_assets_tags; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_tags ON public.assets USING gin (tags);


--
-- Name: idx_assets_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_type ON public.assets USING btree (asset_type);


--
-- Name: idx_attack_lab_runs_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attack_lab_runs_created ON public.attack_lab_runs USING btree (created_at DESC);


--
-- Name: idx_attack_lab_runs_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attack_lab_runs_status ON public.attack_lab_runs USING btree (status, created_at DESC);


--
-- Name: idx_attack_surface_certs_fingerprint; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attack_surface_certs_fingerprint ON public.attack_surface_certificates USING btree (fingerprint_sha256);


--
-- Name: idx_attack_surface_certs_hostname; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attack_surface_certs_hostname ON public.attack_surface_certificates USING btree (hostname, discovered_at DESC);


--
-- Name: idx_attack_surface_certs_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attack_surface_certs_run ON public.attack_surface_certificates USING btree (run_id, cert_id);


--
-- Name: idx_attack_surface_drift_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attack_surface_drift_run ON public.attack_surface_drift_events USING btree (run_id, event_id DESC);


--
-- Name: idx_attack_surface_drift_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attack_surface_drift_type ON public.attack_surface_drift_events USING btree (event_type, created_at DESC);


--
-- Name: idx_attack_surface_exposures_level; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attack_surface_exposures_level ON public.attack_surface_exposures USING btree (exposure_level, updated_at DESC);


--
-- Name: idx_attack_surface_exposures_score; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attack_surface_exposures_score ON public.attack_surface_exposures USING btree (exposure_score DESC, updated_at DESC);


--
-- Name: idx_attack_surface_hosts_asset; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attack_surface_hosts_asset ON public.attack_surface_hosts USING btree (asset_key, discovered_at DESC);


--
-- Name: idx_attack_surface_hosts_hostname; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attack_surface_hosts_hostname ON public.attack_surface_hosts USING btree (hostname, discovered_at DESC);


--
-- Name: idx_attack_surface_hosts_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attack_surface_hosts_run ON public.attack_surface_hosts USING btree (run_id, host_id);


--
-- Name: idx_attack_surface_relationships_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attack_surface_relationships_source ON public.attack_surface_relationships USING btree (source_asset_key, updated_at DESC);


--
-- Name: idx_attack_surface_relationships_target; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attack_surface_relationships_target ON public.attack_surface_relationships USING btree (target_asset_key, updated_at DESC);


--
-- Name: idx_attack_surface_runs_status_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attack_surface_runs_status_started ON public.attack_surface_discovery_runs USING btree (status, started_at DESC);


--
-- Name: idx_attack_surface_services_asset; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attack_surface_services_asset ON public.attack_surface_services USING btree (asset_key, discovered_at DESC);


--
-- Name: idx_attack_surface_services_host_port; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attack_surface_services_host_port ON public.attack_surface_services USING btree (hostname, port, discovered_at DESC);


--
-- Name: idx_attack_surface_services_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attack_surface_services_run ON public.attack_surface_services USING btree (run_id, service_id);


--
-- Name: idx_audit_events_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_events_action ON public.audit_events USING btree (action);


--
-- Name: idx_audit_events_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_events_created_at ON public.audit_events USING btree (created_at DESC);


--
-- Name: idx_audit_events_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_events_user ON public.audit_events USING btree (user_name);


--
-- Name: idx_auth_refresh_tokens_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_refresh_tokens_active ON public.auth_refresh_tokens USING btree (username, expires_at DESC) WHERE (revoked_at IS NULL);


--
-- Name: idx_auth_refresh_tokens_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_refresh_tokens_username ON public.auth_refresh_tokens USING btree (username, issued_at DESC);


--
-- Name: idx_automation_approvals_required_role; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_automation_approvals_required_role ON public.automation_approvals USING btree (required_role, status, created_at DESC);


--
-- Name: idx_automation_approvals_status_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_automation_approvals_status_created ON public.automation_approvals USING btree (status, created_at DESC);


--
-- Name: idx_automation_playbooks_trigger_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_automation_playbooks_trigger_enabled ON public.automation_playbooks USING btree (trigger, enabled, updated_at DESC);


--
-- Name: idx_automation_rollbacks_status_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_automation_rollbacks_status_created ON public.automation_rollbacks USING btree (status, created_at DESC);


--
-- Name: idx_automation_run_actions_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_automation_run_actions_run ON public.automation_run_actions USING btree (run_id, action_index);


--
-- Name: idx_automation_run_actions_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_automation_run_actions_status ON public.automation_run_actions USING btree (status, created_at DESC);


--
-- Name: idx_automation_runs_playbook_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_automation_runs_playbook_started ON public.automation_runs USING btree (playbook_id, started_at DESC);


--
-- Name: idx_automation_runs_status_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_automation_runs_status_started ON public.automation_runs USING btree (status, started_at DESC);


--
-- Name: idx_detection_correlation_rules_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_correlation_rules_enabled ON public.detection_correlation_rules USING btree (enabled, updated_at DESC);


--
-- Name: idx_detection_correlation_runs_mode; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_correlation_runs_mode ON public.detection_correlation_runs USING btree (run_mode, started_at DESC);


--
-- Name: idx_detection_correlation_runs_rule; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_correlation_runs_rule ON public.detection_correlation_runs USING btree (correlation_rule_id, started_at DESC);


--
-- Name: idx_detection_correlation_runs_snapshot; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_correlation_runs_snapshot ON public.detection_correlation_runs USING btree (snapshot_hash);


--
-- Name: idx_detection_rule_runs_mode_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rule_runs_mode_started ON public.detection_rule_runs USING btree (run_mode, started_at DESC);


--
-- Name: idx_detection_rule_runs_rule; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rule_runs_rule ON public.detection_rule_runs USING btree (rule_id, started_at DESC);


--
-- Name: idx_detection_rule_runs_snapshot_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rule_runs_snapshot_hash ON public.detection_rule_runs USING btree (snapshot_hash);


--
-- Name: idx_detection_rules_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_enabled ON public.detection_rules USING btree (enabled, updated_at DESC);


--
-- Name: idx_detection_rules_key_version; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_detection_rules_key_version ON public.detection_rules USING btree (rule_key, version) WHERE (rule_key IS NOT NULL);


--
-- Name: idx_detection_rules_parent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_parent ON public.detection_rules USING btree (parent_rule_id);


--
-- Name: idx_detection_rules_stage; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_stage ON public.detection_rules USING btree (stage, updated_at DESC);


--
-- Name: idx_finding_ai_explanations_generated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_ai_explanations_generated_at ON public.finding_ai_explanations USING btree (generated_at DESC);


--
-- Name: idx_finding_ai_explanations_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_ai_explanations_org_id ON public.finding_ai_explanations USING btree (org_id);


--
-- Name: idx_finding_risk_labels_finding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_risk_labels_finding_id ON public.finding_risk_labels USING btree (finding_id, created_at DESC);


--
-- Name: idx_finding_risk_labels_label; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_risk_labels_label ON public.finding_risk_labels USING btree (label, created_at DESC);


--
-- Name: idx_findings_finding_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_findings_finding_key ON public.findings USING btree (finding_key) WHERE (finding_key IS NOT NULL);


--
-- Name: idx_findings_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_org_id ON public.findings USING btree (org_id);


--
-- Name: idx_findings_package_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_package_name ON public.findings USING btree (package_name) WHERE (package_name IS NOT NULL);


--
-- Name: idx_findings_risk_level; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_risk_level ON public.findings USING btree (risk_level);


--
-- Name: idx_findings_risk_score; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_risk_score ON public.findings USING btree (risk_score DESC);


--
-- Name: idx_findings_vulnerability_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_vulnerability_id ON public.findings USING btree (vulnerability_id) WHERE (vulnerability_id IS NOT NULL);


--
-- Name: idx_incident_ai_summaries_generated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incident_ai_summaries_generated_at ON public.incident_ai_summaries USING btree (generated_at DESC);


--
-- Name: idx_incident_ai_summaries_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incident_ai_summaries_org_id ON public.incident_ai_summaries USING btree (org_id);


--
-- Name: idx_incident_alerts_alert_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incident_alerts_alert_id ON public.incident_alerts USING btree (alert_id) WHERE (alert_id IS NOT NULL);


--
-- Name: idx_incident_alerts_incident_alert_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_incident_alerts_incident_alert_id ON public.incident_alerts USING btree (incident_id, alert_id) WHERE (alert_id IS NOT NULL);


--
-- Name: idx_incident_alerts_incident_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incident_alerts_incident_id ON public.incident_alerts USING btree (incident_id);


--
-- Name: idx_incident_alerts_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incident_alerts_org_id ON public.incident_alerts USING btree (org_id);


--
-- Name: idx_incident_auto_rules_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incident_auto_rules_enabled ON public.incident_auto_rules USING btree (enabled, updated_at DESC);


--
-- Name: idx_incident_checklist_incident; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incident_checklist_incident ON public.incident_checklist_items USING btree (incident_id, created_at DESC);


--
-- Name: idx_incident_checklist_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incident_checklist_status ON public.incident_checklist_items USING btree (incident_id, done, updated_at DESC);


--
-- Name: idx_incident_decisions_incident; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incident_decisions_incident ON public.incident_decisions USING btree (incident_id, created_at DESC);


--
-- Name: idx_incident_evidence_incident; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incident_evidence_incident ON public.incident_evidence USING btree (incident_id, created_at DESC);


--
-- Name: idx_incident_evidence_type_ref; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incident_evidence_type_ref ON public.incident_evidence USING btree (evidence_type, ref_id);


--
-- Name: idx_incident_notes_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incident_notes_created_at ON public.incident_notes USING btree (incident_id, created_at DESC);


--
-- Name: idx_incident_notes_incident_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incident_notes_incident_id ON public.incident_notes USING btree (incident_id);


--
-- Name: idx_incident_notes_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incident_notes_org_id ON public.incident_notes USING btree (org_id);


--
-- Name: idx_incident_watchers_incident; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incident_watchers_incident ON public.incident_watchers USING btree (incident_id, added_at DESC);


--
-- Name: idx_incidents_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incidents_created_at ON public.incidents USING btree (created_at DESC);


--
-- Name: idx_incidents_incident_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_incidents_incident_key ON public.incidents USING btree (incident_key);


--
-- Name: idx_incidents_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incidents_org_id ON public.incidents USING btree (org_id);


--
-- Name: idx_incidents_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incidents_status ON public.incidents USING btree (status);


--
-- Name: idx_job_ai_triages_generated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_job_ai_triages_generated_at ON public.job_ai_triages USING btree (generated_at DESC);


--
-- Name: idx_job_ai_triages_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_job_ai_triages_org_id ON public.job_ai_triages USING btree (org_id);


--
-- Name: idx_maintenance_windows_asset; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_maintenance_windows_asset ON public.maintenance_windows USING btree (asset_key);


--
-- Name: idx_maintenance_windows_times; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_maintenance_windows_times ON public.maintenance_windows USING btree (start_at, end_at);


--
-- Name: idx_platform_api_runtime_snapshots_captured; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_platform_api_runtime_snapshots_captured ON public.platform_api_runtime_snapshots USING btree (captured_at DESC);


--
-- Name: idx_platform_api_runtime_snapshots_instance; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_platform_api_runtime_snapshots_instance ON public.platform_api_runtime_snapshots USING btree (service_instance_id, captured_at DESC);


--
-- Name: idx_platform_sli_samples_captured; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_platform_sli_samples_captured ON public.platform_sli_samples USING btree (captured_at DESC);


--
-- Name: idx_platform_sli_samples_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_platform_sli_samples_source ON public.platform_sli_samples USING btree (source, captured_at DESC);


--
-- Name: idx_policy_bundles_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_policy_bundles_org_id ON public.policy_bundles USING btree (org_id);


--
-- Name: idx_policy_bundles_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_policy_bundles_status ON public.policy_bundles USING btree (status);


--
-- Name: idx_policy_eval_ai_summaries_generated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_policy_eval_ai_summaries_generated_at ON public.policy_evaluation_ai_summaries USING btree (generated_at DESC);


--
-- Name: idx_policy_eval_runs_bundle_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_policy_eval_runs_bundle_time ON public.policy_evaluation_runs USING btree (bundle_id, evaluated_at DESC);


--
-- Name: idx_policy_evaluation_ai_summaries_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_policy_evaluation_ai_summaries_org_id ON public.policy_evaluation_ai_summaries USING btree (org_id);


--
-- Name: idx_policy_evaluation_runs_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_policy_evaluation_runs_org_id ON public.policy_evaluation_runs USING btree (org_id);


--
-- Name: idx_posture_anomalies_detected_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_posture_anomalies_detected_at ON public.posture_anomalies USING btree (detected_at DESC);


--
-- Name: idx_posture_anomalies_metric; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_posture_anomalies_metric ON public.posture_anomalies USING btree (metric);


--
-- Name: idx_report_snapshots_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_report_snapshots_created_at ON public.posture_report_snapshots USING btree (created_at DESC);


--
-- Name: idx_risk_entity_snapshots_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_risk_entity_snapshots_date ON public.risk_entity_snapshots USING btree (snapshot_date DESC, entity_type, score DESC);


--
-- Name: idx_risk_entity_snapshots_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_risk_entity_snapshots_lookup ON public.risk_entity_snapshots USING btree (entity_type, entity_key, snapshot_date DESC);


--
-- Name: idx_risk_model_snapshots_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_risk_model_snapshots_created_at ON public.risk_model_snapshots USING btree (created_at DESC);


--
-- Name: idx_risk_model_snapshots_event_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_risk_model_snapshots_event_type ON public.risk_model_snapshots USING btree (event_type, created_at DESC);


--
-- Name: idx_scan_jobs_claim_token; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_scan_jobs_claim_token ON public.scan_jobs USING btree (claim_token) WHERE (claim_token IS NOT NULL);


--
-- Name: idx_scan_jobs_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scan_jobs_created_at ON public.scan_jobs USING btree (created_at DESC);


--
-- Name: idx_scan_jobs_last_heartbeat; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scan_jobs_last_heartbeat ON public.scan_jobs USING btree (last_heartbeat_at DESC) WHERE (last_heartbeat_at IS NOT NULL);


--
-- Name: idx_scan_jobs_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scan_jobs_org_id ON public.scan_jobs USING btree (org_id);


--
-- Name: idx_scan_jobs_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scan_jobs_status ON public.scan_jobs USING btree (status);


--
-- Name: idx_security_alerts_asset; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_alerts_asset ON public.security_alerts USING btree (asset_key, status, last_seen_at DESC);


--
-- Name: idx_security_alerts_dedupe; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_alerts_dedupe ON public.security_alerts USING btree (dedupe_key);


--
-- Name: idx_security_alerts_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_alerts_org_id ON public.security_alerts USING btree (org_id);


--
-- Name: idx_security_alerts_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_alerts_source ON public.security_alerts USING btree (source, status, last_seen_at DESC);


--
-- Name: idx_security_alerts_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_alerts_status ON public.security_alerts USING btree (status, last_seen_at DESC);


--
-- Name: idx_security_events_asset_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_events_asset_time ON public.security_events USING btree (asset_key, event_time DESC);


--
-- Name: idx_security_events_collector_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_events_collector_time ON public.security_events USING btree (collector, event_time DESC);


--
-- Name: idx_security_events_ingest_job; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_events_ingest_job ON public.security_events USING btree (ingest_job_id, created_at DESC);


--
-- Name: idx_security_events_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_events_org_id ON public.security_events USING btree (org_id);


--
-- Name: idx_security_events_raw_path_offset; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_events_raw_path_offset ON public.security_events USING btree (raw_path, raw_offset DESC);


--
-- Name: idx_security_events_source_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_events_source_time ON public.security_events USING btree (source, event_time DESC);


--
-- Name: idx_security_events_ti_match; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_events_ti_match ON public.security_events USING btree (ti_match, event_time DESC);


--
-- Name: idx_suppression_rules_scope; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_suppression_rules_scope ON public.suppression_rules USING btree (scope, scope_value);


--
-- Name: idx_suppression_rules_times; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_suppression_rules_times ON public.suppression_rules USING btree (starts_at, ends_at);


--
-- Name: idx_threat_ioc_campaigns_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_ioc_campaigns_active ON public.threat_ioc_campaigns USING btree (is_active, updated_at DESC);


--
-- Name: idx_threat_ioc_matches_asset; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_ioc_matches_asset ON public.threat_ioc_asset_matches USING btree (asset_key, last_seen_at DESC);


--
-- Name: idx_threat_ioc_matches_ioc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_ioc_matches_ioc ON public.threat_ioc_asset_matches USING btree (threat_ioc_id, last_seen_at DESC);


--
-- Name: idx_threat_ioc_sightings_asset_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_ioc_sightings_asset_time ON public.threat_ioc_sightings USING btree (asset_key, sighted_at DESC);


--
-- Name: idx_threat_ioc_sightings_ioc_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_ioc_sightings_ioc_time ON public.threat_ioc_sightings USING btree (threat_ioc_id, sighted_at DESC);


--
-- Name: idx_threat_ioc_sightings_source_ref; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_ioc_sightings_source_ref ON public.threat_ioc_sightings USING btree (source_event_ref, sighted_at DESC);


--
-- Name: idx_threat_iocs_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_iocs_active ON public.threat_iocs USING btree (is_active, last_seen_at DESC);


--
-- Name: idx_threat_iocs_campaign; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_iocs_campaign ON public.threat_iocs USING btree (campaign_tag, is_active, last_seen_at DESC);


--
-- Name: idx_threat_iocs_confidence; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_iocs_confidence ON public.threat_iocs USING btree (confidence_score DESC, last_seen_at DESC);


--
-- Name: idx_threat_iocs_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_iocs_source ON public.threat_iocs USING btree (source, indicator_type);


--
-- Name: idx_users_role; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_role ON public.users USING btree (role);


--
-- Name: idx_users_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_username ON public.users USING btree (username);


--
-- Name: assets trg_assets_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_assets_updated_at BEFORE UPDATE ON public.assets FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: ai_feedback ai_feedback_version_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_feedback
    ADD CONSTRAINT ai_feedback_version_id_fkey FOREIGN KEY (version_id) REFERENCES public.ai_summary_versions(version_id) ON DELETE SET NULL;


--
-- Name: attack_lab_runs attack_lab_runs_target_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_lab_runs
    ADD CONSTRAINT attack_lab_runs_target_asset_id_fkey FOREIGN KEY (target_asset_id) REFERENCES public.assets(asset_id) ON DELETE SET NULL;


--
-- Name: attack_surface_certificates attack_surface_certificates_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_certificates
    ADD CONSTRAINT attack_surface_certificates_host_id_fkey FOREIGN KEY (host_id) REFERENCES public.attack_surface_hosts(host_id) ON DELETE CASCADE;


--
-- Name: attack_surface_certificates attack_surface_certificates_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_certificates
    ADD CONSTRAINT attack_surface_certificates_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.attack_surface_discovery_runs(run_id) ON DELETE CASCADE;


--
-- Name: attack_surface_drift_events attack_surface_drift_events_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_drift_events
    ADD CONSTRAINT attack_surface_drift_events_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.attack_surface_discovery_runs(run_id) ON DELETE CASCADE;


--
-- Name: attack_surface_exposures attack_surface_exposures_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_exposures
    ADD CONSTRAINT attack_surface_exposures_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.attack_surface_discovery_runs(run_id) ON DELETE SET NULL;


--
-- Name: attack_surface_hosts attack_surface_hosts_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_hosts
    ADD CONSTRAINT attack_surface_hosts_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.attack_surface_discovery_runs(run_id) ON DELETE CASCADE;


--
-- Name: attack_surface_services attack_surface_services_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_services
    ADD CONSTRAINT attack_surface_services_host_id_fkey FOREIGN KEY (host_id) REFERENCES public.attack_surface_hosts(host_id) ON DELETE CASCADE;


--
-- Name: attack_surface_services attack_surface_services_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_surface_services
    ADD CONSTRAINT attack_surface_services_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.attack_surface_discovery_runs(run_id) ON DELETE CASCADE;


--
-- Name: automation_approvals automation_approvals_run_action_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.automation_approvals
    ADD CONSTRAINT automation_approvals_run_action_id_fkey FOREIGN KEY (run_action_id) REFERENCES public.automation_run_actions(run_action_id) ON DELETE CASCADE;


--
-- Name: automation_rollbacks automation_rollbacks_run_action_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.automation_rollbacks
    ADD CONSTRAINT automation_rollbacks_run_action_id_fkey FOREIGN KEY (run_action_id) REFERENCES public.automation_run_actions(run_action_id) ON DELETE CASCADE;


--
-- Name: automation_run_actions automation_run_actions_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.automation_run_actions
    ADD CONSTRAINT automation_run_actions_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.automation_runs(run_id) ON DELETE CASCADE;


--
-- Name: automation_runs automation_runs_playbook_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.automation_runs
    ADD CONSTRAINT automation_runs_playbook_id_fkey FOREIGN KEY (playbook_id) REFERENCES public.automation_playbooks(playbook_id) ON DELETE CASCADE;


--
-- Name: detection_correlation_runs detection_correlation_runs_correlation_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_correlation_runs
    ADD CONSTRAINT detection_correlation_runs_correlation_rule_id_fkey FOREIGN KEY (correlation_rule_id) REFERENCES public.detection_correlation_rules(correlation_rule_id) ON DELETE CASCADE;


--
-- Name: detection_rule_runs detection_rule_runs_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rule_runs
    ADD CONSTRAINT detection_rule_runs_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.detection_rules(rule_id) ON DELETE CASCADE;


--
-- Name: detection_rules detection_rules_parent_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rules
    ADD CONSTRAINT detection_rules_parent_rule_id_fkey FOREIGN KEY (parent_rule_id) REFERENCES public.detection_rules(rule_id) ON DELETE SET NULL;


--
-- Name: finding_ai_explanations finding_ai_explanations_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_ai_explanations
    ADD CONSTRAINT finding_ai_explanations_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(finding_id) ON DELETE CASCADE;


--
-- Name: finding_risk_labels finding_risk_labels_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_risk_labels
    ADD CONSTRAINT finding_risk_labels_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(finding_id) ON DELETE CASCADE;


--
-- Name: findings findings_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(asset_id);


--
-- Name: incident_ai_summaries incident_ai_summaries_incident_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_ai_summaries
    ADD CONSTRAINT incident_ai_summaries_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES public.incidents(id) ON DELETE CASCADE;


--
-- Name: incident_alerts incident_alerts_alert_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_alerts
    ADD CONSTRAINT incident_alerts_alert_id_fkey FOREIGN KEY (alert_id) REFERENCES public.security_alerts(alert_id) ON DELETE CASCADE;


--
-- Name: incident_alerts incident_alerts_incident_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_alerts
    ADD CONSTRAINT incident_alerts_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES public.incidents(id) ON DELETE CASCADE;


--
-- Name: incident_checklist_items incident_checklist_items_incident_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_checklist_items
    ADD CONSTRAINT incident_checklist_items_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES public.incidents(id) ON DELETE CASCADE;


--
-- Name: incident_decisions incident_decisions_incident_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_decisions
    ADD CONSTRAINT incident_decisions_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES public.incidents(id) ON DELETE CASCADE;


--
-- Name: incident_evidence incident_evidence_incident_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_evidence
    ADD CONSTRAINT incident_evidence_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES public.incidents(id) ON DELETE CASCADE;


--
-- Name: incident_notes incident_notes_incident_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_notes
    ADD CONSTRAINT incident_notes_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES public.incidents(id) ON DELETE CASCADE;


--
-- Name: incident_watchers incident_watchers_incident_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_watchers
    ADD CONSTRAINT incident_watchers_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES public.incidents(id) ON DELETE CASCADE;


--
-- Name: job_ai_triages job_ai_triages_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.job_ai_triages
    ADD CONSTRAINT job_ai_triages_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.scan_jobs(job_id) ON DELETE CASCADE;


--
-- Name: policy_evaluation_ai_summaries policy_evaluation_ai_summaries_evaluation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policy_evaluation_ai_summaries
    ADD CONSTRAINT policy_evaluation_ai_summaries_evaluation_id_fkey FOREIGN KEY (evaluation_id) REFERENCES public.policy_evaluation_runs(id) ON DELETE CASCADE;


--
-- Name: policy_evaluation_runs policy_evaluation_runs_bundle_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policy_evaluation_runs
    ADD CONSTRAINT policy_evaluation_runs_bundle_id_fkey FOREIGN KEY (bundle_id) REFERENCES public.policy_bundles(id) ON DELETE CASCADE;


--
-- Name: scan_jobs scan_jobs_target_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_jobs
    ADD CONSTRAINT scan_jobs_target_asset_id_fkey FOREIGN KEY (target_asset_id) REFERENCES public.assets(asset_id);


--
-- Name: security_alerts security_alerts_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_alerts
    ADD CONSTRAINT security_alerts_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(asset_id) ON DELETE SET NULL;


--
-- Name: security_events security_events_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events
    ADD CONSTRAINT security_events_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(asset_id) ON DELETE SET NULL;


--
-- Name: security_events security_events_ingest_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events
    ADD CONSTRAINT security_events_ingest_job_id_fkey FOREIGN KEY (ingest_job_id) REFERENCES public.scan_jobs(job_id) ON DELETE SET NULL;


--
-- Name: threat_ioc_asset_matches threat_ioc_asset_matches_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_ioc_asset_matches
    ADD CONSTRAINT threat_ioc_asset_matches_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(asset_id) ON DELETE CASCADE;


--
-- Name: threat_ioc_asset_matches threat_ioc_asset_matches_threat_ioc_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_ioc_asset_matches
    ADD CONSTRAINT threat_ioc_asset_matches_threat_ioc_id_fkey FOREIGN KEY (threat_ioc_id) REFERENCES public.threat_iocs(id) ON DELETE CASCADE;


--
-- Name: threat_ioc_sightings threat_ioc_sightings_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_ioc_sightings
    ADD CONSTRAINT threat_ioc_sightings_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(asset_id) ON DELETE SET NULL;


--
-- Name: threat_ioc_sightings threat_ioc_sightings_threat_ioc_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_ioc_sightings
    ADD CONSTRAINT threat_ioc_sightings_threat_ioc_id_fkey FOREIGN KEY (threat_ioc_id) REFERENCES public.threat_iocs(id) ON DELETE CASCADE;


--
-- Name: alert_ai_guidance; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.alert_ai_guidance ENABLE ROW LEVEL SECURITY;

--
-- Name: asset_ai_diagnoses; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.asset_ai_diagnoses ENABLE ROW LEVEL SECURITY;

--
-- Name: assets; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.assets ENABLE ROW LEVEL SECURITY;

--
-- Name: finding_ai_explanations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.finding_ai_explanations ENABLE ROW LEVEL SECURITY;

--
-- Name: findings; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;

--
-- Name: incident_ai_summaries; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.incident_ai_summaries ENABLE ROW LEVEL SECURITY;

--
-- Name: incident_alerts; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.incident_alerts ENABLE ROW LEVEL SECURITY;

--
-- Name: incident_notes; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.incident_notes ENABLE ROW LEVEL SECURITY;

--
-- Name: incidents; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.incidents ENABLE ROW LEVEL SECURITY;

--
-- Name: job_ai_triages; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.job_ai_triages ENABLE ROW LEVEL SECURITY;

--
-- Name: policy_bundles; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.policy_bundles ENABLE ROW LEVEL SECURITY;

--
-- Name: policy_evaluation_ai_summaries; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.policy_evaluation_ai_summaries ENABLE ROW LEVEL SECURITY;

--
-- Name: policy_evaluation_runs; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.policy_evaluation_runs ENABLE ROW LEVEL SECURITY;

--
-- Name: scan_jobs; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.scan_jobs ENABLE ROW LEVEL SECURITY;

--
-- Name: alert_ai_guidance secplat_tenant_alert_ai_guidance; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY secplat_tenant_alert_ai_guidance ON public.alert_ai_guidance USING ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text))) WITH CHECK ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text)));


--
-- Name: asset_ai_diagnoses secplat_tenant_asset_ai_diagnoses; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY secplat_tenant_asset_ai_diagnoses ON public.asset_ai_diagnoses USING ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text))) WITH CHECK ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text)));


--
-- Name: assets secplat_tenant_assets; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY secplat_tenant_assets ON public.assets USING ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text))) WITH CHECK ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text)));


--
-- Name: finding_ai_explanations secplat_tenant_finding_ai_explanations; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY secplat_tenant_finding_ai_explanations ON public.finding_ai_explanations USING ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text))) WITH CHECK ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text)));


--
-- Name: findings secplat_tenant_findings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY secplat_tenant_findings ON public.findings USING ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text))) WITH CHECK ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text)));


--
-- Name: incident_ai_summaries secplat_tenant_incident_ai_summaries; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY secplat_tenant_incident_ai_summaries ON public.incident_ai_summaries USING ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text))) WITH CHECK ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text)));


--
-- Name: incident_alerts secplat_tenant_incident_alerts; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY secplat_tenant_incident_alerts ON public.incident_alerts USING ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text))) WITH CHECK ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text)));


--
-- Name: incident_notes secplat_tenant_incident_notes; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY secplat_tenant_incident_notes ON public.incident_notes USING ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text))) WITH CHECK ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text)));


--
-- Name: incidents secplat_tenant_incidents; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY secplat_tenant_incidents ON public.incidents USING ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text))) WITH CHECK ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text)));


--
-- Name: job_ai_triages secplat_tenant_job_ai_triages; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY secplat_tenant_job_ai_triages ON public.job_ai_triages USING ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text))) WITH CHECK ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text)));


--
-- Name: policy_bundles secplat_tenant_policy_bundles; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY secplat_tenant_policy_bundles ON public.policy_bundles USING ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text))) WITH CHECK ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text)));


--
-- Name: policy_evaluation_ai_summaries secplat_tenant_policy_eval_ai_summaries; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY secplat_tenant_policy_eval_ai_summaries ON public.policy_evaluation_ai_summaries USING ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text))) WITH CHECK ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text)));


--
-- Name: policy_evaluation_runs secplat_tenant_policy_evaluation_runs; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY secplat_tenant_policy_evaluation_runs ON public.policy_evaluation_runs USING ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text))) WITH CHECK ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text)));


--
-- Name: scan_jobs secplat_tenant_scan_jobs; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY secplat_tenant_scan_jobs ON public.scan_jobs USING ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text))) WITH CHECK ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text)));


--
-- Name: security_alerts secplat_tenant_security_alerts; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY secplat_tenant_security_alerts ON public.security_alerts USING ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text))) WITH CHECK ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text)));


--
-- Name: security_events secplat_tenant_security_events; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY secplat_tenant_security_events ON public.security_events USING ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text))) WITH CHECK ((org_id = COALESCE(current_setting('secplat.tenant_id'::text, true), 'default'::text)));


--
-- Name: security_alerts; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.security_alerts ENABLE ROW LEVEL SECURITY;

--
-- Name: security_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;

--
-- PostgreSQL database dump complete
--

\unrestrict 7dJALW4X1I7DIl3LMt23D9X3VK43fvqtNUwXvTgZVxrst9wYNSf5h95ydfhyaxE

