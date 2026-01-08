--
-- PostgreSQL database dump
--

\restrict PS1Dgt2ncSx4FAvWsadIahDQwzkd23wxm2CFUx6SobTL6bl6xzC063ZdFYaTsup

-- Dumped from database version 15.15
-- Dumped by pg_dump version 15.15

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
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


--
-- Name: archive_mission(uuid, jsonb); Type: FUNCTION; Schema: public; Owner: raglox
--

CREATE FUNCTION public.archive_mission(p_mission_id uuid, p_state jsonb) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Update mission with final state
    UPDATE missions 
    SET final_state = p_state,
        status = 'archived',
        completed_at = NOW()
    WHERE id = p_mission_id;
    
    -- Log the archive action
    INSERT INTO audit_log (action, resource_type, resource_id, details)
    VALUES ('archive', 'mission', p_mission_id, '{"action": "archived_from_redis"}');
END;
$$;


ALTER FUNCTION public.archive_mission(p_mission_id uuid, p_state jsonb) OWNER TO raglox;

--
-- Name: get_mission_stats(uuid); Type: FUNCTION; Schema: public; Owner: raglox
--

CREATE FUNCTION public.get_mission_stats(p_mission_id uuid) RETURNS TABLE(targets_count integer, vulns_count integer, creds_count integer, sessions_count integer, critical_vulns integer, high_vulns integer)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        (SELECT COUNT(*)::INTEGER FROM targets WHERE mission_id = p_mission_id),
        (SELECT COUNT(*)::INTEGER FROM vulnerabilities WHERE mission_id = p_mission_id),
        (SELECT COUNT(*)::INTEGER FROM credentials WHERE mission_id = p_mission_id),
        (SELECT COUNT(*)::INTEGER FROM sessions WHERE mission_id = p_mission_id),
        (SELECT COUNT(*)::INTEGER FROM vulnerabilities WHERE mission_id = p_mission_id AND severity = 'critical'),
        (SELECT COUNT(*)::INTEGER FROM vulnerabilities WHERE mission_id = p_mission_id AND severity = 'high');
END;
$$;


ALTER FUNCTION public.get_mission_stats(p_mission_id uuid) OWNER TO raglox;

--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: raglox
--

CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.update_updated_at_column() OWNER TO raglox;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: missions; Type: TABLE; Schema: public; Owner: raglox
--

CREATE TABLE public.missions (
    id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    status character varying(50) NOT NULL,
    scope jsonb NOT NULL,
    goals jsonb NOT NULL,
    constraints jsonb DEFAULT '{}'::jsonb,
    created_by uuid,
    created_at timestamp with time zone NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    targets_discovered integer DEFAULT 0,
    vulns_found integer DEFAULT 0,
    creds_harvested integer DEFAULT 0,
    sessions_established integer DEFAULT 0,
    goals_achieved integer DEFAULT 0,
    final_state jsonb,
    CONSTRAINT valid_status CHECK (((status)::text = ANY ((ARRAY['created'::character varying, 'starting'::character varying, 'running'::character varying, 'paused'::character varying, 'completing'::character varying, 'completed'::character varying, 'failed'::character varying, 'cancelled'::character varying, 'archived'::character varying])::text[])))
);


ALTER TABLE public.missions OWNER TO raglox;

--
-- Name: targets; Type: TABLE; Schema: public; Owner: raglox
--

CREATE TABLE public.targets (
    id uuid NOT NULL,
    mission_id uuid,
    ip inet NOT NULL,
    hostname character varying(255),
    os character varying(255),
    status character varying(50),
    priority character varying(20),
    risk_score numeric(3,1),
    discovered_at timestamp with time zone,
    discovered_by character varying(100),
    ports jsonb DEFAULT '{}'::jsonb,
    services jsonb DEFAULT '[]'::jsonb,
    metadata jsonb DEFAULT '{}'::jsonb
);


ALTER TABLE public.targets OWNER TO raglox;

--
-- Name: users; Type: TABLE; Schema: public; Owner: raglox
--

CREATE TABLE public.users (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    email character varying(255) NOT NULL,
    password_hash character varying(255) NOT NULL,
    full_name character varying(255),
    role character varying(50) DEFAULT 'operator'::character varying NOT NULL,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    last_login timestamp with time zone,
    CONSTRAINT valid_role CHECK (((role)::text = ANY ((ARRAY['admin'::character varying, 'operator'::character varying, 'viewer'::character varying, 'auditor'::character varying])::text[])))
);


ALTER TABLE public.users OWNER TO raglox;

--
-- Name: vulnerabilities; Type: TABLE; Schema: public; Owner: raglox
--

CREATE TABLE public.vulnerabilities (
    id uuid NOT NULL,
    mission_id uuid,
    target_id uuid,
    type character varying(100) NOT NULL,
    severity character varying(20) NOT NULL,
    cvss numeric(3,1),
    description text,
    status character varying(50),
    discovered_at timestamp with time zone,
    discovered_by character varying(100),
    exploit_available boolean DEFAULT false,
    rx_modules jsonb DEFAULT '[]'::jsonb,
    metadata jsonb DEFAULT '{}'::jsonb,
    CONSTRAINT valid_severity CHECK (((severity)::text = ANY ((ARRAY['critical'::character varying, 'high'::character varying, 'medium'::character varying, 'low'::character varying, 'info'::character varying])::text[])))
);


ALTER TABLE public.vulnerabilities OWNER TO raglox;

--
-- Name: active_missions; Type: VIEW; Schema: public; Owner: raglox
--

CREATE VIEW public.active_missions AS
 SELECT m.id,
    m.name,
    m.description,
    m.status,
    m.scope,
    m.goals,
    m.constraints,
    m.created_by,
    m.created_at,
    m.started_at,
    m.completed_at,
    m.targets_discovered,
    m.vulns_found,
    m.creds_harvested,
    m.sessions_established,
    m.goals_achieved,
    m.final_state,
    u.email AS created_by_email,
    ( SELECT count(*) AS count
           FROM public.targets t
          WHERE (t.mission_id = m.id)) AS current_targets,
    ( SELECT count(*) AS count
           FROM public.vulnerabilities v
          WHERE (v.mission_id = m.id)) AS current_vulns
   FROM (public.missions m
     LEFT JOIN public.users u ON ((m.created_by = u.id)))
  WHERE ((m.status)::text = ANY ((ARRAY['created'::character varying, 'starting'::character varying, 'running'::character varying, 'paused'::character varying])::text[]));


ALTER TABLE public.active_missions OWNER TO raglox;

--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: raglox
--

CREATE TABLE public.api_keys (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id uuid,
    key_hash character varying(255) NOT NULL,
    name character varying(100),
    permissions jsonb DEFAULT '[]'::jsonb,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    last_used timestamp with time zone,
    is_active boolean DEFAULT true
);


ALTER TABLE public.api_keys OWNER TO raglox;

--
-- Name: attack_paths; Type: TABLE; Schema: public; Owner: raglox
--

CREATE TABLE public.attack_paths (
    id uuid NOT NULL,
    mission_id uuid,
    from_target_id uuid,
    to_target_id uuid,
    method character varying(100),
    via_cred_id uuid,
    discovered_at timestamp with time zone,
    status character varying(50),
    metadata jsonb DEFAULT '{}'::jsonb
);


ALTER TABLE public.attack_paths OWNER TO raglox;

--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: raglox
--

CREATE TABLE public.audit_log (
    id bigint NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now(),
    user_id uuid,
    action character varying(100) NOT NULL,
    resource_type character varying(50),
    resource_id uuid,
    details jsonb,
    ip_address inet,
    user_agent text,
    success boolean DEFAULT true
);


ALTER TABLE public.audit_log OWNER TO raglox;

--
-- Name: audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: raglox
--

CREATE SEQUENCE public.audit_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.audit_log_id_seq OWNER TO raglox;

--
-- Name: audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: raglox
--

ALTER SEQUENCE public.audit_log_id_seq OWNED BY public.audit_log.id;


--
-- Name: credentials; Type: TABLE; Schema: public; Owner: raglox
--

CREATE TABLE public.credentials (
    id uuid NOT NULL,
    mission_id uuid,
    target_id uuid,
    type character varying(50) NOT NULL,
    username character varying(255),
    domain character varying(255),
    value_encrypted bytea NOT NULL,
    source character varying(100),
    discovered_at timestamp with time zone,
    discovered_by character varying(100),
    verified boolean DEFAULT false,
    privilege_level character varying(50),
    metadata jsonb DEFAULT '{}'::jsonb,
    CONSTRAINT valid_cred_type CHECK (((type)::text = ANY ((ARRAY['password'::character varying, 'hash'::character varying, 'key'::character varying, 'token'::character varying, 'certificate'::character varying])::text[])))
);


ALTER TABLE public.credentials OWNER TO raglox;

--
-- Name: mission_summary; Type: VIEW; Schema: public; Owner: raglox
--

CREATE VIEW public.mission_summary AS
 SELECT m.id,
    m.name,
    m.status,
    m.created_at,
    m.started_at,
    m.completed_at,
    m.targets_discovered,
    m.vulns_found,
    m.creds_harvested,
    m.sessions_established,
    m.goals_achieved,
    u.email AS created_by_email,
    (EXTRACT(epoch FROM (COALESCE(m.completed_at, now()) - m.started_at)) / (3600)::numeric) AS duration_hours
   FROM (public.missions m
     LEFT JOIN public.users u ON ((m.created_by = u.id)));


ALTER TABLE public.mission_summary OWNER TO raglox;

--
-- Name: reports; Type: TABLE; Schema: public; Owner: raglox
--

CREATE TABLE public.reports (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    mission_id uuid,
    type character varying(50) NOT NULL,
    format character varying(20) NOT NULL,
    title character varying(255),
    generated_at timestamp with time zone DEFAULT now(),
    generated_by uuid,
    file_path character varying(500),
    file_size bigint,
    metadata jsonb DEFAULT '{}'::jsonb
);


ALTER TABLE public.reports OWNER TO raglox;

--
-- Name: sessions; Type: TABLE; Schema: public; Owner: raglox
--

CREATE TABLE public.sessions (
    id uuid NOT NULL,
    mission_id uuid,
    target_id uuid,
    type character varying(50) NOT NULL,
    username character varying(255),
    privilege character varying(50),
    established_at timestamp with time zone,
    closed_at timestamp with time zone,
    status character varying(50),
    via_vuln_id uuid,
    via_cred_id uuid,
    metadata jsonb DEFAULT '{}'::jsonb
);


ALTER TABLE public.sessions OWNER TO raglox;

--
-- Name: settings; Type: TABLE; Schema: public; Owner: raglox
--

CREATE TABLE public.settings (
    key character varying(100) NOT NULL,
    value jsonb NOT NULL,
    description text,
    updated_at timestamp with time zone DEFAULT now(),
    updated_by uuid
);


ALTER TABLE public.settings OWNER TO raglox;

--
-- Name: audit_log id; Type: DEFAULT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.audit_log ALTER COLUMN id SET DEFAULT nextval('public.audit_log_id_seq'::regclass);


--
-- Data for Name: api_keys; Type: TABLE DATA; Schema: public; Owner: raglox
--

COPY public.api_keys (id, user_id, key_hash, name, permissions, expires_at, created_at, last_used, is_active) FROM stdin;
\.


--
-- Data for Name: attack_paths; Type: TABLE DATA; Schema: public; Owner: raglox
--

COPY public.attack_paths (id, mission_id, from_target_id, to_target_id, method, via_cred_id, discovered_at, status, metadata) FROM stdin;
\.


--
-- Data for Name: audit_log; Type: TABLE DATA; Schema: public; Owner: raglox
--

COPY public.audit_log (id, "timestamp", user_id, action, resource_type, resource_id, details, ip_address, user_agent, success) FROM stdin;
1	2026-01-02 11:59:47.538674+00	\N	system_init	system	\N	{"message": "RAGLOX v3.0 database initialized", "version": "3.0.0"}	\N	\N	t
\.


--
-- Data for Name: credentials; Type: TABLE DATA; Schema: public; Owner: raglox
--

COPY public.credentials (id, mission_id, target_id, type, username, domain, value_encrypted, source, discovered_at, discovered_by, verified, privilege_level, metadata) FROM stdin;
\.


--
-- Data for Name: missions; Type: TABLE DATA; Schema: public; Owner: raglox
--

COPY public.missions (id, name, description, status, scope, goals, constraints, created_by, created_at, started_at, completed_at, targets_discovered, vulns_found, creds_harvested, sessions_established, goals_achieved, final_state) FROM stdin;
\.


--
-- Data for Name: reports; Type: TABLE DATA; Schema: public; Owner: raglox
--

COPY public.reports (id, mission_id, type, format, title, generated_at, generated_by, file_path, file_size, metadata) FROM stdin;
\.


--
-- Data for Name: sessions; Type: TABLE DATA; Schema: public; Owner: raglox
--

COPY public.sessions (id, mission_id, target_id, type, username, privilege, established_at, closed_at, status, via_vuln_id, via_cred_id, metadata) FROM stdin;
\.


--
-- Data for Name: settings; Type: TABLE DATA; Schema: public; Owner: raglox
--

COPY public.settings (key, value, description, updated_at, updated_by) FROM stdin;
system.version	"3.0.0"	Current system version	2026-01-02 11:59:47.537614+00	\N
system.maintenance_mode	false	System maintenance mode flag	2026-01-02 11:59:47.537614+00	\N
mission.default_timeout	86400	Default mission timeout in seconds (24 hours)	2026-01-02 11:59:47.537614+00	\N
mission.max_concurrent	5	Maximum concurrent missions	2026-01-02 11:59:47.537614+00	\N
security.session_timeout	3600	API session timeout in seconds	2026-01-02 11:59:47.537614+00	\N
security.max_login_attempts	5	Maximum login attempts before lockout	2026-01-02 11:59:47.537614+00	\N
redis.key_prefix	"mission"	Redis key prefix for missions	2026-01-02 11:59:47.537614+00	\N
storage.max_report_size	104857600	Maximum report size in bytes (100MB)	2026-01-02 11:59:47.537614+00	\N
notifications.enabled	true	Enable real-time notifications	2026-01-02 11:59:47.537614+00	\N
audit.retention_days	365	Audit log retention in days	2026-01-02 11:59:47.537614+00	\N
\.


--
-- Data for Name: targets; Type: TABLE DATA; Schema: public; Owner: raglox
--

COPY public.targets (id, mission_id, ip, hostname, os, status, priority, risk_score, discovered_at, discovered_by, ports, services, metadata) FROM stdin;
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: raglox
--

COPY public.users (id, email, password_hash, full_name, role, is_active, created_at, updated_at, last_login) FROM stdin;
a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11	admin@raglox.local	$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X.VNFQjFp0D1YqGWi	RAGLOX Administrator	admin	t	2026-01-02 11:59:47.535256+00	2026-01-02 11:59:47.535256+00	\N
\.


--
-- Data for Name: vulnerabilities; Type: TABLE DATA; Schema: public; Owner: raglox
--

COPY public.vulnerabilities (id, mission_id, target_id, type, severity, cvss, description, status, discovered_at, discovered_by, exploit_available, rx_modules, metadata) FROM stdin;
\.


--
-- Name: audit_log_id_seq; Type: SEQUENCE SET; Schema: public; Owner: raglox
--

SELECT pg_catalog.setval('public.audit_log_id_seq', 1, true);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);


--
-- Name: attack_paths attack_paths_pkey; Type: CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.attack_paths
    ADD CONSTRAINT attack_paths_pkey PRIMARY KEY (id);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);


--
-- Name: credentials credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_pkey PRIMARY KEY (id);


--
-- Name: missions missions_pkey; Type: CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.missions
    ADD CONSTRAINT missions_pkey PRIMARY KEY (id);


--
-- Name: reports reports_pkey; Type: CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: settings settings_pkey; Type: CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.settings
    ADD CONSTRAINT settings_pkey PRIMARY KEY (key);


--
-- Name: targets targets_pkey; Type: CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.targets
    ADD CONSTRAINT targets_pkey PRIMARY KEY (id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: vulnerabilities vulnerabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_pkey PRIMARY KEY (id);


--
-- Name: idx_api_keys_hash; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_api_keys_hash ON public.api_keys USING btree (key_hash);


--
-- Name: idx_api_keys_user; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_api_keys_user ON public.api_keys USING btree (user_id);


--
-- Name: idx_audit_action; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_audit_action ON public.audit_log USING btree (action);


--
-- Name: idx_audit_resource; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_audit_resource ON public.audit_log USING btree (resource_type, resource_id);


--
-- Name: idx_audit_timestamp; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_audit_timestamp ON public.audit_log USING btree ("timestamp" DESC);


--
-- Name: idx_audit_user; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_audit_user ON public.audit_log USING btree (user_id);


--
-- Name: idx_creds_mission; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_creds_mission ON public.credentials USING btree (mission_id);


--
-- Name: idx_creds_privilege; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_creds_privilege ON public.credentials USING btree (privilege_level);


--
-- Name: idx_missions_created_at; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_missions_created_at ON public.missions USING btree (created_at DESC);


--
-- Name: idx_missions_created_by; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_missions_created_by ON public.missions USING btree (created_by);


--
-- Name: idx_missions_status; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_missions_status ON public.missions USING btree (status);


--
-- Name: idx_paths_mission; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_paths_mission ON public.attack_paths USING btree (mission_id);


--
-- Name: idx_reports_mission; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_reports_mission ON public.reports USING btree (mission_id);


--
-- Name: idx_reports_type; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_reports_type ON public.reports USING btree (type);


--
-- Name: idx_sessions_mission; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_sessions_mission ON public.sessions USING btree (mission_id);


--
-- Name: idx_sessions_target; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_sessions_target ON public.sessions USING btree (target_id);


--
-- Name: idx_targets_ip; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_targets_ip ON public.targets USING btree (ip);


--
-- Name: idx_targets_mission; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_targets_mission ON public.targets USING btree (mission_id);


--
-- Name: idx_targets_status; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_targets_status ON public.targets USING btree (status);


--
-- Name: idx_users_email; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_users_email ON public.users USING btree (email);


--
-- Name: idx_users_role; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_users_role ON public.users USING btree (role);


--
-- Name: idx_vulns_mission; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_vulns_mission ON public.vulnerabilities USING btree (mission_id);


--
-- Name: idx_vulns_severity; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_vulns_severity ON public.vulnerabilities USING btree (severity);


--
-- Name: idx_vulns_target; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_vulns_target ON public.vulnerabilities USING btree (target_id);


--
-- Name: idx_vulns_type; Type: INDEX; Schema: public; Owner: raglox
--

CREATE INDEX idx_vulns_type ON public.vulnerabilities USING btree (type);


--
-- Name: users update_users_updated_at; Type: TRIGGER; Schema: public; Owner: raglox
--

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: api_keys api_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: attack_paths attack_paths_from_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.attack_paths
    ADD CONSTRAINT attack_paths_from_target_id_fkey FOREIGN KEY (from_target_id) REFERENCES public.targets(id);


--
-- Name: attack_paths attack_paths_mission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.attack_paths
    ADD CONSTRAINT attack_paths_mission_id_fkey FOREIGN KEY (mission_id) REFERENCES public.missions(id) ON DELETE CASCADE;


--
-- Name: attack_paths attack_paths_to_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.attack_paths
    ADD CONSTRAINT attack_paths_to_target_id_fkey FOREIGN KEY (to_target_id) REFERENCES public.targets(id);


--
-- Name: attack_paths attack_paths_via_cred_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.attack_paths
    ADD CONSTRAINT attack_paths_via_cred_id_fkey FOREIGN KEY (via_cred_id) REFERENCES public.credentials(id);


--
-- Name: audit_log audit_log_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: credentials credentials_mission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_mission_id_fkey FOREIGN KEY (mission_id) REFERENCES public.missions(id) ON DELETE CASCADE;


--
-- Name: credentials credentials_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: missions missions_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.missions
    ADD CONSTRAINT missions_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: reports reports_generated_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_generated_by_fkey FOREIGN KEY (generated_by) REFERENCES public.users(id);


--
-- Name: reports reports_mission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_mission_id_fkey FOREIGN KEY (mission_id) REFERENCES public.missions(id) ON DELETE CASCADE;


--
-- Name: sessions sessions_mission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_mission_id_fkey FOREIGN KEY (mission_id) REFERENCES public.missions(id) ON DELETE CASCADE;


--
-- Name: sessions sessions_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: sessions sessions_via_cred_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_via_cred_id_fkey FOREIGN KEY (via_cred_id) REFERENCES public.credentials(id);


--
-- Name: sessions sessions_via_vuln_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_via_vuln_id_fkey FOREIGN KEY (via_vuln_id) REFERENCES public.vulnerabilities(id);


--
-- Name: settings settings_updated_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.settings
    ADD CONSTRAINT settings_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES public.users(id);


--
-- Name: targets targets_mission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.targets
    ADD CONSTRAINT targets_mission_id_fkey FOREIGN KEY (mission_id) REFERENCES public.missions(id) ON DELETE CASCADE;


--
-- Name: vulnerabilities vulnerabilities_mission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_mission_id_fkey FOREIGN KEY (mission_id) REFERENCES public.missions(id) ON DELETE CASCADE;


--
-- Name: vulnerabilities vulnerabilities_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: raglox
--

ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: TABLE missions; Type: ACL; Schema: public; Owner: raglox
--

GRANT SELECT ON TABLE public.missions TO raglox_readonly;
GRANT SELECT,INSERT,UPDATE ON TABLE public.missions TO raglox_operator;


--
-- Name: TABLE targets; Type: ACL; Schema: public; Owner: raglox
--

GRANT SELECT ON TABLE public.targets TO raglox_readonly;
GRANT SELECT,INSERT,UPDATE ON TABLE public.targets TO raglox_operator;


--
-- Name: TABLE users; Type: ACL; Schema: public; Owner: raglox
--

GRANT SELECT ON TABLE public.users TO raglox_readonly;
GRANT SELECT,INSERT,UPDATE ON TABLE public.users TO raglox_operator;


--
-- Name: TABLE vulnerabilities; Type: ACL; Schema: public; Owner: raglox
--

GRANT SELECT ON TABLE public.vulnerabilities TO raglox_readonly;
GRANT SELECT,INSERT,UPDATE ON TABLE public.vulnerabilities TO raglox_operator;


--
-- Name: TABLE active_missions; Type: ACL; Schema: public; Owner: raglox
--

GRANT SELECT ON TABLE public.active_missions TO raglox_readonly;
GRANT SELECT,INSERT,UPDATE ON TABLE public.active_missions TO raglox_operator;


--
-- Name: TABLE api_keys; Type: ACL; Schema: public; Owner: raglox
--

GRANT SELECT ON TABLE public.api_keys TO raglox_readonly;
GRANT SELECT,INSERT,UPDATE ON TABLE public.api_keys TO raglox_operator;


--
-- Name: TABLE attack_paths; Type: ACL; Schema: public; Owner: raglox
--

GRANT SELECT ON TABLE public.attack_paths TO raglox_readonly;
GRANT SELECT,INSERT,UPDATE ON TABLE public.attack_paths TO raglox_operator;


--
-- Name: TABLE audit_log; Type: ACL; Schema: public; Owner: raglox
--

GRANT SELECT ON TABLE public.audit_log TO raglox_readonly;
GRANT SELECT,INSERT,UPDATE ON TABLE public.audit_log TO raglox_operator;


--
-- Name: SEQUENCE audit_log_id_seq; Type: ACL; Schema: public; Owner: raglox
--

GRANT SELECT,USAGE ON SEQUENCE public.audit_log_id_seq TO raglox_operator;


--
-- Name: TABLE credentials; Type: ACL; Schema: public; Owner: raglox
--

GRANT SELECT ON TABLE public.credentials TO raglox_readonly;
GRANT SELECT,INSERT,UPDATE ON TABLE public.credentials TO raglox_operator;


--
-- Name: TABLE mission_summary; Type: ACL; Schema: public; Owner: raglox
--

GRANT SELECT ON TABLE public.mission_summary TO raglox_readonly;
GRANT SELECT,INSERT,UPDATE ON TABLE public.mission_summary TO raglox_operator;


--
-- Name: TABLE reports; Type: ACL; Schema: public; Owner: raglox
--

GRANT SELECT ON TABLE public.reports TO raglox_readonly;
GRANT SELECT,INSERT,UPDATE ON TABLE public.reports TO raglox_operator;


--
-- Name: TABLE sessions; Type: ACL; Schema: public; Owner: raglox
--

GRANT SELECT ON TABLE public.sessions TO raglox_readonly;
GRANT SELECT,INSERT,UPDATE ON TABLE public.sessions TO raglox_operator;


--
-- Name: TABLE settings; Type: ACL; Schema: public; Owner: raglox
--

GRANT SELECT ON TABLE public.settings TO raglox_readonly;
GRANT SELECT,INSERT,UPDATE ON TABLE public.settings TO raglox_operator;


--
-- PostgreSQL database dump complete
--

\unrestrict PS1Dgt2ncSx4FAvWsadIahDQwzkd23wxm2CFUx6SobTL6bl6xzC063ZdFYaTsup

