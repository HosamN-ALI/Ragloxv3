--
-- PostgreSQL database dump
--

\restrict 4EZbkLQob32KqbGl4eTpXxSSodlIga3zUXPFwRWuKAnyPTGujU6aK7N7JWe02xS

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
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: raglox
--

INSERT INTO public.users VALUES ('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', 'admin@raglox.local', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X.VNFQjFp0D1YqGWi', 'RAGLOX Administrator', 'admin', true, '2026-01-02 11:59:47.535256+00', '2026-01-02 11:59:47.535256+00', NULL);


--
-- Data for Name: api_keys; Type: TABLE DATA; Schema: public; Owner: raglox
--



--
-- Data for Name: missions; Type: TABLE DATA; Schema: public; Owner: raglox
--



--
-- Data for Name: targets; Type: TABLE DATA; Schema: public; Owner: raglox
--



--
-- Data for Name: credentials; Type: TABLE DATA; Schema: public; Owner: raglox
--



--
-- Data for Name: attack_paths; Type: TABLE DATA; Schema: public; Owner: raglox
--



--
-- Data for Name: audit_log; Type: TABLE DATA; Schema: public; Owner: raglox
--

INSERT INTO public.audit_log VALUES (1, '2026-01-02 11:59:47.538674+00', NULL, 'system_init', 'system', NULL, '{"message": "RAGLOX v3.0 database initialized", "version": "3.0.0"}', NULL, NULL, true);


--
-- Data for Name: reports; Type: TABLE DATA; Schema: public; Owner: raglox
--



--
-- Data for Name: vulnerabilities; Type: TABLE DATA; Schema: public; Owner: raglox
--



--
-- Data for Name: sessions; Type: TABLE DATA; Schema: public; Owner: raglox
--



--
-- Data for Name: settings; Type: TABLE DATA; Schema: public; Owner: raglox
--

INSERT INTO public.settings VALUES ('system.version', '"3.0.0"', 'Current system version', '2026-01-02 11:59:47.537614+00', NULL);
INSERT INTO public.settings VALUES ('system.maintenance_mode', 'false', 'System maintenance mode flag', '2026-01-02 11:59:47.537614+00', NULL);
INSERT INTO public.settings VALUES ('mission.default_timeout', '86400', 'Default mission timeout in seconds (24 hours)', '2026-01-02 11:59:47.537614+00', NULL);
INSERT INTO public.settings VALUES ('mission.max_concurrent', '5', 'Maximum concurrent missions', '2026-01-02 11:59:47.537614+00', NULL);
INSERT INTO public.settings VALUES ('security.session_timeout', '3600', 'API session timeout in seconds', '2026-01-02 11:59:47.537614+00', NULL);
INSERT INTO public.settings VALUES ('security.max_login_attempts', '5', 'Maximum login attempts before lockout', '2026-01-02 11:59:47.537614+00', NULL);
INSERT INTO public.settings VALUES ('redis.key_prefix', '"mission"', 'Redis key prefix for missions', '2026-01-02 11:59:47.537614+00', NULL);
INSERT INTO public.settings VALUES ('storage.max_report_size', '104857600', 'Maximum report size in bytes (100MB)', '2026-01-02 11:59:47.537614+00', NULL);
INSERT INTO public.settings VALUES ('notifications.enabled', 'true', 'Enable real-time notifications', '2026-01-02 11:59:47.537614+00', NULL);
INSERT INTO public.settings VALUES ('audit.retention_days', '365', 'Audit log retention in days', '2026-01-02 11:59:47.537614+00', NULL);


--
-- Name: audit_log_id_seq; Type: SEQUENCE SET; Schema: public; Owner: raglox
--

SELECT pg_catalog.setval('public.audit_log_id_seq', 1, true);


--
-- PostgreSQL database dump complete
--

\unrestrict 4EZbkLQob32KqbGl4eTpXxSSodlIga3zUXPFwRWuKAnyPTGujU6aK7N7JWe02xS

