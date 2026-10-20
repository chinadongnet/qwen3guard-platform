"""Versioned relational schema shared by PostgreSQL deployment and SQLite tests."""
from __future__ import annotations

import time
import uuid

from sqlalchemy import (JSON, Boolean, Column, Float, ForeignKey, Index, Integer,
                        MetaData, String, Table, Text, UniqueConstraint, create_engine,
                        event, select)
from sqlalchemy.pool import StaticPool

metadata = MetaData()


def ident():
    return uuid.uuid4().hex


def table(name, *cols, **kw):
    return Table(name, metadata, Column("id", String(64), primary_key=True),
                 Column("created_at", Float, nullable=False, default=time.time), *cols, **kw)


schema_versions = Table("schema_versions", metadata, Column("version", Integer, primary_key=True))
users = table("users", Column("username", String(120), unique=True, nullable=False),
              Column("password_hash", Text, nullable=False), Column("is_admin", Boolean, default=False),
              Column("enabled", Boolean, default=True))
projects = table("projects", Column("name", String(120), nullable=False))
members = table("members", Column("project_id", ForeignKey("projects.id"), nullable=False),
                Column("user_id", ForeignKey("users.id"), nullable=False),
                Column("role", String(32), nullable=False), UniqueConstraint("project_id", "user_id"))
sessions = table("sessions", Column("user_id", ForeignKey("users.id"), nullable=False),
                 Column("token_hash", String(64), unique=True), Column("csrf", String(64)),
                 Column("expires_at", Float, nullable=False))
policies = table("policies", Column("project_id", ForeignKey("projects.id"), nullable=False),
                 Column("name", String(120)), Column("published_version", Integer, default=0))
versions = table("policy_versions", Column("policy_id", ForeignKey("policies.id"), nullable=False),
                 Column("version", Integer, nullable=False), Column("config", JSON, nullable=False),
                 Column("author_id", String(64)), UniqueConstraint("policy_id", "version"))
apps = table("applications", Column("project_id", ForeignKey("projects.id"), nullable=False),
             Column("name", String(120), nullable=False), Column("environment", String(20), nullable=False),
             Column("policy_id", ForeignKey("policies.id"), nullable=False),
             Column("enabled", Boolean, default=True))
keys = table("api_keys", Column("application_id", ForeignKey("applications.id"), nullable=False),
             Column("name", String(120)), Column("prefix", String(40)),
             Column("token_hash", String(64), unique=True, nullable=False),
             Column("expires_at", Float, nullable=False), Column("revoked", Boolean, default=False),
             Column("rpm", Integer, default=60), Column("scopes", JSON, nullable=False),
             Column("last_used_at", Float))
counters = Table("rate_counters", metadata, Column("bucket", String(180), primary_key=True),
                 Column("window", Integer, nullable=False), Column("count", Integer, nullable=False))
events = table("detection_events", Column("request_id", String(64), nullable=False, index=True),
               Column("project_id", ForeignKey("projects.id"), nullable=False),
               Column("application_id", ForeignKey("applications.id"), nullable=False),
               Column("key_id", String(64)), Column("source", String(32), nullable=False),
               Column("environment", String(20), nullable=False), Column("endpoint", String(200)),
               Column("execution_status", String(20)), Column("decision", String(20)),
               Column("risk_level", String(32)), Column("latency_ms", Float),
               Column("policy_version_id", String(64)), Column("prompt_preview", Text),
               Column("response_preview", Text), Column("result", JSON, nullable=False))
Index("ix_events_scope_time", events.c.project_id, events.c.environment, events.c.created_at)
operations = table("operation_events", Column("project_id", String(64)), Column("actor_id", String(64)),
                   Column("action", String(80)), Column("target_id", String(64)), Column("detail", JSON))
endpoints = table("model_endpoints", Column("project_id", ForeignKey("projects.id"), nullable=False),
                  Column("name", String(120)), Column("url", Text), Column("model", String(160)),
                  Column("credential", Text), Column("enabled", Boolean, default=True))
jobs = table("evaluation_jobs", Column("project_id", ForeignKey("projects.id"), nullable=False),
             Column("application_id", ForeignKey("applications.id"), nullable=False),
             Column("endpoint_id", ForeignKey("model_endpoints.id")),
             Column("policy_version_id", ForeignKey("policy_versions.id"), nullable=False),
             Column("name", String(120)), Column("state", String(24), nullable=False),
             Column("dataset_hash", String(64)), Column("items", JSON, nullable=False),
             Column("completed", Integer, default=0), Column("total", Integer),
             Column("cancel_requested", Boolean, default=False),
             Column("error_code", String(64)), Column("idempotency_key", String(128)),
             UniqueConstraint("project_id", "idempotency_key"))
job_items = table("evaluation_items", Column("job_id", ForeignKey("evaluation_jobs.id"), nullable=False),
                  Column("position", Integer), Column("result", JSON),
                  UniqueConstraint("job_id", "position"))
incidents = table("incidents", Column("project_id", ForeignKey("projects.id"), nullable=False),
                  Column("event_id", ForeignKey("detection_events.id"), nullable=False),
                  Column("state", String(20), default="open"), Column("assignee", String(120)),
                  Column("severity", String(20), default="medium"))
reviews = table("incident_reviews", Column("incident_id", ForeignKey("incidents.id"), nullable=False),
                Column("actor_id", ForeignKey("users.id")), Column("state", String(20)),
                Column("note", Text))
hooks = table("webhooks", Column("project_id", ForeignKey("projects.id"), nullable=False),
              Column("url", Text), Column("secret", Text), Column("enabled", Boolean, default=True))
deliveries = table("webhook_deliveries", Column("webhook_id", ForeignKey("webhooks.id"), nullable=False),
                   Column("project_id", ForeignKey("projects.id"), nullable=False),
                   Column("payload", JSON), Column("state", String(24), default="pending"),
                   Column("attempts", Integer, default=0), Column("next_attempt", Float, default=time.time),
                   Column("status_code", Integer))

cases = table("question_cases", Column("project_id", ForeignKey("projects.id"), nullable=False),
              Column("dataset", String(24), nullable=False), Column("case_key", String(120), nullable=False),
              Column("revision", Integer, nullable=False), Column("archived", Boolean, default=False),
              Column("content", JSON, nullable=False), UniqueConstraint("project_id", "dataset", "case_key"))
case_history = table("question_case_versions", Column("case_id", ForeignKey("question_cases.id"), nullable=False),
                     Column("revision", Integer, nullable=False), Column("content", JSON, nullable=False),
                     Column("actor_id", ForeignKey("users.id")), UniqueConstraint("case_id", "revision"))
lab_runs = table("lab_runs", Column("project_id", ForeignKey("projects.id"), nullable=False),
                 Column("application_id", ForeignKey("applications.id")), Column("kind", String(32)),
                 Column("content", JSON, nullable=False))
audit_archives = table("audit_archives", Column("event_id", ForeignKey("detection_events.id"), unique=True),
                      Column("project_id", ForeignKey("projects.id")), Column("actor_id", ForeignKey("users.id")))
key_suspensions = table("key_suspensions", Column("key_id", ForeignKey("api_keys.id"), unique=True, nullable=False))
event_payloads = table("event_payloads", Column("event_id", ForeignKey("detection_events.id"), unique=True, nullable=False),
                       Column("content", JSON, nullable=False), Column("expires_at", Float, nullable=False))


def row(result):
    value = result.mappings().first()
    return dict(value) if value else None


class Database:
    def __init__(self, url):
        options = {"pool_pre_ping": True}
        if url.startswith("sqlite"):
            options["connect_args"] = {"check_same_thread": False, "timeout": 20}
            if ":memory:" in url:
                options["poolclass"] = StaticPool
        self.engine = create_engine(url, **options)
        if url.startswith("sqlite"):
            @event.listens_for(self.engine, "connect")
            def sqlite_pragmas(connection, _):
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("PRAGMA journal_mode=WAL")

    def initialize(self):
        metadata.create_all(self.engine)
        with self.engine.begin() as conn:
            current = conn.execute(select(schema_versions.c.version)).scalars().all()
            if current and current not in ([1], [2]):
                raise RuntimeError("Unsupported database schema version")
            if not current:
                conn.execute(schema_versions.insert().values(version=2))
            elif current == [1]:
                conn.execute(schema_versions.update().values(version=2))

    def one(self, statement):
        with self.engine.connect() as conn:
            return row(conn.execute(statement))

    def all(self, statement):
        with self.engine.connect() as conn:
            return [dict(r) for r in conn.execute(statement).mappings()]

    def insert(self, target, **values):
        values = {"id": ident(), "created_at": time.time(), **values}
        with self.engine.begin() as conn:
            conn.execute(target.insert().values(**values))
        return values

    def operation(self, actor, action, target, project=None, **detail):
        return self.insert(operations, actor_id=actor, action=action, target_id=target,
                           project_id=project, detail=detail)
