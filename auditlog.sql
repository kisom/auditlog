CREATE TABLE events (
    id          INT8 PRIMARY KEY,
    timestamp   INT8 NOT NULL,
    received    INT8 NOT NULL,
    level       TEXT NOT NULL,
    actor       TEXT NOT NULL,
    event       TEXT NOT NULL,
    signature   BYTEA NOT NULL
);

CREATE TABLE attributes (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    value       TEXT NOT NULL,
    event       INT8 NOT NULL,
    position    INT8 NOT NULL
);

CREATE TABLE error_events (
    id          SERIAL PRIMARY KEY,
    serial      INT8 NOT NULL,
    timestamp   INT8 NOT NULL,
    received    INT8 NOT NULL,
    level       TEXT NOT NULL,
    actor       TEXT NOT NULL,
    event       TEXT NOT NULL
);

CREATE TABLE error_attributes (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    value       TEXT NOT NULL,
    event       INT8 NOT NULL,
    position    INT8 NOT NULL
);

CREATE TABLE errors (
    id          SERIAL PRIMARY KEY,
    timestamp   INT8 NOT NULL,
    message     TEXT NOT NULL,
    event       INT8
);
