## auditlog

As part of the development of
[SoftKSM](https://hg.tyrfingr.is/kyle/softksm), I've been thinking
about how to include audit logs. Normal logs are used to convey
information about a program's operation; audit logs attempt to provide
an accountable audit trail for security events. In SoftKSM, for
example, an audit log might record when an administrative action was
taken, or when a key was generated, or that a cryptographic operation
was performed. Audit logs attempt to provide a security snapshot of
events for accounting and incident investigations.

Audit logs have several characteristics:

1. The logs must be **immutable**: the audit logger should not provide
   the capability to remove or tamper with events.
2. Audit logs are a **chain of events**: they are ordered. Just as in
   any other investigation, it's important to establish an order of
   events.
3. The **provenance** of a given event must be established. Provenance
   means that some proof of the event's origin must be presented.
4. The audit logger must provide a means of showing and **certifying**
   a chain of events. That is, the investigator must be able to view
   the chain of events and have the audit logger provide a digital
   signature on the events.

The model taken by `auditlog` is based on events defined as

     type Attribute struct {
         Name  string
         Value string
     }

    type Event struct {
        When       int64
        Received   int64
        Serial     int64
        Level      string
        Actor      string
        Event      string
        Attributes []Attribute
        Signature  []byte
    }

The `When` field records when the event was reported, and the
`Received` field records when the event was entered into the
chain. All timestamps used have a nanosecond resolution. The `Serial`
field records which entry number the event is. The `Level` field is
user-defined, but the proof-of-concept implementation uses the
standard "DEBUG", "INFO", "WARNING", "ERROR", and "CRITICAL"
fields. The `Actor` field is used to record who the event belongs to,
and the `Event` field contains a description of the
event. `Attributes` provide additional details, and the `Signature`
field stores the ECDSA signature on the event.

The signature is generated from the SHA-256 digest of each of these
fields, as well as the signature of the previous event. The chain is a
Merkle tree of events, each dependent on the previous event. Each
signature is dependent on every field in the event, including the
`Received` and `Serial` fields; this makes tampering with the order of
the logs immediately evident.

The auditor produces `Certifications` on request, which are defined as

    type Certification struct {
        When   int64
        Chain  []*Event
        Errors []*ErrorEvent
        Public []byte
    }


### Example Usage

A new logger is created with a database file and a signature key. If
the database file exists, the audit chain is verified.

    const auditLogPath = "/var/lib/ksm/audit.db"

    signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        // Handle the error appropriately.
    }
    
    logger, err := auditlog.New(auditLogPath, signer)
    if err != nil {
        // Handle the error appropriately.
    }

There are seven functions for writing logs:

* `Info`
* `InfoSync`
* `Warning`
* `WarningSync`
* `Error`
* `ErrorSync`
* `CriticalSync`

They all take the same functions; their names indicate what log level
they use. The `Sync` suffix indicates that the function will wait for
the event to be recorded in the database (this takes on the order of
tens to hundreds of milliseconds, on average).

The following example might be used in an authentication system,
noting that a user logged in:

```
    attr := auditlog.Attribute{"username", "jqp"}
    logger.Info("auth", "login", []auditlog.Attribute{attr})
```

### Certifications

A `Certification` contains a list of audit records. A formatted
example certification produced (by default, certifications are not
pretty-printed) looks like


    {
        "chain": [
            {
                "Actor": "logger_test",
                "Attributes": [
                    {
                        "Name": "test",
                        "Value": "123"
                    },
                    {
                        "Name": "foo",
                        "Value": "bar"
                    },
                    {
                        "Name": "baz",
                        "Value": "quux"
                    }
                ],
                "Event": "generic",
                "Level": "INFO",
                "Received": 1412594956023501655,
                "Serial": 0,
                "Signature": "MEUCIFwNIaM7Hck6uyFStvgi2zolZgemxXdHVW/YshkZJhaJAiEAzuCDjJUa0JlPcI0IUcwFhiYSNy+2jeWtAYGXKfVV2n8=",
                "When": 1412594956023495772
            },
            {
                "Actor": "logger_test",
                "Attributes": [
                    {
                        "Name": "test",
                        "Value": "123"
                    },
                    {
                        "Name": "foo",
                        "Value": "bar"
                    },
                    {
                        "Name": "baz",
                        "Value": "quux"
                    }
                ],
                "Event": "warning",
                "Level": "WARNING",
                "Received": 1412594956041156294,
                "Serial": 1,
                "Signature": "MEUCIE7wA94TvIZrcNmQO3QoNrn9rvsjTsAguE581zXNwyq1AiEAvrqXRvCNsZCUm49QVxG3OBlnKWru9emzizgN1Qm8/zM=",
                "When": 1412594956026100241
            },
            {
                "Actor": "actor0",
                "Attributes": null,
                "Event": "ping",
                "Level": "INFO",
                "Received": 1412594956068389191,
                "Serial": 2,
                "Signature": "MEUCIQDf02F9xwimcmlKv0fZAznJkJxetd80H8kZgQYdZyOR+QIgfG3MoWV45IzOq7FZoxOTb32WPZnaa90dikKj70PSxzo=",
                "When": 1412594956056844823
            },
            {
                "Actor": "actor1",
                "Attributes": null,
                "Event": "ping",
                "Level": "INFO",
                "Received": 1412594956086931409,
                "Serial": 3,
                "Signature": "MEUCIBAr0HxDOu9T3bk/e6rCKls6zqILk+8N5vNVjmtm6L3iAiEAhRvG4fm5VgofJJwJuUhiJdgXAVb4To1wOONn64My6h0=",
                "When": 1412594956056848561
            }
        ],
        "errors": [
            {
                "event": {
                    "Actor": "auditlog_test",
                    "Attributes": null,
                    "Event": "PRNG failure",
                    "Level": "INFO",
                    "Received": 1412594956056174667,
                    "Serial": 2,
                    "Signature": null,
                    "When": 1412594956041239087
                },
                "message": "signature: EOF",
                "when": 1412594956056326920
            }
        ],
        "when": 1412594956803267916
    }

The public key used to generate this certification is

    -----BEGIN EC PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtySFtEw1pvr1F8SngKxAoIwlUmzf
    AS20/9IH1u/+jNEQT8rw2e84Oytrces8p49bcv/3jkmNG/VZDmpj7FlxuA==
    -----END EC PUBLIC KEY-----

The `verify_audit_chain` tool will verify the chain, and save a
formatted, verified chain:

    $ verify_audit_chain certified.json
    Verifying certified.json
    OK: writing logs to verified_logs_0.json

`verify_audit_chain` can be installed with

    go get github.com/kisom/auditlog/verify_audit_log


### Database

`auditlog` uses Postgres as the backend. The SQL file containing the
schema can be found in `auditlog.sql`.

### License

`auditlog` is released under the ISC license.

