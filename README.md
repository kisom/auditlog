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
