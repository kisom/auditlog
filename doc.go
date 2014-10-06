// Package auditlog implements auditable logs for recording security
// events. The logs are currently backed by SQLite3. They are designed
// to form a chain of auditable, tamper-evident logs. The chain is a
// tree of signatures where the signature on each event is computed
// over both the event and the previous event's signature.
//
// The audit logger is concerned with events. For example, an event
// might be recorded when a user logs in, or an administrative action
// is carried out.
package auditlog
