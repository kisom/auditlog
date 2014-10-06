package auditlog

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"time"
)

// An Attribute is used to encode additional details about an event. An
// example attribute might be
//
//    Attribute{
//            Name: "user",
//            Value: "root",
//    }
//
type Attribute struct {
	Name  string
	Value string
}

const (
	levelUnknown = iota
	levelDebug
	levelInfo
	levelWarning
	levelError
	levelCritical
)

var levelStrings = map[int]string{
	levelUnknown:  "UNKNOWN",
	levelDebug:    "DEBUG",
	levelInfo:     "INFO",
	levelWarning:  "WARNING",
	levelError:    "ERROR",
	levelCritical: "CRITICAL",
}

// An Event captures information about an event.
type Event struct {
	// Serial is the event's position in the audit chain.
	Serial uint64

	// When is a nanosecond-resolution timestamp recording when
	// the event was logged.
	When int64

	// Received is a nanosecond-resolution timestamp recording
	// when the event was processed by the audit logger.
	Received int64

	// Level contains a text description inidicating the log
	// level; this is currently defined as one of the strings
	// "DEBUG", "INFO", "WARNING", "ERROR", or "CRITICAL".
	Level string

	// Actor indicates the component that reported the event.
	Actor string

	// Event contains a text description of the event that
	// occurred.
	Event string

	// Attributes is an (optional) list of additional details that
	// may be relevant to the event.
	Attributes []Attribute

	// Signature contains the audit logger's ECDSA signature on
	// the event. This signature is computed on the SHA-256 digest
	// of all the other fields in the event and the previous event
	// in the chain's signature.
	Signature []byte
	wait      chan struct{}
}

// Digest computes the SHA-256 digest of the event.
func (ev *Event) digest() []byte {
	h := sha256.New()
	binary.Write(h, binary.BigEndian, int64(ev.Serial))
	binary.Write(h, binary.BigEndian, int64(ev.When))
	binary.Write(h, binary.BigEndian, int64(ev.Received))
	h.Write([]byte(ev.Level))
	h.Write([]byte(ev.Actor))
	h.Write([]byte(ev.Event))
	for i := range ev.Attributes {
		h.Write([]byte(ev.Attributes[i].Name))
		h.Write([]byte(ev.Attributes[i].Value))
	}

	if len(ev.Signature) != 0 {
		h.Write(ev.Signature)
	}

	return h.Sum(nil)
}

// String returns a string for the event. The timestamp is formatted
// to second-resolution RFC3339 format.
func (ev *Event) String() string {
	s := fmt.Sprintf("%s [%s] %s:%s", time.Unix(0, ev.When).Format(time.RFC3339),
		ev.Level, ev.Actor, ev.Event)

	for _, attr := range ev.Attributes {
		s += " " + attr.Name + "=" + attr.Value
	}
	return s
}

// Verify checks the signature on the event. The prev argument should be the previous event's signature.
func (ev *Event) Verify(signer *ecdsa.PublicKey, prev []byte) bool {
	sig := ev.Signature
	ev.Signature = prev
	digest := ev.digest()
	ev.Signature = sig

	var signature ECDSASignature
	remaining, err := asn1.Unmarshal(sig, &signature)
	if err != nil || len(remaining) > 0 {
		return false
	}

	return ecdsa.Verify(signer, digest, signature.R, signature.S)
}

// An ErrorEvent is stored in the error log; these are used to record
// a failure of the auditor to sign and store an event. The event
// contained in the ErrorEvent stores the serial number the event
// would have been assigned, which will be reused by future
// events. These are recorded on the following failures: database
// failures (failure to begin or commit a transaction, or when the
// database returns a failure), and failure to compute a signature.
type ErrorEvent struct {
	When    int64  `json:"when"`
	Message string `json:"message"`
	Event   *Event `json:"event"`
}
