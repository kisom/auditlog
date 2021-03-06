package auditlog

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/asn1"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"sync"
	"time"
)

var prng = rand.Reader

// A Logger is responsible for recording security events.
type Logger struct {
	signer        *ecdsa.PrivateKey
	stdout        io.Writer
	stderr        io.Writer
	lock          sync.Mutex
	listener      chan *Event
	lastSignature []byte
	counter       uint64
	db            *sql.DB
}

// Public returns the public signature key packed as in DER-encoded
// PKIX format.
func (l *Logger) Public() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&l.signer.PublicKey)
}

// Count returns the number of recorded events.
func (l *Logger) Count() uint64 {
	l.lock.Lock()
	defer l.lock.Unlock()

	return l.counter
}

func (l *Logger) ready() bool {
	return l.listener != nil
}

func (l *Logger) logEvent(when int64, level int, actor, event string, attributes []Attribute, wait chan struct{}) {
	if _, ok := levelStrings[level]; !ok {
		level = levelUnknown
	}

	ev := &Event{
		When:       time.Now().UnixNano(),
		Level:      levelStrings[level],
		Actor:      actor,
		Event:      event,
		Attributes: attributes,
		wait:       wait,
	}

	if l.ready() {
		l.listener <- ev
	} else {
		if wait != nil {
			close(wait)
		}
	}
}

// Debug records a debug event. In practice, this should not be used;
// it is intended only for debugging the audit logger. This does not
// wait for the audit logger to finish recording the event.
func (l *Logger) Debug(actor, event string, attributes []Attribute) {
	if !l.ready() {
		return
	}

	go l.logEvent(time.Now().UnixNano(), levelDebug, actor, event, attributes, nil)
}

// Info records an informational event. This probably includes events
// that are expected normally. This does not wait for the audit logger
// to finish recording the event.
func (l *Logger) Info(actor, event string, attributes []Attribute) {
	if !l.ready() {
		return
	}

	go l.logEvent(time.Now().UnixNano(), levelInfo, actor, event, attributes, nil)
}

// InfoSync performs the same function as Info, except it waits for
// the event to be recorded.
func (l *Logger) InfoSync(actor, event string, attributes []Attribute) {
	if !l.ready() {
		return
	}

	wait := make(chan struct{}, 0)
	go l.logEvent(time.Now().UnixNano(), levelInfo, actor, event, attributes, wait)
	<-wait
}

// Warning records an event that isn't an error, but it is a more
// urgent event. Examples of warning events might be users selecting a
// deprecated cipher. This does not wait for the audit logger to
// finish recording the event.
func (l *Logger) Warning(actor, event string, attributes []Attribute) {
	if !l.ready() {
		return
	}

	go l.logEvent(time.Now().UnixNano(), levelWarning, actor, event, attributes, nil)
}

// WarningSync performs the same function as Warning, except it waits
// for the event to be recorded.
func (l *Logger) WarningSync(actor, event string, attributes []Attribute) {
	if !l.ready() {
		return
	}

	wait := make(chan struct{}, 0)
	go l.logEvent(time.Now().UnixNano(), levelWarning, actor, event, attributes, wait)
	<-wait
}

// Error records an error event. An example might be an authentication
// failure. This does not wait for the audit logger to finish
// recording the event.
func (l *Logger) Error(actor, event string, attributes []Attribute) {
	if !l.ready() {
		return
	}

	go l.logEvent(time.Now().UnixNano(), levelError, actor, event, attributes, nil)
}

// ErrorSync performs the same function as error, except it waits for
// the event to be recorded.
func (l *Logger) ErrorSync(actor, event string, attributes []Attribute) {
	if !l.ready() {
		return
	}

	wait := make(chan struct{}, 0)
	go l.logEvent(time.Now().UnixNano(), levelError, actor, event, attributes, wait)
	<-wait
}

// CriticalSync records a critical failure of this system. This is
// almost always followed by a shutdown, and therefore only a
// synchronous version that waits for the event to be recorded is
// provided.
func (l *Logger) CriticalSync(actor, event string, attributes []Attribute) {
	if !l.ready() {
		return
	}

	wait := make(chan struct{}, 0)
	go l.logEvent(time.Now().UnixNano(), levelCritical, actor, event, attributes, wait)
	<-wait
}

// An ECDSASignature is the structure into which an ECDSA signature is
// packed.
type ECDSASignature struct {
	R, S *big.Int
}

func (l *Logger) processEvent(ev *Event) {
	l.lock.Lock()
	defer l.lock.Unlock()

	// After acquiring the lock, Stop may have been called.
	if l.db == nil {
		return
	}
	ev.Received = time.Now().UnixNano()

	tx, err := l.db.Begin()
	if err != nil {
		// This is a fatal error --- can't proceed with database.
		panic(err.Error())
	}

	if ev.wait != nil {
		defer close(ev.wait)
	}

	ev.Serial = l.counter
	l.counter++
	ev.Signature = l.lastSignature
	digest := ev.digest()

	r, s, err := ecdsa.Sign(prng, l.signer, digest)
	ev.Signature = nil

	if err != nil {
		errEv := &ErrorEvent{
			When:    time.Now().UnixNano(),
			Message: "signature: " + err.Error(),
			Event:   ev,
		}

		err = storeError(tx, errEv)
		if err != nil {
			tx.Rollback()
			l.db.Close()
			panic(err.Error())
		}
		tx.Commit()

		if l.stderr != nil {
			fmt.Fprintf(l.stderr, "logger failure:\n%v\n", *errEv)
		}

		l.counter--
		return
	}

	sig := ECDSASignature{R: r, S: s}
	ev.Signature, err = asn1.Marshal(sig)
	if err != nil {
		errEv := &ErrorEvent{
			When:    time.Now().UnixNano(),
			Message: "marshal signature: " + err.Error(),
			Event:   ev,
		}

		err = storeError(tx, errEv)
		if err != nil {
			tx.Rollback()
			l.db.Close()
			panic(err.Error())
		}
		tx.Commit()

		if l.stderr != nil {
			fmt.Fprintf(l.stderr, "logger failure:\n%v\n", *errEv)
		}

		l.counter--
		return
	}

	err = storeEvent(tx, ev)
	if err != nil {
		log.Printf("database error: %v", err)
		tx.Rollback()
		l.db.Close()
		panic(err.Error())
	}
	err = tx.Commit()
	if err != nil {
		panic(err.Error())
	}

	l.lastSignature = ev.Signature
	if ev.Level == "DEBUG" || ev.Level == "INFO" {
		if l.stdout != nil {
			fmt.Fprintf(l.stdout, "%s\n", ev)
		}
	} else {
		if l.stderr != nil {
			fmt.Fprintf(l.stderr, "%s\n", ev)
		}
	}
}

func (l *Logger) processIncoming() {
	for {
		ev, ok := <-l.listener
		if !ok {
			return
		}

		l.processEvent(ev)
	}
}

// Start starts up the audit logger. This must be called prior to
// logging events.
func (l *Logger) Start() error {
	l.listener = make(chan *Event, 16)
	go l.processIncoming()

	return nil
}

// Stop halts the logger and cleanly shuts down the database connection.
func (l *Logger) Stop() {
	for {
		if len(l.listener) == 0 {
			break
		}
		log.Printf("waiting on %d elements", len(l.listener))
		<-time.After(1 * time.Nanosecond)
	}

	l.lock.Lock()
	close(l.listener)
	l.listener = nil
	l.db.Close()
	l.db = nil
	l.lock.Unlock()
}

// New sets up a new logger, using the signer for signatures and
// backed by the database at the specified file. If the database
// exists, the audit chain will be verified.
func New(cd *DBConnDetails, signer *ecdsa.PrivateKey) (*Logger, error) {
	l := &Logger{
		signer: signer,
		stdout: os.Stdout,
		stderr: os.Stderr,
	}

	err := l.setupDB(cd)
	if err != nil {
		return nil, err
	}

	l.counter, err = countEvents(l.db)
	if err != nil {
		return nil, err
	}

	err = l.verifyAuditChain()
	if err != nil {
		return nil, err
	}

	return l, nil
}
