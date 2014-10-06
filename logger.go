package auditlog

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"os"
	"sync"
	"time"
)

var prng = rand.Reader

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

func (l *Logger) Public() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&l.signer.PublicKey)
}

func (l *Logger) Count() int {
	l.lock.Lock()
	defer l.lock.Unlock()
	// count := len(l.logs)
	return 0
}

func (l *Logger) Store(event *Event) error {
	fmt.Fprintf(os.Stderr, "persistent logs not implemented")
	return nil
}

func (l *Logger) logEvent(when int64, level int, actor, event string, attributes []Attribute, wait chan struct{}) {
	if _, ok := LevelStrings[level]; !ok {
		level = LevelUnknown
	}

	ev := &Event{
		When:       time.Now().UnixNano(),
		Level:      LevelStrings[level],
		Actor:      actor,
		Event:      event,
		Attributes: attributes,
		wait:       wait,
	}
	l.listener <- ev
}

func (l *Logger) Debug(actor, event string, attributes []Attribute) {
	go l.logEvent(time.Now().UnixNano(), LevelDebug, actor, event, attributes, nil)
}

func (l *Logger) Info(actor, event string, attributes []Attribute) {
	go l.logEvent(time.Now().UnixNano(), LevelInfo, actor, event, attributes, nil)
}

func (l *Logger) InfoSync(actor, event string, attributes []Attribute) {
	wait := make(chan struct{}, 0)
	go l.logEvent(time.Now().UnixNano(), LevelInfo, actor, event, attributes, wait)
	<-wait
}

func (l *Logger) Warning(actor, event string, attributes []Attribute) {
	go l.logEvent(time.Now().UnixNano(), LevelWarning, actor, event, attributes, nil)
}

func (l *Logger) Error(actor, event string, attributes []Attribute) {
	go l.logEvent(time.Now().UnixNano(), LevelError, actor, event, attributes, nil)
}

func (l *Logger) Critical(actor, event string, attributes []Attribute) {
	go l.logEvent(time.Now().UnixNano(), LevelCritical, actor, event, attributes, nil)
}

type ECDSASignature struct {
	R, S *big.Int
}

func (l *Logger) processEvent(ev *Event) {
	ev.Received = time.Now().UnixNano()

	if ev.wait != nil {
		go close(ev.wait)
	}

	ev.Serial = l.counter
	l.counter++
	ev.Signature = l.lastSignature
	digest := ev.Digest()

	r, s, err := ecdsa.Sign(prng, l.signer, digest)
	ev.Signature = nil

	err = begin(l.db)
	if err != nil {
		// This is a fatal error --- can't proceed with database.
		panic(err.Error())
	}

	if err != nil {
		errEv := &ErrorEvent{
			When:    time.Now().UnixNano(),
			Message: "signature: " + err.Error(),
			Event:   ev,
		}

		err = storeError(l.db, errEv)
		if err != nil {
			rollback(l.db)
			l.db.Close()
			panic(err.Error())
		}
		commit(l.db)

		if l.stderr != nil {
			fmt.Fprintf(l.stderr, "logger failure:\n%v\n", errEv)
		}
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

		err = storeError(l.db, errEv)
		if err != nil {
			rollback(l.db)
			l.db.Close()
			panic(err.Error())
		}
		commit(l.db)

		if l.stderr != nil {
			fmt.Fprintf(l.stderr, "logger failure:\n%v\n", errEv)
		}
		return
	}

	err = storeEvent(l.db, ev)
	if err != nil {
		rollback(l.db)
		l.db.Close()
		panic(err.Error())
	}
	err = commit(l.db)
	if err != nil {
		panic(err.Error())
	}

	l.lastSignature = ev.Signature
	if l.stdout != nil {
		fmt.Fprintf(l.stdout, "%s\n", ev)
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

func (l *Logger) Start(dbFile string) error {
	err := l.setupDB(dbFile)
	if err != nil {
		return err
	}

	l.listener = make(chan *Event, 16)
	go l.processIncoming()

	return nil
}

func (l *Logger) Stop() {
	l.lock.Lock()
	close(l.listener)
	l.listener = nil
	l.db.Close()
	l.lock.Unlock()
}

func New() (*Logger, error) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), prng)
	if err != nil {
		return nil, err
	}

	return &Logger{
		signer: signer,
		stdout: os.Stdout,
		stderr: os.Stderr,
	}, nil
}
