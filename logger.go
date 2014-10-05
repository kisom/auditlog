package logger

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
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
	logs     []*Event
	signer   *ecdsa.PrivateKey
	stdout   io.Writer
	stderr   io.Writer
	lock     sync.Mutex
	listener chan *Event
	errors   []*ErrorEvent
}

func (l *Logger) Public() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&l.signer.PublicKey)
}

func (l *Logger) Count() int {
	l.lock.Lock()
	defer l.lock.Unlock()
	count := len(l.logs)
	return count
}

func (l *Logger) Store(event *Event) error {
	fmt.Fprintf(os.Stderr, "persistent logs not implemented")
	return nil
}

func (l *Logger) logEvent(when int64, level int, actor, event string, attributes []Attribute) {
	if _, ok := LevelStrings[level]; !ok {
		level = LevelUnknown
	}

	ev := &Event{
		When:       time.Now().UnixNano(),
		Level:      LevelStrings[level],
		Actor:      actor,
		Event:      event,
		Attributes: attributes,
	}
	l.listener <- ev
}

func (l *Logger) Debug(actor, event string, attributes []Attribute) {
	go l.logEvent(time.Now().UnixNano(), LevelDebug, actor, event, attributes)
}

func (l *Logger) Info(actor, event string, attributes []Attribute) {
	go l.logEvent(time.Now().UnixNano(), LevelInfo, actor, event, attributes)
}

func (l *Logger) Warning(actor, event string, attributes []Attribute) {
	go l.logEvent(time.Now().UnixNano(), LevelWarning, actor, event, attributes)
}

func (l *Logger) Error(actor, event string, attributes []Attribute) {
	go l.logEvent(time.Now().UnixNano(), LevelError, actor, event, attributes)
}

func (l *Logger) Critical(actor, event string, attributes []Attribute) {
	go l.logEvent(time.Now().UnixNano(), LevelCritical, actor, event, attributes)
}

type ECDSASignature struct {
	R, S *big.Int
}

func (l *Logger) processIncoming() {
	for {
		ev, ok := <-l.listener
		if !ok {
			return
		}

		if l.stdout != nil {
			fmt.Fprintf(l.stdout, "received log: %v\n", ev)
		}

		l.lock.Lock()
		count := len(l.logs)

		if len(l.logs) != 0 {
			ev.Signature = l.logs[count-1].Signature
		}

		digest := ev.Digest()
		r, s, err := ecdsa.Sign(prng, l.signer, digest)
		ev.Signature = nil
		if err != nil {
			errEv := &ErrorEvent{
				When:    time.Now().UnixNano(),
				Message: "signature: " + err.Error(),
				Event:   ev,
			}
			if l.stderr != nil {
				fmt.Fprintf(l.stderr, "logger failure:\n%v\n", errEv)
			}
			l.errors = append(l.errors, errEv)
			l.lock.Unlock()
			continue
		}
		sig := ECDSASignature{R: r, S: s}
		ev.Signature, err = asn1.Marshal(sig)
		if err != nil {
			errEv := &ErrorEvent{
				When:    time.Now().UnixNano(),
				Message: "marshal signature: " + err.Error(),
				Event:   ev,
			}
			if l.stderr != nil {
				fmt.Fprintf(l.stderr, "logger failure:\n%v\n", errEv)
			}
			l.errors = append(l.errors, errEv)
			l.lock.Unlock()
			continue
		}
		l.logs = append(l.logs, ev)
		l.lock.Unlock()
		if l.stdout != nil {
			fmt.Fprintf(l.stdout, "log stored\n")
		}
	}
}

func (l *Logger) Start() {
	l.listener = make(chan *Event, 16)
	go l.processIncoming()
}

func (l *Logger) Stop() {
	l.lock.Lock()
	close(l.listener)
	l.listener = nil
	l.errors = nil
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
