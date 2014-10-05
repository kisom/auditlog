package logger

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
)

type Attribute struct {
	Name  string
	Value string
}

const (
	LevelUnknown = iota
	LevelDebug
	LevelInfo
	LevelWarning
	LevelError
	LevelCritical
)

var LevelStrings = map[int]string{
	LevelUnknown:  "UNKNOWN",
	LevelDebug:    "DEBUG",
	LevelInfo:     "INFO",
	LevelWarning:  "WARNING",
	LevelError:    "ERROR",
	LevelCritical: "CRITICAL",
}

type Event struct {
	When       int64       `json:"when"`
	Level      string      `json:"level"`
	Actor      string      `json:"actor"`
	Event      string      `json:"event"`
	Attributes []Attribute `json:"attributes"`
	Signature  []byte      `json:"signature"`
}

func (ev *Event) Digest() []byte {
	h := sha256.New()
	binary.Write(h, binary.BigEndian, int64(ev.When))
	h.Write([]byte(ev.Level))
	h.Write([]byte(ev.Actor))
	h.Write([]byte(ev.Event))
	for i := range ev.Attributes {
		h.Write([]byte(ev.Attributes[i].Name))
		h.Write([]byte(ev.Attributes[i].Value))
	}
	h.Write(ev.Signature)
	return h.Sum(nil)
}

func (ev *Event) Verify(signer *ecdsa.PublicKey, prev []byte) bool {
	sig := ev.Signature
	ev.Signature = prev
	digest := ev.Digest()
	ev.Signature = sig

	var signature ECDSASignature
	remaining, err := asn1.Unmarshal(sig, &signature)
	if err != nil || len(remaining) > 0 {
		return false
	}

	return ecdsa.Verify(signer, digest, signature.R, signature.S)
}

type ErrorEvent struct {
	When    int64  `json:"when"`
	Message string `json:"message"`
	// Signature []byte `json:"signature"`
	Event *Event `json:"event"`
}
