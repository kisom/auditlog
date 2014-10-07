package auditlog

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// A Certification contains a snapshot an audit chain, errors that
// occurred in the range of events, and a nanosecond-resolution timestamp
// of when the certification was built.
type Certification struct {
	When   int64         `json:"when"`
	Chain  []*Event      `json:"chain"`
	Errors []*ErrorEvent `json:"errors"`
}

// Certify returns a certification for the requested range of events;
// start and end are event serial numbers. The certification is
// returned in JSON.
func (l *Logger) Certify(start, end uint64) ([]byte, error) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if end <= 0 {
		end = l.counter - 1
	}

	attributes := []Attribute{
		{"start", fmt.Sprintf("%d", start)},
		{"end", fmt.Sprintf("%d", end)},
	}
	l.Info("auditlog", "certify", attributes)
	var certification Certification
	var err error

	tx, err := l.db.Begin()
	if err != nil {
		return nil, err
	}

	defer func() {
		if err == nil {
			tx.Commit()
		} else {
			tx.Rollback()
		}
	}()
	certification.Chain, err = loadEvents(tx, start, end)
	if err != nil {
		return nil, err
	}

	certification.Errors, err = loadErrors(tx, start, end)
	if err != nil {
		return nil, err
	}

	certification.When = time.Now().UnixNano()

	return json.Marshal(certification)
}

// VerifyCertification verifies a JSON-encoded certification against
// the signer's public key.
func VerifyCertification(in []byte, signer *ecdsa.PublicKey) (*Certification, bool) {
	var cl Certification
	err := json.Unmarshal(in, &cl)
	if err != nil {
		return nil, false
	}

	if len(cl.Chain) > 0 && cl.Chain[0].Serial == 0 {
		if !cl.Chain[0].Verify(signer, nil) {
			return nil, false
		}
	}

	if len(cl.Chain) > 1 {
		for i := 1; i < len(cl.Chain); i++ {
			if !cl.Chain[i].Verify(signer, cl.Chain[i-1].Signature) {
				return nil, false
			}
		}
	}
	return &cl, true
}

func publicFingerprint(signer *ecdsa.PublicKey) []byte {
	h := sha256.New()
	h.Write(signer.X.Bytes())
	h.Write(signer.Y.Bytes())
	return h.Sum(nil)
}
