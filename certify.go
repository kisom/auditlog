package auditlog

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"time"
)

type Certification struct {
	When   int64         `json:"when"`
	Chain  []*Event      `json:"chain"`
	Errors []*ErrorEvent `json:"errors"`
	Public []byte        `json:"public"`
}

func (l *Logger) Certify(start, end uint64) ([]byte, error) {
	if end <= 0 {
		end = l.counter - 1
	}

	attributes := []Attribute{
		{"start", fmt.Sprintf("%d", start)},
		{"end", fmt.Sprintf("%d", end)},
	}
	l.InfoSync("auditlog", "certify", attributes)
	var certification Certification
	var err error

	certification.Chain, err = loadEvents(l.db, start, end)
	if err != nil {
		return nil, err
	}

	certification.When = time.Now().UnixNano()
	certification.Public, err = l.Public()
	if err != nil {
		return nil, err
	}

	return json.Marshal(certification)
}

func VerifyCertifiedLog(in []byte, signer *ecdsa.PublicKey) (*Certification, bool) {
	var cl Certification
	err := json.Unmarshal(in, &cl)
	if err != nil {
		return nil, false
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
