package logger

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type Certification struct {
	When      int64  `json:"when"`
	Certified []byte `json:"certified"`
	Signature []byte `json:"signature"`
}

type CertifiedLogs struct {
	When   int64         `json:"when"`
	Logs   []*Event      `json:"logs"`
	Errors []*ErrorEvent `json:"errors"`
}

func (l *Logger) Certify(start, end int) ([]byte, error) {
	l.lock.Lock()
	if end == 0 {
		end = len(l.logs)
	}
	if start < 0 || end > len(l.logs)+1 || end < start {
		l.lock.Unlock()
		return nil, errors.New("logger: invalid log range")
	}
	tbsCertified := &CertifiedLogs{
		When:   time.Now().UnixNano(),
		Logs:   l.logs[start:end],
		Errors: l.errors[:],
	}
	l.lock.Unlock()

	attrs := []Attribute{
		{"log_count", fmt.Sprintf("%d", len(l.logs))},
		{"error_count", fmt.Sprintf("%d", len(l.errors))},
	}
	l.Info("logger", "certify", attrs)

	certified, err := json.Marshal(tbsCertified)
	if err != nil {
		attrs = append(attrs, Attribute{
			Name:  "message",
			Value: err.Error(),
		})
		attrs = append(attrs, Attribute{
			Name:  "stage",
			Value: "marshal",
		})
		l.Critical("logger", "certify", attrs)
		return nil, err
	}

	digest := sha256.Sum256(certified)
	r, s, err := ecdsa.Sign(prng, l.signer, digest[:])
	if err != nil {
		attrs = append(attrs, Attribute{
			Name:  "message",
			Value: err.Error(),
		})
		attrs = append(attrs, Attribute{
			Name:  "stage",
			Value: "sign",
		})
		l.Critical("logger", "certify", attrs)
		return nil, err
	}

	signature, err := asn1.Marshal(ECDSASignature{R: r, S: s})
	if err != nil {
		attrs = append(attrs, Attribute{
			Name:  "message",
			Value: err.Error(),
		})
		attrs = append(attrs, Attribute{
			Name:  "stage",
			Value: "sign",
		})
		l.Critical("logger", "certify", attrs)
		return nil, err
	}

	cl := &Certification{
		When:      tbsCertified.When,
		Certified: certified,
		Signature: signature,
	}

	out, err := json.Marshal(cl)
	if err != nil {
		attrs = append(attrs, Attribute{
			Name:  "message",
			Value: err.Error(),
		})
		attrs = append(attrs, Attribute{
			Name:  "stage",
			Value: "sign",
		})
		l.Critical("logger", "certify", attrs)
		return nil, err
	}

	return out, nil
}

func VerifyCertifiedLog(in []byte, signer *ecdsa.PublicKey) (*CertifiedLogs, bool) {
	var cl Certification
	err := json.Unmarshal(in, &cl)
	if err != nil {
		fmt.Println("failed to unmarshal certification")
		return nil, false
	}

	var signature ECDSASignature
	remaining, err := asn1.Unmarshal(cl.Signature, &signature)
	if err != nil || len(remaining) > 0 {
		fmt.Println("trailing signature data")
		return nil, false
	}

	digest := sha256.Sum256(cl.Certified)
	if !ecdsa.Verify(signer, digest[:], signature.R, signature.S) {
		fmt.Println("ecdsa signature validation failed")
		return nil, false
	}

	var logs CertifiedLogs
	err = json.Unmarshal(cl.Certified, &logs)
	if err != nil {
		fmt.Println("failed to unmarshal certified logs")
		return nil, false
	}

	if len(logs.Logs) > 1 {
		for i := 1; i < len(logs.Logs); i++ {
			if !logs.Logs[i].Verify(signer, logs.Logs[i-1].Signature) {
				fmt.Printf("event %d is invalid\n", i)
			}
		}
	}
	return &logs, true
}
