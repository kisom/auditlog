package auditlog

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"testing"
	"time"
)

var testlog *Logger

const dbFile = "testdata/audit.db"

func TestLogger(t *testing.T) {
	os.Remove(dbFile)

	signer, err := ecdsa.GenerateKey(elliptic.P256(), prng)
	if err != nil {
		t.Fatalf("%v", err)
	}

	testlog, err = New(dbFile, signer)
	if err != nil {
		t.Fatalf("%v", err)
	}

	testlog.Start()
	testlog.stdout = nil
}

func testActor(actorID, count int, wg *sync.WaitGroup) {
	actor := fmt.Sprintf("actor%d", actorID)
	for i := 0; i < count; i++ {
		testlog.InfoSync(actor, "ping", nil)
	}

	wg.Done()
}

func TestLogs(t *testing.T) {
	var attrs = []Attribute{
		{"test", "123"},
		{"foo", "bar"},
		{"baz", "quux"},
	}

	testlog.InfoSync("logger_test", "generic", attrs)
	testlog.WarningSync("logger_test", "warning", attrs)
}

func TestError(t *testing.T) {
	prng = &bytes.Buffer{}
	testlog.InfoSync("auditlog_test", "PRNG failure", nil)
	prng = rand.Reader
}

func TestMultipleActors(t *testing.T) {
	wg := new(sync.WaitGroup)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go testActor(i, 10, wg)
	}
	wg.Wait()
}

func TestLoad(t *testing.T) {
	testlog.Stop()

	signer := testlog.signer

	var err error
	testlog, err = New(dbFile, signer)
	if err != nil {
		t.Fatalf("%v", err)
	}

	testlog.Start()
}

func TestCertification(t *testing.T) {
	pub, err := testlog.Public()
	if err != nil {
		t.Fatalf("%v", err)
	}
	ioutil.WriteFile("logger.pub", pub, 0644)

	cl, err := testlog.Certify(0, 0)
	if err != nil {
		t.Fatalf("%v", err)
	}
	ioutil.WriteFile("certified.json", cl, 0644)

	_, ok := VerifyCertification(cl, &testlog.signer.PublicKey)
	if !ok {
		t.Fatal("failed to verified certification")
	}
}

func TestMultipleActorsExtended(t *testing.T) {
	wg := new(sync.WaitGroup)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go testActor(i, 10000, wg)
	}
	wg.Wait()
}

func BenchmarkTestLogs(b *testing.B) {
	for i := 0; i < b.N; i++ {
		var attrs = []Attribute{
			{"test", "123"},
			{"foo", "bar"},
			{"baz", "quux"},
		}
		testlog.InfoSync("logger_test", "generic", attrs)
		<-time.After(1 * time.Nanosecond)
	}
}

func BenchmarkCertifyLogs(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := testlog.Certify(0, 0)
		if err != nil {
			b.Fatalf("%v", err)
		}
	}
	b.StopTimer()
	cl, err := testlog.Certify(0, 0)
	if err != nil {
		b.Fatalf("%v", err)
	}
	ioutil.WriteFile("certified_bench.json", cl, 0644)
}
