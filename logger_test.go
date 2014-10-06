package auditlog

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/log"
)

var testlog *Logger

const dbFile = "testdata/audit.db"

func TestLogger(t *testing.T) {
	os.Remove(dbFile)
	var err error
	testlog, err = New()
	if err != nil {
		t.Fatalf("%v", err)
	}

	testlog.Start(dbFile)
	//testlog.stdout = nil
}

func testActor(actorID int) {
	actor := fmt.Sprintf("actor%d", actorID)
	for i := 0; i < 100; i++ {
		testlog.Info(actor, "ping", nil)
	}
}

func TestLogs(t *testing.T) {
	var attrs = []Attribute{
		{"test", "123"},
		{"foo", "bar"},
		{"baz", "quux"},
	}

	testlog.Info("logger_test", "generic", attrs)
	testlog.Warning("logger_test", "warning", attrs)

	<-time.After(250 * time.Millisecond)

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

	_, ok := VerifyCertifiedLog(cl, &testlog.signer.PublicKey)
	if !ok {
		t.Fatal("failed to verified certification")
	}
}

func TestMultipleActors(t *testing.T) {
	for i := 0; i < 4; i++ {
		go testActor(i)
	}
}

func TestError(t *testing.T) {
	prng = &bytes.Buffer{}
	log.Info("auditlog_test", "PRNG failure", nil)
	prng = rand.Reader
}

func BenchmarkTestLogsParallel(b *testing.B) {
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

func BenchmarkCertifyLogsParallel(b *testing.B) {
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
