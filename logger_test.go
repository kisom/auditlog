package logger

import (
	"bytes"
	"crypto/rand"
	"io/ioutil"
	"testing"
	"time"
)

var testlog *Logger

func TestLogger(t *testing.T) {
	var err error
	testlog, err = New()
	if err != nil {
		t.Fatalf("%v", err)
	}

	testlog.Start()
	testlog.stdout = nil
}

func TestLogs(t *testing.T) {
	var attrs = []Attribute{
		{"test", "123"},
		{"foo", "bar"},
		{"baz", "quux"},
	}

	testlog.Info("logger_test", "generic", attrs)
	testlog.Warning("logger_test", "warning", attrs)

	<-time.After(1 * time.Nanosecond)

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
}

func TestErrorLogs(t *testing.T) {
	prng = &bytes.Buffer{}
	testlog.Info("logger_test", "generic", nil)
	<-time.After(1 * time.Nanosecond)
	prng = rand.Reader
	if len(testlog.errors) == 0 {
		t.Fatal("ECDSA signature should have failed")
	}
}

func BenchmarkTestLogsParallel(b *testing.B) {
	for i := 0; i < b.N; i++ {
		var attrs = []Attribute{
			{"test", "123"},
			{"foo", "bar"},
			{"baz", "quux"},
		}
		testlog.Info("logger_test", "generic", attrs)
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
