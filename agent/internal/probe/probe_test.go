package probe

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestTCPResetVsTimeout — ключевой различитель из модели: RST и молчаливый
// drop должны раскладываться в разные поля, а не в одно «недоступно».

func TestTCPResetIsDistinguishedFromTimeout(t *testing.T) {
	// Слушатель с крошечным backlog: часть connect'ов получит RST.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Закрываем сразу, чтобы клиент получил RST на следующей попытке.
	ln.Close()

	facts := tcpDial(context.Background(), "127.0.0.1", portOf(t, ln), 800*time.Millisecond)
	if facts.Connected {
		t.Fatalf("expected failure after listener closed, got connected")
	}
	if !facts.ResetReceived && !facts.TimeoutHappened {
		t.Fatalf("neither reset nor timeout recorded: %+v", facts)
	}
	if facts.ResetReceived && facts.TimeoutHappened {
		t.Fatalf("reset and timeout must be mutually exclusive here: %+v", facts)
	}
}

func TestTCPTimeoutOnBlackhole(t *testing.T) {
	// 192.0.2.0/24 — TEST-NET-1, адрес не отвечает: это чистый таймаут.
	facts := tcpDial(context.Background(), "192.0.2.1", 443, 400*time.Millisecond)
	if facts.Connected {
		t.Skip("unexpected connectivity to TEST-NET-1")
	}
	if !facts.TimeoutHappened {
		t.Errorf("expected timeout for blackholed address, got %+v", facts)
	}
	if facts.ResetReceived {
		t.Errorf("blackhole must not report RST, got %+v", facts)
	}
}

func TestTCPConnectSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	facts := tcpDial(context.Background(), "127.0.0.1", portOf(t, ln), time.Second)
	if !facts.Connected {
		t.Fatalf("expected success, got %+v", facts)
	}
	if facts.ResetReceived || facts.TimeoutHappened {
		t.Errorf("successful connect must not set reset/timeout: %+v", facts)
	}
}

// TestSNISilentDrop: сервер принимает TCP и молчит после ClientHello — это и есть
// приоритетная сигнатура умной блокировки по SNI.
func TestSNISilentDrop(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf) // читаем ClientHello и не отвечаем
		time.Sleep(2 * time.Second)
	}()

	facts := runSNI(context.Background(), "127.0.0.1", portOf(t, ln), "blocked.example", 500*time.Millisecond)
	if !facts.HandshakeStarted {
		t.Fatalf("handshake should have started: %+v", facts)
	}
	if !facts.SilentDrop {
		t.Errorf("expected silent drop, got %+v", facts)
	}
	if facts.ResetReceived {
		t.Errorf("silent drop must not be reported as RST: %+v", facts)
	}
}

// TestClientHelloIsWellFormed проверяет, что собранный hello вообще разбирается
// как TLS-record: без этого зонд отправлял бы мусор и все ответы были бы ложными.
func TestClientHelloIsWellFormed(t *testing.T) {
	hello, err := BuildClientHello(defaultClientHelloSpec("example.com"))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(hello) < 60 {
		t.Fatalf("hello suspiciously short: %d bytes", len(hello))
	}
	if hello[0] != 22 {
		t.Errorf("record type = %d, want 22 (handshake)", hello[0])
	}
	recordLen := int(hello[3])<<8 | int(hello[4])
	if recordLen != len(hello)-5 {
		t.Errorf("record length %d does not match payload %d", recordLen, len(hello)-5)
	}
	if hello[5] != 1 {
		t.Errorf("handshake type = %d, want 1 (ClientHello)", hello[5])
	}
	// SNI должен присутствовать в открытом виде — иначе зонд бессмыслен,
	// поскольку фильтр извлекает SNI именно оттуда.
	if !containsSubslice(hello, []byte("example.com")) {
		t.Errorf("SNI not found in ClientHello")
	}
}

func TestParseTargetKinds(t *testing.T) {
	cases := []struct {
		raw  string
		want TargetKind
	}{
		{"1.2.3.4", TargetIP},
		{"example.com", TargetDomain},
		{"5.6.7.0/29", TargetCIDR},
		{"1.2.3.4-1.2.3.20", TargetRange},
		{"1.2.3.4-20", TargetRange},
		{"not a target!", TargetUnknown},
	}
	for _, c := range cases {
		got, err := ParseTarget(c.raw)
		if c.want == TargetUnknown {
			if err == nil {
				t.Errorf("%q: expected error, got %v", c.raw, got.Kind)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.raw, err)
			continue
		}
		if got.Kind != c.want {
			t.Errorf("%q: kind = %s, want %s", c.raw, got.Kind, c.want)
		}
	}
}

func TestCIDRExpansionIsBounded(t *testing.T) {
	target, err := ParseTarget("192.0.2.0/24")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	addrs := target.Expand(8)
	if len(addrs) != 8 {
		t.Fatalf("expected 8 addresses, got %d", len(addrs))
	}
	if addrs[0] != "192.0.2.0" {
		t.Errorf("first address = %s, want 192.0.2.0", addrs[0])
	}
}

func portOf(t *testing.T, ln net.Listener) int {
	t.Helper()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected addr type %T", ln.Addr())
	}
	return addr.Port
}

func containsSubslice(haystack, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}

// TestICMPChecksum проверяет арифметику контрольной суммы по её определению:
// сумма всех 16-битных слов вместе с записанной контрольной суммой даёт 0xffff.
func TestICMPChecksum(t *testing.T) {
	msg := buildICMPEcho(1, 1)
	sum := uint32(0)
	for i := 0; i+1 < len(msg); i += 2 {
		sum += uint32(msg[i])<<8 | uint32(msg[i+1])
	}
	if len(msg)%2 == 1 {
		sum += uint32(msg[len(msg)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if sum != 0xffff {
		t.Errorf("checksum verification sum = %#x, want 0xffff", sum)
	}
}
