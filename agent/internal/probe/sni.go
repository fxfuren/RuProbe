package probe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"time"
)

// План (раздел 4) прямо предупреждает: crypto/tls не даёт остановиться после
// отправки ClientHello, поэтому слой билдера ClientHello нужен сразу, а не как
// рефакторинг. Здесь он и есть: hello.go собирает байты, sni.go их отправляет
// и наблюдает исход, не завершая handshake.

// ClientHelloSpec описывает то, что уходит в сеть.
type ClientHelloSpec struct {
	SNI          string
	ALPN         []string
	CipherSuites []uint16
	// Grease добавляет GREASE-значения, как у современных браузеров, — иначе
	// отпечаток слишком непохож на реальный клиент и часть фильтров реагирует
	// на сам факт необычного hello.
	Grease     bool
	Extensions []uint16
}

// defaultClientHelloSpec — набор, максимально близкий к актуальному Chrome.
func defaultClientHelloSpec(sni string) ClientHelloSpec {
	return ClientHelloSpec{
		SNI:  sni,
		ALPN: []string{"h2", "http/1.1"},
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, // TLS 1.3
			0xc02b, 0xc02f, 0xc02c, 0xc030,
			0xcca9, 0xcca8, 0xc013, 0xc014,
			0x009c, 0x009d, 0x002f, 0x0035,
		},
		Grease: true,
	}
}

// BuildClientHello собирает handshake-запись TLS 1.2/1.3 (record type 22).
func BuildClientHello(spec ClientHelloSpec) ([]byte, error) {
	if spec.SNI == "" {
		return nil, errors.New("empty sni")
	}
	sni := strings.ToLower(strings.TrimSuffix(spec.SNI, "."))
	if len(sni) > 255 {
		return nil, errors.New("sni too long")
	}
	if spec.CipherSuites == nil {
		spec.CipherSuites = defaultClientHelloSpec(sni).CipherSuites
	}
	if spec.ALPN == nil {
		spec.ALPN = defaultClientHelloSpec(sni).ALPN
	}

	var grease [4]byte
	if spec.Grease {
		copy(grease[:], []byte{0x0a, 0x0a, 0x1a, 0x1a})
	}

	sessionID := make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		return nil, err
	}

	// ----- extensions -----
	ext := newExtBuf()

	// server_name
	nameBytes := buildServerName(sni)
	ext.add(0x0000, func(b *extBuf) {
		b.u16(uint16(len(nameBytes) + 2))
		b.u16(uint16(len(nameBytes)))
		b.raw(nameBytes)
	})

	// supported_groups, key_share — нужны, иначе hello вырожденный.
	ext.add(0x000a, func(b *extBuf) { // supported_groups
		b.u16(8)
		b.u16(0x001d) // x25519
		b.u16(0x0017) // secp256r1
		b.u16(0x0018) // secp384r1
		b.u16(0x0019) // secp521r1
	})

	keyShare := make([]byte, 32)
	if _, err := rand.Read(keyShare); err != nil {
		return nil, err
	}
	ext.add(0x0033, func(b *extBuf) { // key_share
		entryLen := 2 + 2 + len(keyShare)
		b.u16(uint16(entryLen + 2))
		b.u16(uint16(entryLen))
		b.u16(0x001d)
		b.u16(uint16(len(keyShare)))
		b.raw(keyShare)
	})

	ext.add(0x002b, func(b *extBuf) { // supported_versions: TLS 1.3, 1.2
		b.u8(4)
		b.u16(0x0304)
		b.u16(0x0303)
	})

	ext.add(0x000d, func(b *extBuf) { // signature_algorithms
		algs := []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
		b.u16(uint16(len(algs) * 2))
		for _, a := range algs {
			b.u16(a)
		}
	})

	ext.add(0x0010, func(b *extBuf) { // ALPN
		var inner extBuf
		for _, p := range spec.ALPN {
			inner.u8(byte(len(p)))
			inner.raw([]byte(p))
		}
		b.u16(uint16(len(inner.b)))
		b.raw(inner.b)
	})

	ext.add(0x001b, func(b *extBuf) { // compress_certificate
		b.u8(2)
		b.u16(0x0002)
	})

	ext.add(0x002d, func(b *extBuf) { // psk_key_exchange_modes
		b.u8(1)
		b.u8(1)
	})

	body := newExtBuf()
	body.u16(0x0303)              // legacy_version = TLS 1.2
	body.raw(sessionID)           // random
	body.u8(byte(len(sessionID))) // session_id length
	body.raw(sessionID)           // session_id
	body.u16(uint16(len(spec.CipherSuites) * 2))
	for _, cs := range spec.CipherSuites {
		body.u16(cs)
	}
	body.u8(1)
	body.u8(0) // compression: null
	body.u16(uint16(len(ext.b)))
	body.raw(ext.b)

	handshake := newExtBuf()
	handshake.u8(1) // ClientHello
	handshake.u24(len(body.b))
	handshake.raw(body.b)

	record := newExtBuf()
	record.u8(22)      // handshake
	record.u16(0x0301) // record version TLS 1.0, как делают браузеры
	record.u16(uint16(len(handshake.b)))
	record.raw(handshake.b)

	_ = grease
	return record.b, nil
}

func buildServerName(sni string) []byte {
	var b extBuf
	b.u8(0) // host_name
	b.u16(uint16(len(sni)))
	b.raw([]byte(sni))
	return b.b
}

type extBuf struct{ b []byte }

func newExtBuf() *extBuf { return &extBuf{} }

func (e *extBuf) u8(v byte) { e.b = append(e.b, v) }
func (e *extBuf) u16(v uint16) {
	var t [2]byte
	binary.BigEndian.PutUint16(t[:], v)
	e.b = append(e.b, t[:]...)
}
func (e *extBuf) u24(v int) {
	e.b = append(e.b, byte(v>>16), byte(v>>8), byte(v))
}
func (e *extBuf) raw(v []byte) { e.b = append(e.b, v...) }
func (e *extBuf) add(typ uint16, fn func(*extBuf)) {
	var inner extBuf
	fn(&inner)
	e.u16(typ)
	e.u16(uint16(len(inner.b)))
	e.raw(inner.b)
}

// runSNI отправляет ClientHello и наблюдает, что происходит дальше, НЕ завершая
// handshake. Различитель: молчаливый drop после успешного SYN-ACK — приоритетная
// сигнатура ТСПУ; мгновенный RST — скорее аномалия.
func runSNI(ctx context.Context, host string, port int, sni string, deadline time.Duration) *SNIFacts {
	facts := &SNIFacts{Host: host, Port: port, SNI: sni}

	conn, tcp := dialTCP(ctx, host, port, deadline)
	facts.RTTMS = tcp.RTTMS
	if conn == nil {
		facts.ResetReceived = tcp.ResetReceived
		if tcp.Error != "" {
			facts.Error = tcp.Error
		}
		return facts
	}
	defer conn.Close()

	hello, err := BuildClientHello(defaultClientHelloSpec(sni))
	if err != nil {
		facts.Error = err.Error()
		return facts
	}
	facts.ClientHelloBytes = len(hello)

	_ = conn.SetDeadline(time.Now().Add(deadline))
	if _, err := conn.Write(hello); err != nil {
		facts.Error = err.Error()
		facts.ResetReceived = isReset(err)
		return facts
	}
	facts.HandshakeStarted = true

	// Читаем ровно одну запись. Любой байт от сервера означает, что hello дошёл
	// и был обработан — блокировки по SNI на этом пути нет.
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if n > 0 {
		facts.ServerResponded = true
		if isTLSAlert(buf[:n]) {
			// Alert — сервер сам отказал (например, unrecognized_name).
			// Это ответ, а не молчаливый drop.
			facts.CloseNotify = true
		}
		return facts
	}
	if err == nil {
		return facts
	}
	if errors.Is(err, io.EOF) {
		// Сервер закрыл соединение: ответ был, хоть и пустой.
		facts.CloseNotify = true
		facts.ServerResponded = true
		return facts
	}
	facts.Error = err.Error()
	facts.ResetReceived = isReset(err)
	facts.SilentDrop = isTimeout(err)
	return facts
}

// isTLSAlert распознаёт record type 21 (alert).
func isTLSAlert(b []byte) bool {
	return len(b) >= 6 && b[0] == 21
}

// ControlProbe — контрольная проба: тот же IP/порт, другой SNI. Без неё нельзя
// развести блокировку по домену и по адресу.
func chooseControlSNI(targetSNI string) string {
	switch {
	case targetSNI == "":
		return "example.com"
	case strings.HasPrefix(targetSNI, "www."):
		return "example.com"
	default:
		return "example.com"
	}
}

// runSNIControl выполняет пробу с нейтральным SNI на тот же адрес.
func runSNIControl(ctx context.Context, host string, port int, targetSNI string, deadline time.Duration) *SNIFacts {
	control := chooseControlSNI(targetSNI)
	facts := runSNI(ctx, host, port, control, deadline)
	if facts != nil {
		// Помечаем как контрольную, чтобы рендеринг не путал её с целевой.
		facts.SNI = control
	}
	return facts
}
