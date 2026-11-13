package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// runTLSFull — сквозная доступность: полный handshake плюс HTTP(S)-запрос.
// Основной различитель тот же: RST против timeout.
func runTLSFull(ctx context.Context, host string, port int, sni string, deadline time.Duration) *TLSFacts {
	facts := &TLSFacts{Host: host, Port: port, SNI: sni}
	if sni == "" {
		sni = host
	}
	start := time.Now()

	dialer := &net.Dialer{Timeout: deadline}
	tlsConn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, itoa(port)), &tls.Config{
		ServerName: sni,
		// Проверка сертификата не наша задача: мы измеряем доступность,
		// а не доверие. Скретч-сертификат не должен выглядеть как блокировка.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	facts.HandshakeMS = msFloat(time.Since(start))
	if err != nil {
		facts.Error = err.Error()
		facts.TimeoutHappened = isTimeout(err)
		facts.ResetReceived = isReset(err)
		facts.TotalMS = msFloat(time.Since(start))
		return facts
	}
	defer tlsConn.Close()

	facts.TLSHandshake = true
	facts.TLSVersion = tlsVersionName(tlsConn.ConnectionState().Version)
	facts.CipherSuite = tls.CipherSuiteName(tlsConn.ConnectionState().CipherSuite)

	_ = tlsConn.SetDeadline(time.Now().Add(deadline))
	req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: RuProbe/1.0\r\nConnection: close\r\n\r\n", sni)
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		facts.Error = err.Error()
		facts.ResetReceived = isReset(err)
		facts.TimeoutHappened = isTimeout(err)
		facts.TotalMS = msFloat(time.Since(start))
		return facts
	}

	// Читаем только заголовки: тело для проверки доступности не нужно.
	br := newLimitedLineReader(tlsConn, 8192)
	if status, ok := br.readStatus(); ok {
		facts.HTTPStatus = status
	} else if err := br.err; err != nil {
		facts.Error = err.Error()
		facts.ResetReceived = isReset(err)
		facts.TimeoutHappened = isTimeout(err)
	}
	facts.TotalMS = msFloat(time.Since(start))
	return facts
}

// runThroughput измеряет пропускную способность. Без этого зонда деградация
// capacity (класс 2.3) не видна: connect и короткий HEAD отвечают 200, а длинная
// передача «пилит» окно и висит.
func runThroughput(ctx context.Context, host string, port int, sni string, bytesRequested int64, deadline time.Duration) *ThroughputFacts {
	facts := &ThroughputFacts{Host: host, Port: port, BytesRequested: bytesRequested}
	if sni == "" {
		sni = host
	}
	scheme := "https"
	if port == 80 {
		scheme = "http"
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{Timeout: deadline}).DialContext,
		TLSClientConfig: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		MaxIdleConns:       1,
		DisableCompression: true,
		DisableKeepAlives:  true,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   deadline,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(host, itoa(port)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		facts.Error = err.Error()
		return facts
	}
	req.Header.Set("User-Agent", "RuProbe/1.0")
	req.Header.Set("Accept", "*/*")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		facts.Error = err.Error()
		facts.ResetReceived = isReset(err)
		facts.TimedOut = isTimeout(err)
		facts.DurationMS = msFloat(time.Since(start))
		return facts
	}
	defer resp.Body.Close()

	// Читаем не больше запрошенного объёма и не дольше дедлайна. Короткие
	// паузы между чтениями и фиксируем — это и есть «пила».
	var received int64
	var lastGap time.Duration
	buf := make([]byte, 32*1024)
	readDeadline := time.Now().Add(deadline)
	_ = resp.Body
	rw := struct {
		r io.Reader
	}{resp.Body}
	for received < bytesRequested && time.Now().Before(readDeadline) {
		before := time.Now()
		n, err := rw.r.Read(buf)
		after := time.Now()
		gap := after.Sub(before)
		if n > 0 {
			if gap > 250*time.Millisecond {
				facts.Sawtooth = true
			}
			received += int64(n)
			lastGap = gap
		}
		if err != nil {
			if isTimeout(err) {
				facts.TimedOut = true
			} else {
				facts.Error = err.Error()
				facts.ResetReceived = isReset(err)
			}
			break
		}
	}
	_ = lastGap

	elapsed := time.Since(start)
	facts.DurationMS = msFloat(elapsed)
	facts.BytesReceived = received
	if elapsed > 0 {
		facts.ThroughputBps = float64(received) * 8 / elapsed.Seconds()
	}
	if received < bytesRequested && !facts.TimedOut && facts.Error == "" {
		// Сервер ответил телом короче запрошенного — это нормально для статики,
		// но если тело оборвалось на середине, это уже сигнал.
		facts.TimedOut = true
	}
	facts.Retransmits = estimateRetransmits(facts, received, elapsed)
	return facts
}

// estimateRetransmits даёт грубую оценку повторных передач: TCP прячет их от
// приложения, поэтому косвенно — по провалам в скорости относительно первых
// прочитанных байт и по «пиле».
func estimateRetransmits(facts *ThroughputFacts, received int64, elapsed time.Duration) int {
	if facts.Error != "" && !facts.TimedOut {
		return 0
	}
	if elapsed <= 0 || received == 0 {
		return 0
	}
	bps := float64(received) / elapsed.Seconds()
	if facts.Sawtooth {
		// Оценка «на глаз»: каждая зафиксированная пауза соответствует
		// примерно одному RTO-циклу. Значение приблизительное, и это отражено
		// в имени поля.
		return 1 + int(float64(received)/65536)
	}
	if bps < 16*1024 {
		return 1
	}
	return 0
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// limitedLineReader читает статусную строку HTTP, не вычитывая тело.
type limitedLineReader struct {
	r     io.Reader
	limit int
	n     int
	err   error
}

func newLimitedLineReader(r io.Reader, limit int) *limitedLineReader {
	return &limitedLineReader{r: r, limit: limit}
}

func (l *limitedLineReader) readStatus() (int, bool) {
	var line []byte
	buf := make([]byte, 1)
	for l.n < l.limit {
		n, err := l.r.Read(buf)
		if n > 0 {
			l.n++
			line = append(line, buf[0])
			if buf[0] == '\n' {
				break
			}
		}
		if err != nil {
			l.err = err
			break
		}
	}
	text := strings.TrimSpace(string(line))
	if !strings.HasPrefix(text, "HTTP/") {
		return 0, false
	}
	parts := strings.SplitN(text, " ", 3)
	if len(parts) < 2 {
		return 0, false
	}
	var code int
	if _, err := fmt.Sscanf(parts[1], "%d", &code); err != nil {
		return 0, false
	}
	return code, true
}
