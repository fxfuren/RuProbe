package probe

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// tcpDial выполняет TCP-соединение и раскладывает исход на три различимых события:
// успех, RST, timeout. Контроль над сокетом нужен, чтобы отличить RST от таймаута
// надёжнее, чем по тексту ошибки (docs/tspu-model.md, раздел 6.2).
func tcpDial(ctx context.Context, host string, port int, deadline time.Duration) TCPFacts {
	facts := TCPFacts{Host: host, Port: port}

	dialCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	start := time.Now()
	conn, err := (&net.Dialer{Timeout: deadline}).DialContext(dialCtx, "tcp", net.JoinHostPort(host, itoa(port)))
	elapsed := time.Since(start)
	facts.RTTMS = msFloat(elapsed)
	if err == nil {
		facts.Connected = true
		_ = conn.Close()
		return facts
	}

	facts.Error = err.Error()
	facts.TimeoutHappened = isTimeout(err)
	facts.ResetReceived = isReset(err)
	if !facts.TimeoutHappened && !facts.ResetReceived {
		// Прочие ошибки (нет маршрута, недоступная сеть) — не блокировка сама по себе,
		// но и не «ресурс жив».
		facts.TimeoutHappened = false
	}
	return facts
}

// dialTCP возвращает также живое соединение — нужно для sni/tls/throughput зондов.
func dialTCP(ctx context.Context, host string, port int, deadline time.Duration) (net.Conn, TCPFacts) {
	facts := TCPFacts{Host: host, Port: port}
	dialCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	start := time.Now()
	conn, err := (&net.Dialer{Timeout: deadline}).DialContext(dialCtx, "tcp", net.JoinHostPort(host, itoa(port)))
	facts.RTTMS = msFloat(time.Since(start))
	if err != nil {
		facts.Error = err.Error()
		facts.TimeoutHappened = isTimeout(err)
		facts.ResetReceived = isReset(err)
		return nil, facts
	}
	facts.Connected = true
	return conn, facts
}

// isTimeout определяет, что ответа не было до дедлайна.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if ok := asNetError(err, &ne); ok && ne.Timeout() {
		return true
	}
	if err == context.DeadlineExceeded {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "timed out")
}

// isReset определяет TCP RST. Кросс-платформенно надёжного типа ошибки нет,
// поэтому проверяем и обёртки, и текст. Список текстовых форм шире, чем кажется
// нужным: на Windows отказ приходит как «No connection could be made because the
// target machine actively refused it» (WSAECONNREFUSED через connectex), и без
// этой строки RST молча терялся бы — то есть ровно тот сигнал, который модель
// считает ключевым различителем.
func isReset(err error) bool {
	if err == nil {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		msg := strings.ToLower(opErr.Err.Error())
		if strings.Contains(msg, "refused") || strings.Contains(msg, "reset") {
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"connection reset",
		"reset by peer",
		"connection refused",
		"actively refused",
		"forcibly closed",
		"wsa econnreset",
		"wsa econnrefused",
		"wsaeconnreset",
		"wsaeconnrefused",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// asNetError — локальная обёртка над errors.As, чтобы не тянуть import в каждый файл.
func asNetError(err error, target *net.Error) bool {
	for err != nil {
		if ne, ok := err.(net.Error); ok {
			*target = ne
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func msFloat(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}
