package probe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"
)

// runUDP различает блокировку транспорта целиком (весь UDP отбрасывается)
// и точечную фильтрацию. С ответом считаем любой байт; ICMP port unreachable
// означает, что хост жив и стек ответил — это не блокировка.
func runUDP(ctx context.Context, host string, port int, protocol string, deadline time.Duration) *UDPFacts {
	facts := &UDPFacts{Host: host, Port: port, Protocol: protocol}

	dctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	d := net.Dialer{}
	conn, err := d.DialContext(dctx, "udp", net.JoinHostPort(host, itoa(port)))
	if err != nil {
		facts.Error = err.Error()
		facts.TimeoutHappened = isTimeout(err)
		return facts
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(deadline))

	payload := buildUDPPayload(protocol)
	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		facts.Error = err.Error()
		facts.TimeoutHappened = isTimeout(err)
		return facts
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	facts.RTTMS = msFloat(time.Since(start))
	if err != nil {
		facts.Error = err.Error()
		facts.TimeoutHappened = isTimeout(err)
		msg := err.Error()
		if containsAny(msg, "connection refused", "unreachable", "icmp") {
			facts.ICMPUnreachable = true
			facts.TimeoutHappened = false
		}
		return facts
	}
	facts.Responded = true
	facts.ResponseBytes = n
	return facts
}

// buildUDPPayload собирает либо QUIC Initial, либо нейтральный DNS-подобный UDP-пробник.
func buildUDPPayload(protocol string) []byte {
	if protocol == "quic" {
		return buildQUICInitial()
	}
	// 64 байта случайных данных: цель — увидеть сам факт ответа сокета.
	payload := make([]byte, 64)
	_, _ = rand.Read(payload)
	return payload
}

// buildQUICInitial формирует минимальный QUIC v1 Initial. Полноценный Initial
// требует шифрования заголовка ключами из Initial salt, поэтому для проверки
// доступности транспорта достаточно корректно размеченного заголовка
// с версией QUIC v1: фильтр по QUIC-листу реагирует уже на него.
func buildQUICInitial() []byte {
	buf := make([]byte, 0, 128)

	// long header, Initial, version 1
	buf = append(buf, 0xc0)
	buf = append(buf, 0x00, 0x00, 0x00, 0x01) // QUIC v1
	dcid := make([]byte, 8)
	scid := make([]byte, 8)
	_, _ = rand.Read(dcid)
	_, _ = rand.Read(scid)
	buf = append(buf, byte(len(dcid)))
	buf = append(buf, dcid...)
	buf = append(buf, byte(len(scid)))
	buf = append(buf, scid...)

	// token length = 0
	buf = append(buf, 0x00)
	// length (varint, 2-байтовая форма 0x40xx)
	payloadLen := 32
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(0x4000|payloadLen))
	buf = append(buf, lenBuf[:]...)

	// Ровно payloadLen байт полезной нагрузки, чтобы длины сходились.
	payload := make([]byte, payloadLen)
	_, _ = rand.Read(payload)
	buf = append(buf, payload...)
	return buf
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) <= len(s) && indexFold(s, sub) >= 0 {
			return true
		}
	}
	return false
}

func indexFold(s, sub string) int {
	n := len(sub)
	for i := 0; i+n <= len(s); i++ {
		if equalFold(s[i:i+n], sub) {
			return i
		}
	}
	return -1
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
