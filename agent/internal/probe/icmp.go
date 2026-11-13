package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

const (
	icmpEchoRequest = 8
	icmpEchoReply   = 0
)

// runICMP — базовая живость. Отделяет «сеть мертва» от «заблокирован конкретный протокол».
func runICMP(ctx context.Context, host string, attempts int, deadline time.Duration) *ICMPFacts {
	facts := &ICMPFacts{Host: host, Sent: attempts}
	ip := net.ParseIP(host)
	if ip == nil {
		// Разрешаем имя: ICMP доступен только по адресу.
		rctx, cancel := context.WithTimeout(ctx, dnsQueryTimeout)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupIP(rctx, "ip4", host)
		if err != nil || len(addrs) == 0 {
			facts.Error = "resolve failed"
			facts.TimeoutHappened = true
			facts.PacketLoss = 1
			return facts
		}
		ip = addrs[0]
	}

	var total time.Duration
	for i := 0; i < attempts; i++ {
		rtt, err := icmpOnce(ctx, ip, deadline)
		if err != nil {
			facts.Error = err.Error()
			continue
		}
		facts.Received++
		total += rtt
	}
	if facts.Received > 0 {
		facts.Alive = true
		facts.RTTMS = msFloat(total / time.Duration(facts.Received))
	}
	facts.PacketLoss = float64(facts.Sent-facts.Received) / float64(facts.Sent)
	facts.TimeoutHappened = facts.Received == 0
	return facts
}

// icmpOnce посылает echo через raw-сокет, если он доступен, иначе деградирует
// до TCP-connect на распространённые порты: в контейнере без CAP_NET_RAW
// raw-сокет недоступен, и падать из-за этого нельзя.
func icmpOnce(ctx context.Context, ip net.IP, deadline time.Duration) (time.Duration, error) {
	conn, err := net.DialTimeout("ip4:icmp", ip.String(), deadline)
	if err == nil {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(deadline))

		id := os.Getpid() & 0xffff
		msg := buildICMPEcho(uint16(id), 1)
		start := time.Now()
		if _, err := conn.Write(msg); err != nil {
			return 0, err
		}
		buf := make([]byte, 1500)
		for {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			default:
			}
			n, err := conn.Read(buf)
			if err != nil {
				return 0, err
			}
			if n >= 8 && buf[0] == icmpEchoReply {
				return time.Since(start), nil
			}
		}
	}
	return icmpFallback(ctx, ip, deadline)
}

// icmpFallback — TCP-проба на типовые порты. Это не ICMP, поэтому поле Error
// явно сообщает о деградации: интерпретировать такие данные надо осторожно.
func icmpFallback(ctx context.Context, ip net.IP, deadline time.Duration) (time.Duration, error) {
	for _, port := range []int{443, 80} {
		dctx, cancel := context.WithTimeout(ctx, deadline)
		start := time.Now()
		conn, err := (&net.Dialer{}).DialContext(dctx, "tcp", net.JoinHostPort(ip.String(), itoa(port)))
		cancel()
		if err == nil {
			_ = conn.Close()
			return time.Since(start), nil
		}
	}
	return 0, fmt.Errorf("icmp unavailable: no raw socket and no tcp fallback")
}

func buildICMPEcho(id, seq uint16) []byte {
	msg := make([]byte, 8+16)
	msg[0] = icmpEchoRequest
	msg[1] = 0
	binary.BigEndian.PutUint16(msg[4:6], id)
	binary.BigEndian.PutUint16(msg[6:8], seq)
	for i := 8; i < len(msg); i++ {
		msg[i] = byte(i)
	}
	binary.BigEndian.PutUint16(msg[2:4], checksum(msg))
	return msg
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

// runNeighbors пингует адреса вокруг цели: адресное правило против префикса/CDN.
// Простой перебор /24 даёт больше информации, чем один идеально сделанный зонд.
func runNeighbors(ctx context.Context, host string, scope string, limit int, workers int, deadline time.Duration) *NeighborsFacts {
	facts := &NeighborsFacts{Base: host, Scope: scope}
	base := net.ParseIP(host)
	if base == nil {
		rctx, cancel := context.WithTimeout(ctx, dnsQueryTimeout)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupIP(rctx, "ip4", host)
		if err != nil || len(addrs) == 0 {
			return facts
		}
		base = addrs[0]
	}
	ip4 := base.To4()
	if ip4 == nil {
		return facts
	}

	var candidates []net.IP
	switch scope {
	case "/16":
		prefix := []byte{ip4[0], ip4[1], 0, 0}
		candidates = samplePrefix(prefix, limit)
	default: // /24
		prefix := []byte{ip4[0], ip4[1], ip4[2], 0}
		candidates = samplePrefix(prefix, limit)
	}

	if workers < 1 {
		workers = 16
	}
	sem := make(chan struct{}, workers)
	results := make([]NeighborFact, len(candidates))
	var wg sync.WaitGroup
	for i, cand := range candidates {
		wg.Add(1)
		go func(i int, cand net.IP) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			nctx, cancel := context.WithTimeout(ctx, deadline)
			defer cancel()
			f := NeighborFact{Address: cand.String()}
			rtt, err := icmpOnce(nctx, cand, deadline)
			if err != nil {
				f.Error = err.Error()
			} else {
				f.Alive = true
				f.RTTMS = msFloat(rtt)
			}
			results[i] = f
		}(i, cand)
	}
	wg.Wait()

	for _, r := range results {
		facts.Neighbors = append(facts.Neighbors, r)
		facts.Probed++
		if r.Alive {
			facts.Alive++
		} else {
			facts.Dead++
		}
	}
	return facts
}

// samplePrefix берёт равномерную выборку адресов префикса, исключая .0 и .255.
func samplePrefix(prefix []byte, limit int) []net.IP {
	total := 254
	if len(prefix) == 4 && prefix[2] == 0 && prefix[3] == 0 {
		// /16: берём по одному адресу из каждого из 254 третьих октетов
		total = 254
	}
	if limit <= 0 || limit > total {
		limit = total
	}
	step := total / limit
	if step < 1 {
		step = 1
	}
	var out []net.IP
	for host := 1; host <= total && len(out) < limit; host += step {
		ip := net.IPv4(prefix[0], prefix[1], prefix[2], byte(host))
		if len(prefix) == 4 && prefix[2] == 0 && prefix[3] == 0 {
			ip = net.IPv4(prefix[0], prefix[1], byte(host), 1)
		}
		out = append(out, ip)
	}
	return out
}
