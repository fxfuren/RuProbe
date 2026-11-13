package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// dnsQueryTimeout — дедлайн одного resolve.
const dnsQueryTimeout = 4 * time.Second

// PublicResolvers — резолверы, с которыми сравнивается системный.
var PublicResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// DoHEndpoint — шифрованный резолвер. Расхождение с открытым DNS — самостоятельный сигнал.
const DoHEndpoint = "https://cloudflare-dns.com/dns-query"

// runDNS опрашивает системный и публичный резолверы параллельно и сравнивает ответы.
func runDNS(ctx context.Context, host string) *DNSFacts {
	facts := &DNSFacts{Query: host}

	type slot struct {
		resolver string
		fn       func(context.Context, string) DNSAnswer
	}
	calls := []slot{
		{"system", resolveSystem},
	}
	for _, r := range PublicResolvers {
		resolver := r
		calls = append(calls, slot{resolver, func(ctx context.Context, host string) DNSAnswer {
			return resolveUDP(ctx, host, resolver)
		}})
	}

	answers := make([]DNSAnswer, len(calls))
	var wg sync.WaitGroup
	for i, c := range calls {
		wg.Add(1)
		go func(i int, c slot) {
			defer wg.Done()
			qctx, cancel := context.WithTimeout(ctx, dnsQueryTimeout)
			defer cancel()
			answers[i] = c.fn(qctx, host)
		}(i, c)
	}
	wg.Wait()

	facts.Answers = answers
	classifyDNS(facts)
	return facts
}

// runDoH — тот же вопрос через шифрованный резолвер.
func runDoH(ctx context.Context, host string) *DNSFacts {
	facts := &DNSFacts{Query: host}
	qctx, cancel := context.WithTimeout(ctx, dnsQueryTimeout)
	defer cancel()
	answer := resolveDoH(qctx, host, DoHEndpoint)
	facts.Answers = []DNSAnswer{answer}
	return facts
}

// classifyDNS выставляет mismatch/substituted по совокупности ответов.
func classifyDNS(facts *DNSFacts) {
	var base []string
	var baseSet map[string]bool
	for _, a := range facts.Answers {
		if a.Status != DNSOK {
			continue
		}
		set := toStringSet(a.Addresses)
		if base == nil {
			base = a.Addresses
			baseSet = set
			continue
		}
		if !sameSet(baseSet, set) {
			facts.Mismatch = true
			// Подмена — когда внешний резолвер знает адрес, а системный нет.
			for addr := range set {
				if !baseSet[addr] {
					facts.Substituted = true
				}
			}
		}
	}
}

func resolveSystem(ctx context.Context, host string) DNSAnswer {
	start := time.Now()
	answer := DNSAnswer{Resolver: "system"}
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	answer.DurationMS = msFloat(time.Since(start))
	if err != nil {
		answer.Status = statusFromError(err)
		answer.Error = err.Error()
		return answer
	}
	answer.Status = DNSOK
	answer.Addresses = addrs
	if cname, err := net.DefaultResolver.LookupCNAME(ctx, host); err == nil {
		answer.CNAMEs = []string{cname}
	}
	return answer
}

// resolveUDP делает запрос напрямую к указанному резолверу, минуя системный.
// Это принципиально: иначе невозможно отличить «резолвер оператора врёт»
// от «система настроена на другой резолвер».
func resolveUDP(ctx context.Context, host, resolver string) DNSAnswer {
	start := time.Now()
	answer := DNSAnswer{Resolver: resolver}

	query, id, err := buildDNSQuery(host, 1) // A
	if err != nil {
		answer.Status = DNSError
		answer.Error = err.Error()
		return answer
	}

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "udp", resolver)
	if err != nil {
		answer.Status = statusFromError(err)
		answer.Error = err.Error()
		answer.DurationMS = msFloat(time.Since(start))
		return answer
	}
	defer conn.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(query); err != nil {
		answer.Status = statusFromError(err)
		answer.Error = err.Error()
		answer.DurationMS = msFloat(time.Since(start))
		return answer
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	answer.DurationMS = msFloat(time.Since(start))
	if err != nil {
		answer.Status = statusFromError(err)
		answer.Error = err.Error()
		return answer
	}
	status, addrs, cnames := parseDNSResponse(buf[:n], id)
	answer.Status = status
	answer.Addresses = addrs
	answer.CNAMEs = cnames
	return answer
}

func resolveDoH(ctx context.Context, host, endpoint string) DNSAnswer {
	start := time.Now()
	answer := DNSAnswer{Resolver: endpoint}
	query, _, err := buildDNSQuery(host, 1)
	if err != nil {
		answer.Status = DNSError
		answer.Error = err.Error()
		return answer
	}

	url := fmt.Sprintf("%s?dns=%s", endpoint, base64URLNoPad(query))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		answer.Status = DNSError
		answer.Error = err.Error()
		return answer
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := (&http.Client{Timeout: dnsQueryTimeout}).Do(req)
	answer.DurationMS = msFloat(time.Since(start))
	if err != nil {
		answer.Status = statusFromError(err)
		answer.Error = err.Error()
		return answer
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		answer.Status = DNSError
		answer.Error = fmt.Sprintf("doh http %d", resp.StatusCode)
		return answer
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		answer.Status = statusFromError(err)
		answer.Error = err.Error()
		return answer
	}
	status, addrs, cnames := parseDNSResponse(body, 0)
	answer.Status = status
	answer.Addresses = addrs
	answer.CNAMEs = cnames
	return answer
}

// buildDNSQuery собирает минимальный запрос A/AAAA без внешних зависимостей.
func buildDNSQuery(host string, qtype uint16) ([]byte, uint16, error) {
	name := strings.TrimSuffix(host, ".")
	if name == "" {
		return nil, 0, fmt.Errorf("empty dns name")
	}
	id := uint16(time.Now().UnixNano() & 0xffff)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, id)
	binary.Write(buf, binary.BigEndian, uint16(0x0100)) // RD
	binary.Write(buf, binary.BigEndian, uint16(1))      // QDCOUNT
	binary.Write(buf, binary.BigEndian, uint16(0))      // ANCOUNT
	binary.Write(buf, binary.BigEndian, uint16(0))      // NSCOUNT
	binary.Write(buf, binary.BigEndian, uint16(0))      // ARCOUNT

	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, 0, fmt.Errorf("invalid dns label %q", label)
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0)
	binary.Write(buf, binary.BigEndian, qtype)
	binary.Write(buf, binary.BigEndian, uint16(1)) // IN
	return buf.Bytes(), id, nil
}

// parseDNSResponse достаёт rcode и адреса. Усечённые и неразобранные ответы
// не считаются успехом вслепую.
func parseDNSResponse(msg []byte, expectID uint16) (DNSStatus, []string, []string) {
	if len(msg) < 12 {
		return DNSError, nil, nil
	}
	id := binary.BigEndian.Uint16(msg[0:2])
	if expectID != 0 && id != expectID {
		return DNSError, nil, nil
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	rcode := flags & 0x000f
	switch rcode {
	case 0:
		// продолжаем разбор
	case 3:
		return DNSNXDomain, nil, nil
	case 5:
		return DNSRefused, nil, nil
	default:
		return DNSServfail, nil, nil
	}

	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	offset := 12
	for i := 0; i < qd; i++ {
		var ok bool
		offset, ok = skipName(msg, offset)
		if !ok || offset+4 > len(msg) {
			return DNSError, nil, nil
		}
		offset += 4
	}

	var addrs, cnames []string
	for i := 0; i < an; i++ {
		var ok bool
		_, offset, ok = readName(msg, offset, 0)
		if !ok || offset+10 > len(msg) {
			break
		}
		rtype := binary.BigEndian.Uint16(msg[offset : offset+2])
		rdlen := int(binary.BigEndian.Uint16(msg[offset+8 : offset+10]))
		rdataStart := offset + 10
		if rdataStart+rdlen > len(msg) {
			break
		}
		switch rtype {
		case 1: // A
			if rdlen == 4 {
				addrs = append(addrs, net.IP(msg[rdataStart:rdataStart+4]).String())
			}
		case 28: // AAAA
			if rdlen == 16 {
				addrs = append(addrs, net.IP(msg[rdataStart:rdataStart+16]).String())
			}
		case 5: // CNAME
			if name, _, ok := readName(msg, rdataStart, 0); ok {
				cnames = append(cnames, name)
			}
		}
		offset = rdataStart + rdlen
	}
	if len(addrs) == 0 && len(cnames) == 0 {
		return DNSOK, nil, nil
	}
	return DNSOK, addrs, cnames
}

func skipName(msg []byte, offset int) (int, bool) {
	_, next, ok := readName(msg, offset, 0)
	return next, ok
}

// readName разбирает имя, включая компрессию указателями, с защитой от циклов.
func readName(msg []byte, offset, depth int) (string, int, bool) {
	if depth > 16 {
		return "", offset, false
	}
	var labels []string
	pos := offset
	next := offset
	jumped := false
	for {
		if pos >= len(msg) {
			return "", offset, false
		}
		l := int(msg[pos])
		if l == 0 {
			if !jumped {
				next = pos + 1
			}
			break
		}
		if l&0xc0 == 0xc0 {
			if pos+1 >= len(msg) {
				return "", offset, false
			}
			ptr := int(binary.BigEndian.Uint16(msg[pos:pos+2]) & 0x3fff)
			if !jumped {
				next = pos + 2
				jumped = true
			}
			name, _, ok := readName(msg, ptr, depth+1)
			if !ok {
				return "", offset, false
			}
			if name != "" {
				labels = append(labels, name)
			}
			break
		}
		if pos+1+l > len(msg) {
			return "", offset, false
		}
		labels = append(labels, string(msg[pos+1:pos+1+l]))
		pos += 1 + l
	}
	return strings.Join(labels, "."), next, true
}

func statusFromError(err error) DNSStatus {
	if isTimeout(err) {
		return DNSTimeout
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "no such host"):
		return DNSNXDomain
	case strings.Contains(msg, "refused"):
		return DNSRefused
	case strings.Contains(msg, "server misbehaving"):
		return DNSServfail
	}
	return DNSError
}

func base64URLNoPad(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var sb strings.Builder
	for i := 0; i < len(b); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], b[i:])
		sb.WriteByte(alphabet[chunk[0]>>2])
		sb.WriteByte(alphabet[(chunk[0]&0x03)<<4|chunk[1]>>4])
		if n > 1 {
			sb.WriteByte(alphabet[(chunk[1]&0x0f)<<2|chunk[2]>>6])
		}
		if n > 2 {
			sb.WriteByte(alphabet[chunk[2]&0x3f])
		}
	}
	return sb.String()
}

func toStringSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, i := range items {
		set[i] = true
	}
	return set
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
