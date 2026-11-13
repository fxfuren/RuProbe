package probe

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// TargetKind — что именно за цель пришла от бота.
type TargetKind string

const (
	TargetIP      TargetKind = "net"
	TargetDomain  TargetKind = "domain"
	TargetRange   TargetKind = "range"
	TargetCIDR    TargetKind = "cidr"
	TargetUnknown TargetKind = "unknown"
)

// Target — нормализованная цель пробы.
type Target struct {
	Raw  string     `json:"raw"`
	Kind TargetKind `json:"kind"`
	IP   net.IP     `json:"-"`
	Host string     `json:"host,omitempty"`
	// CIDR заполнен для диапазонов: /29 раскрывается в адреса.
	CIDR *net.IPNet `json:"-"`
}

// ParseTarget без обращения к сети распознаёт вид цели.
func ParseTarget(raw string) (Target, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return Target{}, fmt.Errorf("empty target")
	}
	t := Target{Raw: value, Kind: TargetUnknown}

	if _, ipnet, err := net.ParseCIDR(value); err == nil {
		t.CIDR = ipnet
		t.Kind = TargetCIDR
		return t, nil
	}
	if ip := net.ParseIP(value); ip != nil {
		t.IP = ip
		t.Kind = TargetIP
		return t, nil
	}
	// Диапазон вида 1.2.3.4-1.2.3.20 или 1.2.3.4-20.
	if lo, hi, ok := splitRange(value); ok {
		t.Kind = TargetRange
		t.Host = lo.String()
		if hi != nil {
			t.CIDR = rangeToCIDRHint(lo, hi)
		}
		return t, nil
	}
	if looksLikeDomain(value) {
		t.Kind = TargetDomain
		t.Host = strings.ToLower(strings.TrimSuffix(value, "."))
		return t, nil
	}
	return t, fmt.Errorf("unrecognized target %q", value)
}

// Expand разворачивает диапазон/CIDR в список адресов с ограничением сверху:
// /16 не должен превращаться в 65536 проб.
func (t Target) Expand(limit int) []string {
	if t.Kind != TargetCIDR || t.CIDR == nil {
		return []string{t.Raw}
	}
	if limit <= 0 {
		limit = 32
	}
	var out []string
	ip := t.CIDR.IP.Mask(t.CIDR.Mask)
	for t.CIDR.Contains(ip) && len(out) < limit {
		out = append(out, ip.String())
		next := make(net.IP, len(ip))
		copy(next, ip)
		incIP(next)
		ip = next
	}
	return out
}

func splitRange(value string) (net.IP, net.IP, bool) {
	parts := strings.SplitN(value, "-", 2)
	if len(parts) != 2 {
		return nil, nil, false
	}
	lo := net.ParseIP(strings.TrimSpace(parts[0]))
	if lo == nil {
		return nil, nil, false
	}
	hiRaw := strings.TrimSpace(parts[1])
	if hi := net.ParseIP(hiRaw); hi != nil {
		return lo, hi, true
	}
	// Короткая форма: 1.2.3.4-20
	if n, err := strconv.Atoi(hiRaw); err == nil {
		lo4 := lo.To4()
		if lo4 == nil || n < 0 || n > 255 {
			return nil, nil, false
		}
		return lo, net.IPv4(lo4[0], lo4[1], lo4[2], byte(n)), true
	}
	return nil, nil, false
}

func rangeToCIDRHint(lo, hi net.IP) *net.IPNet {
	if hi == nil {
		return nil
	}
	// Для подсказки о префиксе достаточно /24 вокруг начала диапазона; точная
	// агрегация диапазонов в CIDR здесь не нужна.
	lo4 := lo.To4()
	if lo4 == nil {
		return nil
	}
	_, ipnet, err := net.ParseCIDR(fmt.Sprintf("%d.%d.%d.0/24", lo4[0], lo4[1], lo4[2]))
	if err != nil {
		return nil
	}
	return ipnet
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func looksLikeDomain(value string) bool {
	if len(value) > 253 {
		return false
	}
	if !strings.Contains(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := c == '-' || c == '_' ||
				('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9')
			if !ok {
				return false
			}
		}
	}
	return true
}

// Options — параметры одной пробы.
type Options struct {
	Target          Target
	Kinds           []Kind
	Port            int
	Timeout         time.Duration
	ThroughputBytes int64
	// NeighborLimit ограничивает перебор соседей: /24 целиком — это 254 пробы.
	NeighborLimit int
	NeighborScope string
	Workers       int
}

// DefaultPorts — порты для зонда tcp_alt_ports: правило по порту против правила по IP.
var DefaultPorts = []int{443, 80, 8080, 8443}

// Run выполняет запрошенные зонды для одной цели и собирает структурированные факты.
// Зонды независимы: падение одного не отменяет остальные, а лишь оставляет пробел
// в данных — «нет данных» и «недоступно» не одно и то же.
func Run(ctx context.Context, opts Options) Result {
	started := time.Now()
	res := Result{
		Target:    opts.Target.Raw,
		Kind:      string(opts.Target.Kind),
		StartedAt: started,
	}
	port := opts.Port
	if port == 0 {
		port = 443
	}
	deadline := opts.Timeout
	if deadline <= 0 {
		deadline = 5 * time.Second
	}
	host := probeHost(opts.Target)
	sni := ""
	if opts.Target.Kind == TargetDomain {
		sni = opts.Target.Host
	}

	requested := map[Kind]bool{}
	for _, k := range opts.Kinds {
		requested[k] = true
	}
	want := func(k Kind) bool { return requested[k] || len(requested) == 0 }

	if want(KindDNS) {
		if opts.Target.Kind == TargetDomain {
			res.Facts.DNS = runDNS(ctx, opts.Target.Host)
		}
	}
	if want(KindDoH) && opts.Target.Kind == TargetDomain {
		res.Facts.DoH = runDoH(ctx, opts.Target.Host)
	}
	if want(KindTCP) {
		facts := tcpDial(ctx, host, port, deadline)
		res.Facts.TCP = &facts
	}
	if want(KindTCPAltPorts) {
		for _, p := range DefaultPorts {
			if p == port {
				continue
			}
			res.Facts.TCPAltPorts = append(res.Facts.TCPAltPorts, tcpDial(ctx, host, p, deadline))
		}
	}
	if want(KindSNI) {
		res.Facts.SNI = runSNI(ctx, host, port, sniOrHost(sni, host), deadline)
	}
	if want(KindSNIControl) {
		res.Facts.SNIControl = runSNIControl(ctx, host, port, sni, deadline)
	}
	if want(KindTLSFull) {
		res.Facts.TLSFull = runTLSFull(ctx, host, port, sni, deadline)
	}
	if want(KindThroughput) {
		bytesWanted := opts.ThroughputBytes
		if bytesWanted <= 0 {
			bytesWanted = 1 << 20
		}
		res.Facts.Throughput = runThroughput(ctx, host, port, sni, bytesWanted, deadline)
	}
	if want(KindUDP) {
		res.Facts.UDP = runUDP(ctx, host, 443, "quic", deadline)
	}
	if want(KindICMP) {
		res.Facts.ICMP = runICMP(ctx, host, 3, deadline)
	}
	if want(KindNeighbors) {
		scope := opts.NeighborScope
		if scope == "" {
			scope = "/24"
		}
		res.Facts.Neighbors = runNeighbors(ctx, host, scope, opts.NeighborLimit, opts.Workers, deadline)
	}

	res.FinishedAt = time.Now()
	return res
}

func probeHost(t Target) string {
	switch t.Kind {
	case TargetDomain:
		return t.Host
	case TargetIP:
		return t.IP.String()
	case TargetRange:
		if t.Host != "" {
			return t.Host
		}
	}
	if t.CIDR != nil {
		return t.CIDR.IP.String()
	}
	return t.Raw
}

func sniOrHost(sni, host string) string {
	if sni != "" {
		return sni
	}
	return host
}
