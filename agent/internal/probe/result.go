// Package probe содержит атомарные сетевые зонды и структурированные факты,
// которые они возвращают.
//
// Ключевой принцип (docs/tspu-model.md, раздел 6): зонд возвращает структурированный
// факт, а не булево «доступно». RST и timeout — разные события и фиксируются явно.
package probe

import (
	"errors"
	"time"
)

// Kind — идентификатор зонда.
type Kind string

const (
	KindDNS         Kind = "dns"
	KindDoH         Kind = "doh"
	KindTCP         Kind = "tcp"
	KindTCPAltPorts Kind = "tcp_alt_ports"
	KindSNI         Kind = "sni"
	KindSNIControl  Kind = "sni_control"
	KindTLSFull     Kind = "tls_full"
	KindThroughput  Kind = "throughput"
	KindUDP         Kind = "udp"
	KindICMP        Kind = "icmp"
	KindNeighbors   Kind = "neighbors"
)

// AllKinds — полный набор зондов, который умеет агент.
func AllKinds() []Kind {
	return []Kind{
		KindDNS, KindDoH, KindTCP, KindTCPAltPorts, KindSNI, KindSNIControl,
		KindTLSFull, KindThroughput, KindUDP, KindICMP, KindNeighbors,
	}
}

// Valid сообщает, известен ли такой зонд.
func (k Kind) Valid() bool {
	for _, known := range AllKinds() {
		if k == known {
			return true
		}
	}
	return false
}

// DNSStatus — наблюдаемый исход resolve.
type DNSStatus string

const (
	DNSOK       DNSStatus = "ok"
	DNSNXDomain DNSStatus = "nxdomain"
	DNSRefused  DNSStatus = "refused"
	DNSServfail DNSStatus = "servfail"
	DNSTimeout  DNSStatus = "timeout"
	DNSError    DNSStatus = "error"
)

// DNSAnswer — один резолвер и то, что он ответил.
type DNSAnswer struct {
	Resolver   string    `json:"resolver"`
	Status     DNSStatus `json:"status"`
	Addresses  []string  `json:"addresses,omitempty"`
	CNAMEs     []string  `json:"cnames,omitempty"`
	DurationMS float64   `json:"duration_ms"`
	Error      string    `json:"error,omitempty"`
}

// DNSFacts — совокупность ответов: системный, публичный, DoH.
type DNSFacts struct {
	Query   string      `json:"query"`
	Answers []DNSAnswer `json:"answers"`
	// Mismatch — множество адресов расходится между резолверами: самостоятельный сигнал.
	Mismatch bool `json:"mismatch"`
	// Substituted — публичный/DoH резолвер отдал адрес, которого нет у системного.
	Substituted bool `json:"substituted"`
}

// TCPFacts — исход попытки соединения.
type TCPFacts struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Connected bool   `json:"connected"`
	// ResetReceived — пришёл RST. Отдельное поле, а не «ошибка»: модель
	// трактует мгновенный RST как аномалию, а не как штатное поведение ТСПУ.
	ResetReceived bool `json:"reset_received"`
	// TimeoutHappened — ответа не было до дедлайна (в т.ч. SYN без ответа).
	TimeoutHappened bool    `json:"timeout_happened"`
	RTTMS           float64 `json:"rtt_ms"`
	Error           string  `json:"error,omitempty"`
}

// SNIFacts — результат отправки ClientHello без завершения handshake.
type SNIFacts struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	SNI  string `json:"sni"`
	// HandshakeStarted — SYN-ACK получен и ClientHello отправлен.
	HandshakeStarted bool `json:"handshake_started"`
	// ServerResponded — сервер что-то прислал после ClientHello (ServerHello/Alert).
	ServerResponded bool `json:"server_responded"`
	// SilentDrop — ClientHello ушёл, дальше тишина до таймаута. Приоритетная
	// сигнатура умной блокировки по SNI.
	SilentDrop    bool `json:"silent_drop"`
	ResetReceived bool `json:"reset_received"`
	// CloseNotify — сервер корректно закрыл соединение (alert или FIN) — это не блокировка.
	CloseNotify      bool    `json:"close_notify"`
	ClientHelloBytes int     `json:"client_hello_bytes"`
	RTTMS            float64 `json:"rtt_ms"`
	Error            string  `json:"error,omitempty"`
}

// TLSFacts — полный handshake и опциональный HTTP-запрос.
type TLSFacts struct {
	Host            string  `json:"host"`
	Port            int     `json:"port"`
	SNI             string  `json:"sni"`
	TLSHandshake    bool    `json:"tls_handshake"`
	TLSVersion      string  `json:"tls_version,omitempty"`
	CipherSuite     string  `json:"cipher_suite,omitempty"`
	HTTPStatus      int     `json:"http_status,omitempty"`
	ResetReceived   bool    `json:"reset_received"`
	TimeoutHappened bool    `json:"timeout_happened"`
	HandshakeMS     float64 `json:"handshake_ms"`
	TotalMS         float64 `json:"total_ms"`
	Error           string  `json:"error,omitempty"`
}

// ThroughputFacts — замер передачи. Без этого зонда деградация capacity не видна.
type ThroughputFacts struct {
	Host           string  `json:"host"`
	Port           int     `json:"port"`
	BytesRequested int64   `json:"bytes_requested"`
	BytesReceived  int64   `json:"bytes_received"`
	DurationMS     float64 `json:"duration_ms"`
	ThroughputBps  float64 `json:"throughput_bps"`
	// Retransmits — оценка числа повторных передач по таймерам RTO.
	Retransmits   int    `json:"retransmits"`
	TimedOut      bool   `json:"timed_out"`
	ResetReceived bool   `json:"reset_received"`
	Sawtooth      bool   `json:"sawtooth"`
	Error         string `json:"error,omitempty"`
}

// UDPFacts — UDP-проба, включая QUIC Initial.
type UDPFacts struct {
	Host            string  `json:"host"`
	Port            int     `json:"port"`
	Protocol        string  `json:"protocol"`
	Responded       bool    `json:"responded"`
	ResponseBytes   int     `json:"response_bytes"`
	TimeoutHappened bool    `json:"timeout_happened"`
	ICMPUnreachable bool    `json:"icmp_unreachable"`
	RTTMS           float64 `json:"rtt_ms"`
	Error           string  `json:"error,omitempty"`
}

// ICMPFacts — базовая живость сети.
type ICMPFacts struct {
	Host            string  `json:"host"`
	Alive           bool    `json:"alive"`
	RTTMS           float64 `json:"rtt_ms"`
	PacketLoss      float64 `json:"packet_loss"`
	Sent            int     `json:"sent"`
	Received        int     `json:"received"`
	TimeoutHappened bool    `json:"timeout_happened"`
	Error           string  `json:"error,omitempty"`
}

// NeighborFact — результат пинга одного адреса из окружения цели.
type NeighborFact struct {
	Address string  `json:"address"`
	Alive   bool    `json:"alive"`
	RTTMS   float64 `json:"rtt_ms"`
	Error   string  `json:"error,omitempty"`
}

// NeighborsFacts — адресное правило против префикса/CDN.
type NeighborsFacts struct {
	Base      string         `json:"base"`
	Scope     string         `json:"scope"`
	Probed    int            `json:"probed"`
	Alive     int            `json:"alive"`
	Dead      int            `json:"dead"`
	Neighbors []NeighborFact `json:"neighbors"`
}

// Facts — контейнер для всех фактов пробы одной цели.
type Facts struct {
	DNS         *DNSFacts        `json:"dns,omitempty"`
	DoH         *DNSFacts        `json:"doh,omitempty"`
	TCP         *TCPFacts        `json:"tcp,omitempty"`
	TCPAltPorts []TCPFacts       `json:"tcp_alt_ports,omitempty"`
	SNI         *SNIFacts        `json:"sni,omitempty"`
	SNIControl  *SNIFacts        `json:"sni_control,omitempty"`
	TLSFull     *TLSFacts        `json:"tls_full,omitempty"`
	Throughput  *ThroughputFacts `json:"throughput,omitempty"`
	UDP         *UDPFacts        `json:"udp,omitempty"`
	ICMP        *ICMPFacts       `json:"icmp,omitempty"`
	Neighbors   *NeighborsFacts  `json:"neighbors,omitempty"`
}

// Result — факты по одной цели.
type Result struct {
	Target     string    `json:"target"`
	Kind       string    `json:"kind"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Facts      Facts     `json:"facts"`
	// Errors — непредвиденные ошибки отдельных зондов. Проба остаётся валидной:
	// отсутствующий зонд — это отсутствие данных, а не «недоступно».
	Errors []string `json:"errors,omitempty"`
}

// ErrTimeout — истёк дедлайн пробы.
var ErrTimeout = errors.New("probe timeout")
