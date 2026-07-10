// Package config provides configuration types, loading, generation, and validation.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

// ServerConfig is the top-level configuration structure for the DNS server.
type ServerConfig struct {
	Server   ServerSettings   `json:"server"`
	Upstream []UpstreamServer `json:"upstream"`
	Fallback []UpstreamServer `json:"fallback,omitempty"`
	Zone     ZoneConfig       `json:"zone"`
	CIDR     []CIDRConfig     `json:"cidr"`
}

// ServerSettings contains the server runtime settings and feature flags.
type ServerSettings struct {
	Port     string           `json:"port"`
	Pprof    string           `json:"pprof"`
	LogLevel string           `json:"log_level"`
	TLS      TLSSettings      `json:"tls"`
	DNSCrypt DNSCryptSettings `json:"dnscrypt,omitempty"`
	Features FeatureFlags     `json:"features"`
}

// DNSCryptSettings configures the DNSCrypt v2 encrypted DNS listener.
type DNSCryptSettings struct {
	Port         string `json:"port"`               // default "8443"
	ProviderName string `json:"provider_name"`      // e.g. "2.dnscrypt-cert.example.com"
	PrivateKey   string `json:"private_key"`        // Ed25519 private key (hex, optional)
	PublicKey    string `json:"public_key"`         // Ed25519 public key (hex, optional)
	ResolverSk   string `json:"resolver_sk"`        // X25519 secret or X-Wing seed (hex, optional; key type determined by es_version)
	ResolverPk   string `json:"resolver_pk"`        // X25519 public or X-Wing public (hex, optional; key type determined by es_version)
	ESVersion    string `json:"es_version"`         // "xwingpq" (default) or "xchacha20poly1305"
	CertTTL      string `json:"cert_ttl,omitempty"` // "30d", "720h", "86400s", "86400"; empty defaults to 365 days
}

// IsEnabled reports whether DNSCrypt is configured.  An empty DNSCryptSettings
// block means DNSCrypt is disabled.
func (d *DNSCryptSettings) IsEnabled() bool {
	return d.ProviderName != "" || d.PublicKey != "" || d.PrivateKey != ""
}

// DNSCryptConfigGenerator is a hook for generating DNSCrypt server + client
// JSON configuration.  Set by server/dnscrypt's init() to avoid a layering
// violation (internal/cli must not import server/dnscrypt).
var DNSCryptConfigGenerator func(provider, addr, esVersion, certTTL string) (string, error)

// TLSSettings configures TLS listener ports, certificates, and HTTPS settings.
type TLSSettings struct {
	Port       string        `json:"port"`
	CertFile   string        `json:"cert_file"`
	KeyFile    string        `json:"key_file"`
	SelfSigned bool          `json:"self_signed"`
	HTTPS      HTTPSSettings `json:"https"`
	KTLS       *KTLSSettings `json:"ktls,omitempty"`
}

// HTTPSSettings configures the HTTPS (DoH/DoH3) listener port and endpoint.
type HTTPSSettings struct {
	Port     string `json:"port"`
	Endpoint string `json:"endpoint"`
}

// KTLSSettings configures kernel TLS offload for DoT/DoH server listeners.
type KTLSSettings struct {
	KernelTX bool `json:"kernel_tx"` // kernel TLS TX offload (default false)
	KernelRX bool `json:"kernel_rx"` // kernel TLS RX offload (default false)
}

// FeatureFlags enables optional features: hijack protection, DDR, ECS,
// database, cache, latency probes, and stats.
type FeatureFlags struct {
	HijackProtection bool               `json:"hijack_protection"`
	DNSSECEnforce    bool               `json:"dnssec_enforce,omitempty"`
	DDR              DDRSettings        `json:"ddr,omitempty"`
	ECS              ECSConfig          `json:"ecs_subnet,omitempty"`
	Database         DatabaseSettings   `json:"database,omitempty"`
	Cache            CacheSettings      `json:"cache,omitempty"`
	LatencyProbe     []LatencyProbeStep `json:"latency_probe,omitempty"`
}

// DDRSettings configures Discovery of Designated Resolvers (DDR) advertisement.
type DDRSettings struct {
	Domain string `json:"domain"`
	IPv4   string `json:"ipv4"`
	IPv6   string `json:"ipv6"`
}

// DatabaseSettings configures the shared SQLite database backing cache and zone.
type DatabaseSettings struct {
	DBPath      string `json:"db_path,omitempty"`       // database file path
	MMapSizeMB  int    `json:"mmap_size_mb,omitempty"`  // SQLite mmap_size PRAGMA
	CacheSizeMB int    `json:"cache_size_mb,omitempty"` // SQLite cache_size PRAGMA
}

// CacheSettings configures DNS response cache size and stale serving.
type CacheSettings struct {
	MaxEntries  int  `json:"max_entries,omitempty"`
	PreferStale bool `json:"prefer_stale,omitempty"`
}

// UpstreamServer defines a single upstream DNS server with address, protocol,
// and optional matching.
type UpstreamServer struct {
	Address       string   `json:"address"`
	Protocol      string   `json:"protocol"`
	ServerName    string   `json:"server_name,omitempty"`
	SkipTLSVerify bool     `json:"skip_tls_verify,omitempty"`
	NoCache       bool     `json:"no_cache,omitempty"`
	Match         []string `json:"match,omitempty"`
	Proxy         string   `json:"proxy,omitempty"`      // socks5://[user:pass@]host:port
	PublicKey     string   `json:"public_key,omitempty"` // DNSCrypt resolver public key (hex); provider name uses server_name
}

// ZoneConfig wraps zone rules and global zone settings.
type ZoneConfig struct {
	Rules      []ZoneRule `json:"rules"`
	BypassTags []string   `json:"bypass_tags,omitempty"` // tags that skip all zone rules
}

// ZoneRule defines a DNS zone rule for constructing synthetic responses.
// Matches on (QNAME, QTYPE, QCLASS) and returns ANSWER + AUTHORITY +
// ADDITIONAL + RCODE.  Client filtering uses CIDR match tags.
type ZoneRule struct {
	Name       string       `json:"name"`                 // domain or *.domain
	File       string       `json:"file,omitempty"`       // CSV import path
	Match      []string     `json:"match,omitempty"`      // CIDR tags (mirrors UpstreamServer.Match)
	Rcode      int          `json:"rcode,omitempty"`      // response code (0 = NOERROR)
	Answer     []ZoneRecord `json:"answer,omitempty"`     // ANSWER section RRs
	Authority  []ZoneRecord `json:"authority,omitempty"`  // AUTHORITY section RRs
	Additional []ZoneRecord `json:"additional,omitempty"` // ADDITIONAL section RRs

	NormalizedName   string          `json:"-"`
	CachedAnswer     []dns.RR        `json:"-"`
	CachedAuthority  []dns.RR        `json:"-"`
	CachedAdditional []dns.RR        `json:"-"`
	DynamicContent   func() []string `json:"-"`
}

// ZoneRecord defines a single DNS resource record for zone responses.
// Type and Class are numeric (IANA-registered values), enabling zero-allocation
// lookup and forward compatibility with new DNS types.
type ZoneRecord struct {
	Name    string `json:"name,omitempty"`
	Type    uint16 `json:"type"`            // dns.TypeA=1, dns.TypeAAAA=28, ...
	Class   uint16 `json:"class,omitempty"` // default dns.ClassINET=1
	TTL     uint32 `json:"ttl,omitempty"`
	Content string `json:"content"`
}

// CIDRConfig defines a CIDR rule set loaded from a file or inline rules,
// associated with a tag.
type CIDRConfig struct {
	File string   `json:"file,omitempty"`
	IPs  []string `json:"ips,omitempty"`
	Tag  string   `json:"tag"`
}

// LatencyProbeStep defines a single latency probe step with protocol, port,
// and timeout.
type LatencyProbeStep struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port,omitempty"`
	Timeout  int    `json:"timeout,omitempty"`
}

// IsRecursive reports whether the upstream server is the built-in recursive
// resolver.
func (s *UpstreamServer) IsRecursive() bool {
	if s == nil {
		return false
	}
	return s.Address == RecursiveIndicator
}

// LoadConfig reads, parses, validates, and enriches the configuration from a
// JSON file.
func LoadConfig(configFile string) (*ServerConfig, error) {
	if configFile == "" {
		return NewDefaultServerConfig(), nil
	}

	data, err := os.ReadFile(configFile) //nolint:gosec // G304: config file path from user
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	// Warn if config file has group/other read permissions — it may contain
	// SOCKS5 proxy credentials and other sensitive values.
	if info, err := os.Stat(configFile); err == nil {
		if info.Mode().Perm()&GroupOtherPermMask != 0 {
			log.Warnf("CONFIG: config file has insecure permissions (%04o). Consider 'chmod 600 %s'",
				info.Mode().Perm(), configFile)
		}
	}

	cfg := &ServerConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	if shouldEnableDDR(cfg) {
		addDDRRecords(cfg)
	}

	addChaosRecord(cfg)

	log.Infof("CONFIG: Configuration loaded successfully")
	return cfg, nil
}

// NewDefaultServerConfig returns a ServerConfig with sensible defaults.
func NewDefaultServerConfig() *ServerConfig {
	cfg := &ServerConfig{}
	cfg.Server.LogLevel = log.DefaultLevel

	cfg.Server.Port = DefaultDNSPort

	cfg.Server.TLS.Port = DefaultDOTPort
	cfg.Server.TLS.HTTPS.Port = DefaultDOHPort
	cfg.Server.TLS.HTTPS.Endpoint = DefaultQueryPath

	cfg.Server.Features.DDR = DDRSettings{Domain: "dns.example.com", IPv4: "127.0.0.1", IPv6: "::1"}
	cfg.Server.Features.ECS = ECSConfig{IPv4: "auto", IPv6: "auto", PreferIPv4: true}
	cfg.Server.Features.DNSSECEnforce = true
	cfg.Server.Features.HijackProtection = true

	return cfg
}

func shouldEnableDDR(cfg *ServerConfig) bool {
	ddr := cfg.Server.Features.DDR
	return ddr.Domain != "" &&
		(ddr.IPv4 != "" || ddr.IPv6 != "")
}

func addDDRRecords(cfg *ServerConfig) {
	ddr := cfg.Server.Features.DDR

	if strings.ContainsAny(ddr.Domain, " \"") || strings.ContainsAny(ddr.IPv4, " \"") || strings.ContainsAny(ddr.IPv6, " \"") {
		log.Warnf("CONFIG: DDR domain/IP contains unsafe characters, DDR records will not be added")
		return
	}
	if ddr.Domain == "" {
		log.Warnf("CONFIG: DDR domain is empty, DDR records will not be added")
		return
	}
	domain := strings.TrimSuffix(ddr.Domain, ".")
	endpoint := cfg.Server.TLS.HTTPS.Endpoint
	if endpoint == "" {
		endpoint = DefaultQueryPath
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}
	dohPath := "dohpath=\"" + endpoint + "{?dns}\""

	// Zone equivalents.
	zoneDirectRecords := make([]ZoneRecord, 0, 2)
	if ddr.IPv4 != "" {
		zoneDirectRecords = append(zoneDirectRecords, ZoneRecord{Type: dns.TypeA, Content: ddr.IPv4})
	}
	if ddr.IPv6 != "" {
		zoneDirectRecords = append(zoneDirectRecords, ZoneRecord{Type: dns.TypeAAAA, Content: ddr.IPv6})
	}
	if len(zoneDirectRecords) > 0 {
		cfg.Zone.Rules = append(cfg.Zone.Rules, ZoneRule{Name: domain, Answer: zoneDirectRecords})
	}

	ddrNames := []string{"_dns.resolver.arpa", "_dns." + domain}
	if cfg.Server.Port != "" && cfg.Server.Port != DefaultDNSPort {
		ddrNames = append(ddrNames, "_"+cfg.Server.Port+"._dns."+domain)
	}

	// Build zone SVCB records.
	zoneServiceRecords := make([]ZoneRecord, 2)
	zoneServiceRecords[0] = ZoneRecord{Type: dns.TypeSVCB, Content: "1 . alpn=h3,h2 port=" + cfg.Server.TLS.HTTPS.Port + " " + dohPath}
	zoneServiceRecords[1] = ZoneRecord{Type: dns.TypeSVCB, Content: "2 . alpn=doq,dot port=" + cfg.Server.TLS.Port}
	var zoneAdditional []ZoneRecord
	if ddr.IPv4 != "" {
		for i := range zoneServiceRecords {
			zoneServiceRecords[i].Content += " ipv4hint=" + ddr.IPv4
		}
		zoneAdditional = append(zoneAdditional, ZoneRecord{Name: domain, Type: dns.TypeA, Content: ddr.IPv4})
	}
	if ddr.IPv6 != "" {
		for i := range zoneServiceRecords {
			zoneServiceRecords[i].Content += " ipv6hint=" + ddr.IPv6
		}
		zoneAdditional = append(zoneAdditional, ZoneRecord{Name: domain, Type: dns.TypeAAAA, Content: ddr.IPv6})
	}

	for _, name := range ddrNames {
		cfg.Zone.Rules = append(cfg.Zone.Rules, ZoneRule{Name: name, Answer: zoneServiceRecords, Additional: zoneAdditional})
	}

	log.Infof("CONFIG: DDR enabled for domain %s (IPv4: %s, IPv6: %s)",
		domain, ddr.IPv4, ddr.IPv6)
}

func addChaosRecord(cfg *ServerConfig) {
	version := DefaultVersion
	if version == "" || version == "dev" {
		version = DefaultProjectName
	}
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = DefaultProjectName
	}
	chaosRecords := map[string]string{
		"id.server":      hostname,
		"hostname.bind":  hostname,
		"version.server": version,
		"version.bind":   version,
	}
	for name, value := range chaosRecords {
		cfg.Zone.Rules = append(cfg.Zone.Rules, ZoneRule{
			Name: name,
			Answer: []ZoneRecord{{
				Type:    dns.TypeTXT,
				Class:   dns.ClassCHAOS,
				TTL:     DefaultTTL,
				Content: strconv.Quote(value),
			}},
		})
	}
	for _, name := range []string{
		DefaultProjectName + ".stats",
		DefaultProjectName + ".db.clear",
		DefaultProjectName + ".db.clear.cache",
		DefaultProjectName + ".db.clear.stats",
		DefaultProjectName + ".db.clear.latency",
	} {
		cfg.Zone.Rules = append(cfg.Zone.Rules, ZoneRule{
			Name:   name,
			Answer: []ZoneRecord{{Type: dns.TypeTXT, Class: dns.ClassCHAOS, TTL: 0, Content: ""}},
		})
	}
}

// GenerateExampleConfig returns a complete example configuration as indented JSON.
func GenerateExampleConfig() string {
	cfg := NewDefaultServerConfig()

	cfg.Server.Pprof = DefaultPprofPort
	cfg.Server.LogLevel = log.DefaultLevel

	cfg.Server.TLS.CertFile = "/path/to/cert.pem"
	cfg.Server.TLS.KeyFile = "/path/to/key.pem"

	cfg.Server.TLS.KTLS = &KTLSSettings{KernelTX: true}

	cfg.Server.DNSCrypt = DNSCryptSettings{
		Port:         DefaultDNSCryptPort,
		ProviderName: "2.dnscrypt-cert.example.com",
		PublicKey:    "1A10FA5B04BC9188691C303960080BC93CCE83E7BC922AA5E59C49C34D675074",
		PrivateKey:   "34E2546B6F4C1FCE695E0C62DD3D74D39CEA52C70A283E7615EF4B67F82178D51A10FA5B04BC9188691C303960080BC93CCE83E7BC922AA5E59C49C34D675074",
		ResolverSk:   "86E8DAED24164E868CF4D2BDB29F7177FD9C20A8E3302BB04498FFE16AC61837",
		ResolverPk:   "999AC4B4F10E60B8A9EA694F56CB136A2C3FDA803320B6A2F3386D87E249A6ACCB7099B7BF9549BA17BC3646490B5B03FA068CCE76714598C60D5B056D47ACB7044ADC23205079B496C426069CB79B9B5868F6168B7C2F60654AD68C58AD35370EEB2C4C403E3CC415BCDA59E5483537D82131E11DB1393A03A842F311465EF152C73561CDD3476ED516810B2B1A6A3C75A397D835315FE3759D10B78AC947FE091402AB370A21B00F8647B03C7EDF3120BD03A860781522E90FA3A5595CC30EE7A657F9E10B279542F73347F3EA531F8C55FC0979EF7155FA21B8F2061209FB23BBC91E11279A51F76E596A5F5D0A95047246A0007B90A7631963680B000CB0EC392FE7747E1C8EE48B536842910EFB17E1726F133205BC2787402942AF744EFCB4CE71B9551CF850AECBB8549816F9D56A06484D39E66687DB028A8A784D869131CB8A948C3247DB151F31186A25007E0B601136A96676AD1488741021BB618A3F86B48624D28A134475B029222B565CA2C831DD346C4A158D4D00CC09A62DF582AE369A19A3D3174A9B246CFB8DBB4152CA994246AC669CD69BBF792D217694CEF4541708A61A5091E376C766456A8D8899B9F6B5902971A4EC806DE67916A9181C244413A95B0CA100B0A736F4B660DB62545C6C8959E7A5EA08BC6445837EC603135495303C461D67305B02AA77BA17BDF82832C47E3C165A14FCB536A24558A36E8969911F035E7272AD1EA0CCDEAC890E076AD82A8CF24A8F0703B523B34B4439551483893045577DE5BF62FB03FBB133688237DF7B833C837F8AA82D1477722DB09E8F90087A95A0A69179189525CCBABD09AC9837868BF84594571201AB7963FB110FF0DA77CF557E17F60BB2EBBFFB762D8318CE26E38893AA4DF1B9632B04222F251244973173A6717029A099DB513856292BC86DA0F28264F601FC52A887412E4AE47D2071B02CE1C80FF9AAFAC0A0B76C5486A4B557E18883FC24E65B5AE441B4D1BC964C193B5B50B9E2D766EEB2BA1E455E39942577725675543D3AA78B4B743ADFD2409287C7CA95CDB4008B3D1BA7E9A77BE9B80FF9458558272CEB60548D235BD7B836FEF2472383742B9125252A81D01C964597C69C22C5999500A3BB880E833F181684A442CA99AC29EEF89F6D4A9A736A3AE5CCBC3CACACE751537784609A98CDD9C01DB172C3C0D762FEB3B5460C08E9642A177010BA979A70EBB53C7790A6E679F6286A893B3C157229787B9FE802340589AD92E15519E93176A3B35DEA7DC256CD8C752E88E28F66599D85C6750C773992A09831E07738A9A35A2470AEE7BF5B128C691B62438C0B3CBB308E44881C7C26FA1262DC2092F36792F79188C288B57EC64F94C4B8F60245C79C691F8629D5E47D82D58B2A426DA911CDB0B00BF92B4DE0387A91A621FE5B8780B6155A48AC57194B9727B53DB05A7B39BEBF1C337C560062F8223A2501FCB033ADA6C458652943F07216919B1D9A7EBE04A3EF6ABEBF7AC880E201CD28456B24CE5AA070831220B992149D9797A85357E279BF305406255409CE1501C52A7A12E6A5A3D54979D746B70B87CE633CA37C5820391A1B40CED72B8428096E8C59754F544C23510ECB8C03CC8FFEA10675D454E1B9221C14CFC79EFA946ACAFB9F005B8EBB286EB15C825948A71375315F0DB1DD574B1F8BD7D3F34C11803E088AAF2AFD59A3CD654BA258",
		ESVersion:    "xwingpq",
		CertTTL:      "3650d",
	}

	cfg.Server.Features.Database.DBPath = "cache.db"
	cfg.Server.Features.Database.MMapSizeMB = DefaultCacheMMapSizeMB
	cfg.Server.Features.Database.CacheSizeMB = DefaultCacheCacheSizeMB

	cfg.Server.Features.Cache.MaxEntries = DefaultMaxCacheEntries
	cfg.Server.Features.Cache.PreferStale = true

	cfg.Server.Features.ECS = ECSConfig{IPv4: "auto", IPv6: "auto", PreferIPv4: true}
	cfg.Server.Features.LatencyProbe = []LatencyProbeStep{
		{Protocol: ProtoPing, Timeout: int(DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: ProtoTCP, Port: DefaultProbePortHTTPS, Timeout: int(DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: ProtoTCP, Port: DefaultProbePortHTTP, Timeout: int(DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: ProtoUDP, Port: DefaultProbePortDNS, Timeout: int(DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: ProtoHTTPPlain, Port: DefaultProbePortHTTP, Timeout: int(DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: ProtoHTTP, Port: DefaultProbePortHTTPS, Timeout: int(DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: ProtoHTTP3, Port: DefaultProbePortHTTPS, Timeout: int(DefaultLatencyProbeTimeout.Milliseconds())},
	}
	cfg.Upstream = []UpstreamServer{
		{Address: "223.5.5.5:53", Protocol: ProtoTCP, Proxy: "socks5://127.0.0.1:1080"},
		{Address: "223.6.6.6:53", Protocol: ProtoUDP},
		{Address: "223.5.5.5:853", Protocol: ProtoTLS, ServerName: "dns.alidns.com"},
		{Address: "223.6.6.6:853", Protocol: ProtoQUIC, ServerName: "dns.alidns.com", SkipTLSVerify: true},
		{Address: "https://223.5.5.5:443/dns-query", Protocol: ProtoHTTP, ServerName: "dns.alidns.com", Match: []string{"corp-net"}},
		{Address: "https://223.6.6.6:443/dns-query", Protocol: ProtoHTTP3, ServerName: "dns.alidns.com", Match: []string{"!corp-net"}},
	}

	cfg.Fallback = []UpstreamServer{
		{Address: RecursiveIndicator},
		{Address: "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0", Protocol: ProtoDNSCrypt},
		{Address: "149.112.112.9:53", Protocol: ProtoUDP, NoCache: true},
	}

	cfg.Zone.BypassTags = []string{"gateway"}

	cfg.Zone.Rules = []ZoneRule{
		{Name: "blocked.com", Rcode: dns.RcodeNameError},
		{Name: "static.example.com", Answer: []ZoneRecord{
			{Type: dns.TypeA, TTL: 300, Content: "10.0.0.1"},
			{Type: dns.TypeAAAA, TTL: 3600, Content: "::1"},
		}},
		{
			Name: "*.cdn.example.com", Match: []string{"corp-net", "!guest"},
			Answer: []ZoneRecord{{Type: dns.TypeA, TTL: 300, Content: "10.0.0.1"}},
		},
		{
			Name:       "example.com",
			Answer:     []ZoneRecord{{Type: dns.TypeA, TTL: 300, Content: "10.0.0.1"}},
			Authority:  []ZoneRecord{{Type: dns.TypeSOA, TTL: 3600, Content: "ns1.example.com. admin.example.com. 1 3600 900 86400 3600"}},
			Additional: []ZoneRecord{{Type: dns.TypeA, Name: "ns1.example.com", TTL: 3600, Content: "10.0.0.2"}},
		},
	}

	cfg.CIDR = []CIDRConfig{
		{IPs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}, Tag: "corp-net"},
		{IPs: []string{"0.0.0.0/0"}, Tag: "guest"},
		{IPs: []string{"10.0.0.1/32"}, Tag: "gateway"},
	}

	data, _ := json.MarshalIndent(cfg, "", "  ")
	return string(data)
}
