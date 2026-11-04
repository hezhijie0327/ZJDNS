module zjdns

go 1.27.0

require (
	codeberg.org/miekg/dns v0.6.129-0.20261103201307-13a1a0b709ac
	gitee.com/Trisia/gotlcp v1.6.2
	github.com/cloudflare/circl v1.6.6-0.20261103013143-009e98e5d362
	github.com/emmansun/gmsm v0.45.2
	github.com/klauspost/compress v1.20.4-0.20261103133652-b660d6de9d90
	github.com/pion/dtls/v4 v4.0.0-rc.8.0.20261101211820-c20a03f2b3db
	github.com/quic-go/quic-go v0.65.0
	gitlab.com/go-extension/tls v0.0.0-20261021190435-364702b25a0c
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.62.0
	golang.org/x/sync v0.24.0
	golang.org/x/sys v0.49.0
)

require (
	github.com/RyuaNerin/go-krypto v1.3.0 // indirect
	github.com/andybalholm/brotli v1.2.7 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cronokirby/saferith v0.33.1-0.20250226174546-1f11f94ce488 // indirect
	github.com/dgryski/go-camellia v0.0.0-20191119043421-69a8a13fb23d // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v5 v5.1.4 // indirect
	github.com/pmorjan/kmod v1.1.1 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/rogpeppe/go-internal v1.15.0 // indirect
	gitlab.com/go-extension/aes-ccm v0.0.0-20230221065045-e58665ef23c7 // indirect
	gitlab.com/go-extension/ffdh v0.0.0-20251208192952-367b797915cb // indirect
	gitlab.com/go-extension/hash v0.0.0-20250912170447-263d1d8375e4 // indirect
	gitlab.com/go-extension/io v0.0.0-20260929105507-614496a44375 // indirect
	gitlab.com/go-extension/rand v0.0.0-20240303103951-707937a049b5 // indirect
	gitlab.com/go-extension/utils v0.0.0-20251006173700-b62b19cda891 // indirect
	go.uber.org/mock v0.6.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace gitlab.com/go-extension/tls => ./.etls-patched
