module github.com/anywherelan/awl

go 1.16

require (
	github.com/anywherelan/ts-dns v0.0.0-20210614204238-859a28a4197b
	github.com/go-playground/validator/v10 v10.6.1
	github.com/ipfs/go-datastore v0.4.5
	github.com/ipfs/go-log/v2 v2.1.3
	github.com/labstack/echo/v4 v4.3.0
	github.com/libp2p/go-eventbus v0.2.1
	github.com/libp2p/go-libp2p v0.14.1
	github.com/libp2p/go-libp2p-connmgr v0.2.4
	github.com/libp2p/go-libp2p-core v0.8.5
	github.com/libp2p/go-libp2p-kad-dht v0.11.1
	github.com/libp2p/go-libp2p-noise v0.2.0
	github.com/libp2p/go-libp2p-peerstore v0.2.7
	github.com/libp2p/go-libp2p-quic-transport v0.10.0
	github.com/libp2p/go-libp2p-swarm v0.5.0
	github.com/libp2p/go-libp2p-tls v0.1.3
	github.com/libp2p/go-tcp-transport v0.2.2
	github.com/miekg/dns v1.1.42
	github.com/milosgajdos/tenus v0.0.3
	github.com/mr-tron/base58 v1.2.0
	github.com/multiformats/go-multiaddr v0.3.1
	github.com/olekukonko/tablewriter v0.0.5
	github.com/stretchr/testify v1.7.0
	github.com/urfave/cli/v2 v2.3.0
	go.uber.org/multierr v1.7.0
	go.uber.org/zap v1.17.0
	golang.org/x/net v0.0.0-20210525063256-abc453219eb5
	golang.org/x/sys v0.0.0-20210608053332-aa57babbf139
	golang.zx2c4.com/wireguard v0.0.0-20210525143454-64cb82f2b3f5
	golang.zx2c4.com/wireguard/windows v0.3.15-0.20210525143335-94c0476d63e3
	inet.af/netaddr v0.0.0-20210602152128-50f8686885e3
)

replace github.com/ipfs/go-log/v2 => github.com/anywherelan/go-log/v2 v2.0.3-0.20210308150645-ad120b957e42
