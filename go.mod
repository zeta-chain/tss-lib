module github.com/bnb-chain/tss-lib

go 1.16

require (
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412
	github.com/btcsuite/btcd v0.24.2
	github.com/btcsuite/btcd/btcec/v2 v2.3.2
	github.com/btcsuite/btcd/btcutil v1.1.6
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.0
	github.com/hashicorp/go-multierror v1.0.0
	github.com/ipfs/go-log v0.0.1
	github.com/mattn/go-colorable v0.1.2 // indirect
	github.com/opentracing/opentracing-go v1.1.0 // indirect
	github.com/otiai10/mint v1.2.4 // indirect
	github.com/otiai10/primes v0.0.0-20180210170552-f6d2a1ba97c4
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.9.0
	golang.org/x/crypto v0.35.0
	google.golang.org/protobuf v1.33.0
)

replace github.com/agl/ed25519 => github.com/binance-chain/edwards25519 v0.0.0-20200305024217-f36fc4b53d43
