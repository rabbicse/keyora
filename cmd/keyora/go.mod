module github.com/rabbicse/keyora/cmd/keyora

go 1.26.0

require (
	github.com/jackc/pgx/v5 v5.13.0
	github.com/rabbicse/keyora v0.0.0
	github.com/rabbicse/keyora/transport/graphql v0.0.0
	github.com/rabbicse/keyora/transport/grpc v0.0.0
	google.golang.org/grpc v1.85.0
	modernc.org/sqlite v1.63.0
)

require (
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/graph-gophers/graphql-go v1.11.1 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260817212433-ac3dfec99bb1 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	modernc.org/libc v1.80.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

replace (
	github.com/rabbicse/keyora => ../..
	github.com/rabbicse/keyora/transport/graphql => ../../transport/graphql
	github.com/rabbicse/keyora/transport/grpc => ../../transport/grpc
)
