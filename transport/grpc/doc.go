// Package grpcapi exposes Keyora over gRPC. It is a transport and nothing
// more: every use case lives in the service layer, and every decision about
// who is calling is made by the access gate it shares with the REST API.
//
// The API is defined in proto/keyora/v1 and the generated Go code is in the
// keyorapb package, which is all a Go client needs to import.
//
// A Keyora binary links the transport by passing Extension to server.Main:
//
//	os.Exit(server.Main(os.Args[1:], version, os.Stdout, os.Stderr, grpcapi.Extension()))
//
// It then listens on KEYORA_GRPC_ADDR. The listener is plaintext: like
// Keyora's HTTP listener it is meant to sit behind a reverse proxy that
// terminates TLS.
package grpcapi

//go:generate ./generate.sh
