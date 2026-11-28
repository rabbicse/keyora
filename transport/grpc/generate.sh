#!/bin/sh
# Regenerates keyorapb/ from proto/keyora/v1/*.proto.
#
# Needs protoc, protoc-gen-go and protoc-gen-go-grpc on PATH. The generated
# files record the tool versions in their headers, so other versions produce a
# diff; README.md lists the versions the committed code was generated with.
set -eu

cd "$(dirname "$0")"

for tool in protoc protoc-gen-go protoc-gen-go-grpc; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "generate.sh: $tool is not on PATH" >&2
		exit 1
	fi
done

module=github.com/rabbicse/keyora/transport/grpc

# Start clean so a deleted or renamed .proto leaves no stale Go file behind.
rm -f keyorapb/*.pb.go

# require_unimplemented_servers=false: the server in this module must
# implement every RPC, and the compiler checks that it does.
protoc \
	--proto_path=proto \
	--go_out=. --go_opt=module="$module" \
	--go-grpc_out=. --go-grpc_opt=module="$module" \
	--go-grpc_opt=require_unimplemented_servers=false \
	proto/keyora/v1/*.proto
