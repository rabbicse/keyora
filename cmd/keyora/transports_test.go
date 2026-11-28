package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	graphqlapi "github.com/rabbicse/keyora/transport/graphql"
	grpcapi "github.com/rabbicse/keyora/transport/grpc"
	"github.com/rabbicse/keyora/transport/grpc/keyorapb"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// TestAllTransports boots the server exactly as main does, with the GraphQL
// and gRPC transports linked, and checks that one user and one token work
// across REST, GraphQL and gRPC alike.
func TestAllTransports(t *testing.T) {
	grpcAddr := freeAddr(t)
	in := start(t, t.TempDir(), map[string]string{"KEYORA_GRPC_ADDR": grpcAddr},
		graphqlapi.Extension(), grpcapi.Extension())
	defer in.stop()

	// REST: tenant, application, user, sign-in.
	_, tenant := in.call("POST", "/api/v1/tenants", testAdminKey, map[string]any{"slug": "acme", "name": "Acme"})
	tenantID, _ := tenant["id"].(string)
	_, app := in.call("POST", "/api/v1/tenants/"+tenantID+"/applications", testAdminKey, map[string]any{"name": "web"})
	client := app["client_id"].(string) + ":" + app["client_secret"].(string)
	if status, _ := in.call("POST", "/api/v1/auth/register", client,
		map[string]any{"email": "ada@example.com", "password": "correct horse battery"}); status != 201 {
		t.Fatalf("register: %d", status)
	}
	_, login := in.call("POST", "/api/v1/auth/login", client, map[string]any{"email": "ada@example.com", "password": "correct horse battery"})
	access, _ := login["access_token"].(string)
	if access == "" {
		t.Fatal("REST login returned no access token")
	}

	// GraphQL: the REST token identifies the same user.
	req, _ := http.NewRequest("POST", in.base+"/graphql", strings.NewReader(`{"query":"{ me { user { email } } }"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+access)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var gql struct {
		Data struct {
			Me struct{ User struct{ Email string } }
		}
	}
	json.NewDecoder(res.Body).Decode(&gql)
	res.Body.Close()
	if res.StatusCode != 200 || gql.Data.Me.User.Email != "ada@example.com" {
		t.Fatalf("GraphQL me: %d %+v", res.StatusCode, gql)
	}

	// gRPC: health, then the same token and a sign-in through gRPC.
	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var hres *healthpb.HealthCheckResponse
	for i := 0; i < 50; i++ { // the gRPC listener starts alongside the HTTP one
		if hres, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil || hres.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("gRPC health: %v %v", hres, err)
	}
	authed := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+access)
	me, err := keyorapb.NewAccountServiceClient(conn).GetMe(authed, &keyorapb.GetMeRequest{})
	if err != nil || me.GetUser().GetEmail() != "ada@example.com" {
		t.Fatalf("gRPC GetMe with the REST token: %v %v", me, err)
	}
	id, secret, _ := strings.Cut(client, ":")
	_, err = keyorapb.NewAuthServiceClient(conn).Login(ctx, &keyorapb.LoginRequest{
		ClientId: id, ClientSecret: secret, Email: "ada@example.com", Password: "wrong"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("gRPC wrong password: %v", err)
	}
}

// TestTransportSwitches: GraphQL can be switched off. (gRPC staying off without
// KEYORA_GRPC_ADDR is tested in the gRPC module.)
func TestTransportSwitches(t *testing.T) {
	in := start(t, t.TempDir(), map[string]string{"KEYORA_GRAPHQL_ENABLED": "false"},
		graphqlapi.Extension(), grpcapi.Extension())
	defer in.stop()
	req, _ := http.NewRequest("POST", in.base+"/graphql", strings.NewReader(`{"query":"{ __typename }"}`))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("GraphQL disabled but /graphql answered %d", res.StatusCode)
	}
}
