# PingServer
API server to ping your host, made with rust (For Linux only).  
Made for https://github.com/MagicTeaMC/PingCat

## Usage

### Ping
Supports both IP addresses and domain names:

```bash
# Ping with IP address
curl -X POST http://localhost:9199/ping \
  -H "Content-Type: application/json" \
  -d '{
    "api_key": "your_api_key",
    "target": "1.1.1.1",
    "ip_version": "ipv4"
  }'
```

```bash
# Ping with domain name
curl -X POST http://localhost:9199/ping \
  -H "Content-Type: application/json" \
  -d '{
    "api_key": "your_api_key",
    "target": "google.com",
    "ip_version": "auto"
  }'
```

### MTR
Supports both IP addresses and domain names:

```bash
# MTR with IP address
curl -X POST http://localhost:9199/mtr \
  -H "Content-Type: application/json" \
  -d '{
    "api_key": "your_api_key",
    "target": "1.1.1.1",
    "ip_version": "ipv4"
  }'
```

```bash
# MTR with domain name
curl -X POST http://localhost:9199/mtr \
  -H "Content-Type: application/json" \
  -d '{
    "api_key": "your_api_key",
    "target": "google.com",
    "ip_version": "auto"
  }'
```

## Parameters

- **api_key**: Your API key (configured via environment variable `API_KEYS`)
- **target**: IP address or domain name to ping/trace
- **ip_version**: Version preference - `"ipv4"`, `"ipv6"`, or `"auto"`

## Security Notes

The server includes validation to prevent access to:
- Private network IP addresses (10.x.x.x, 192.168.x.x, 172.16-31.x.x, 127.x.x.x)
- Local domains (.localhost, .local, .localdomain)
- Internal domains (.internal, .corp, .home, .lan)
- Test domains (.test, .example)