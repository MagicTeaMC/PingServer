# PingServer
API server to ping your host, made with rust (For Linux only).  
Made for https://github.com/MagicTeaMC/PingCat
## Usage
Ping  
```
curl -X POST http://localhost:9199/ping \
  -H "Content-Type: application/json" \
  -d '{
    "api_key": "your_api_key",
    "target_ip": "1.1.1.1",
    "ip_version": "ipv4"
  }'
```
MTR  
```
curl -X POST http://localhost:9199/mtr \
  -H "Content-Type: application/json" \
  -d '{
    "api_key": "your_api_key",
    "target_ip": "1.1.1.1",
    "ip_version": "ipv4"
  }'
```