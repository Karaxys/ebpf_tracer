# eBPF Traffic Capture — OWASP Juice Shop

**Target:** `http://localhost:3000` (Docker container)  
**Process:** PID `96621` · `MainThread` · `/nodejs/bin/node`  
**Capture Source:** eBPF

---

## Traffic Summary

| # | Method | Path | Status | Notes |
|---|--------|------|--------|-------|
| 1 | GET | `/rest/user/whoami` | 304 Not Modified | Pre-login identity check (no token) |
| 2 | POST | `/rest/user/login` | 200 OK | Successful login, JWT issued |
| 3 | GET | `/rest/user/whoami?fields=email` | 200 OK | Post-login identity check (with JWT) |
| 4 | GET | `/rest/user/whoami` | 200 OK | Full profile fetch (id, email, lastLoginIp, profileImage) |
| 5 | GET | `/rest/products/search?q=` | 304 Not Modified | Product listing (cached) |
| 6 | GET | `/rest/basket/6` | 200 OK | Basket fetch for user id 23 |

---

## Event 1 — `GET /rest/user/whoami` → `304 Not Modified`

**Timestamp:** 23:19:47  
**Connection:** `172.17.0.1:43430` → `172.17.0.2:3000` (TCP/IPv6, outbound)

### eBPF Raw Events
```
event pid=96621 fd=24 gen=5 seq=1 dir=read  kind=request  size=535
event pid=96621 fd=24 gen=5 seq=2 dir=write kind=response size=303
```

### Request
```
GET /rest/user/whoami HTTP/1.1
Host: localhost:3000
Cookie: language=en; welcomebanner_status=dismiss; cookieconsent_status=dismiss
If-None-Match: W/"b-/5bSboVjVhGw3qRgvUfZjE1r1Ns"
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0
```

> No `Authorization` header — this is a pre-login request. The browser sends the cached ETag.

### Response
```
HTTP/1.1 304 Not Modified
ETag: W/"b-/5bSboVjVhGw3qRgvUfZjE1r1Ns"
Access-Control-Allow-Origin: *
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
```

> Cache hit. No body returned.

---

## Event 2 — `POST /rest/user/login` → `200 OK`

**Timestamp:** 23:19:47  
**Connection:** `172.17.0.1:43414` → `172.17.0.2:3000` (TCP/IPv6, outbound)

### eBPF Raw Events
```
event pid=96621 fd=23 gen=6 seq=1 dir=read    kind=request  size=617
event pid=96621 fd=23 gen=6 seq=2 dir=write   kind=response size=386
event pid=96621 fd=23 gen=6 seq=3 dir=write   kind=unknown  size=804
  preview: {"authentication":{"token":"eyJ0eXAiOiJKV1Qi...
```

### Request Body
```json
{
  "email": "hello@gmail.com",
  "password": "hello123"
}
```

### Response Body (truncated JWT)
```json
{
  "authentication": {
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.<payload>.<signature>",
    "bid": 6,
    "umail": "hello@gmail.com"
  }
}
```

**JWT Algorithm:** `RS256`  
**Basket ID assigned:** `6`  
**User email confirmed:** `hello@gmail.com`

#### Decoded JWT Payload
```json
{
  "status": "success",
  "data": {
    "id": 23,
    "username": "",
    "email": "hello@gmail.com",
    "password": "f30aa7a662c728b7407c54ae6bfd27d1",
    "role": "customer",
    "deluxeToken": "",
    "lastLoginIp": "0.0.0.0",
    "profileImage": "/assets/public/images/uploads/default.svg",
    "totpSecret": "",
    "isActive": true,
    "createdAt": "2026-04-29 17:49:29.437 +00:00",
    "updatedAt": "2026-04-29 17:49:29.437 +00:00",
    "deletedAt": null
  },
  "iat": 1777484988
}
```

> **Note:** The JWT payload contains a hashed password (`f30aa7a662c728b7407c54ae6bfd27d1` — MD5). This is a known Juice Shop vulnerability: sensitive user data is embedded directly in the JWT.

---

## Event 3 — `GET /rest/user/whoami?fields=email` → `200 OK`

**Timestamp:** 23:19:47  
**Connection:** `172.17.0.1:43414` → `172.17.0.2:3000` (TCP/IPv6, outbound)

### eBPF Raw Events
```
event pid=96621 fd=23 gen=6 seq=4 dir=read    kind=request  size=2043
event pid=96621 fd=23 gen=6 seq=5 dir=write   kind=response size=384
event pid=96621 fd=23 gen=6 seq=6 dir=write   kind=unknown  size=36
  preview: {"user":{"email":"hello@gmail.com"}}
```

### Request (notable headers)
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...
Cookie: token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...
```

> JWT now present in both `Authorization` header and `Cookie`. The token is being sent redundantly via both mechanisms.

### Response Body
```json
{
  "user": {
    "email": "hello@gmail.com"
  }
}
```

---

## Event 4 — `GET /rest/user/whoami` → `200 OK`

**Timestamp:** 23:19:47  
**Connection:** `172.17.0.1:43406` → `172.17.0.2:3000` (TCP/IPv6, outbound)

### eBPF Raw Events
```
event pid=96621 fd=22 gen=5 seq=3 dir=read    kind=request  size=2030
event pid=96621 fd=22 gen=5 seq=4 dir=write   kind=response size=385
event pid=96621 fd=22 gen=5 seq=5 dir=write   kind=unknown  size=127
  preview: {"user":{"id":23,"email":"hello@gmail.com","lastLoginIp":"0.0.0.0","profileImage":"/assets/publi...
```

### Response Body
```json
{
  "user": {
    "id": 23,
    "email": "hello@gmail.com",
    "lastLoginIp": "0.0.0.0",
    "profileImage": "/assets/public/images/uploads/default.svg"
  }
}
```

---

## Event 5 — `GET /rest/products/search?q=` → `304 Not Modified`

**Timestamp:** 23:19:47  
**Connection:** `172.17.0.1:43406` → `172.17.0.2:3000` (TCP/IPv6, outbound)

### eBPF Raw Events
```
event pid=96621 fd=22 gen=5 seq=6 dir=read    kind=request  size=2040
event pid=96621 fd=22 gen=5 seq=7 dir=write   kind=response size=306
```

### Request (notable headers)
```
If-None-Match: W/"354c-dt0VTJdKkwcihGfxnmGhaIjLeBY"
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...
```

### Response
```
HTTP/1.1 304 Not Modified
ETag: W/"354c-dt0VTJdKkwcihGfxnmGhaIjLeBY"
```

> Product list unchanged since last request. Cached response returned (no body).

---

## Event 6 — `GET /rest/basket/6` → `200 OK`

**Timestamp:** 23:19:48  
**Connection:** `172.17.0.1:43430` → `172.17.0.2:3000` (TCP/IPv6, outbound)

### eBPF Raw Events
```
event pid=96621 fd=24 gen=5 seq=3 dir=read    kind=request  size=2028
event pid=96621 fd=24 gen=5 seq=4 dir=write   kind=response size=385
event pid=96621 fd=24 gen=5 seq=5 dir=write   kind=unknown  size=154
  preview: {"status":"success","data":{"id":6,"coupon":null,"UserId":23,...
```

### Response Body
```json
{
  "status": "success",
  "data": {
    "id": 6,
    "coupon": null,
    "UserId": 23,
    "createdAt": "2026-04-29T17:49:47.498Z",
    "updatedAt": "2026-04-29T17:49:47.498Z",
    "Products": []
  }
}
```

> Basket `id=6` belongs to user `id=23`. Empty on creation — `Products: []`.

---

## Connection Overview

| File Descriptor | Port (dst) | Used For |
|-----------------|------------|----------|
| fd=22 | 43406 | whoami (auth'd), product search |
| fd=23 | 43414 | login POST, whoami (fields=email) |
| fd=24 | 43430 | whoami (pre-login), basket fetch |

> Juice Shop reuses persistent TCP connections (keep-alive) across multiple requests, visible through the incrementing `seq` numbers on the same `fd`.

---

## Observations

- **JWT contains MD5-hashed password** in the payload — readable by anyone who base64-decodes it.
- **Token sent twice** on authenticated requests — both `Authorization: Bearer` header and `Cookie: token=`.
- **CORS wildcard** (`Access-Control-Allow-Origin: *`) on all responses.
- **`X-Recruiting` header** present on all responses pointing to `/#/jobs` — a Juice Shop easter egg.
- **`lastLoginIp` is `0.0.0.0`** — Docker networking masking the real client IP.
- **Basket ID (`bid: 6`) == User ID (`id: 23`) offset** — predictable integer IDs, potential IDOR target.

---

## Raw eBPF Output

> Exact output as captured from eBPF directly on interacting with the Juice Shop webapp.

```
2026/04/29 23:19:47 event pid=96621 fd=23 gen=6 seq=1 dir=read kind=request routed=request size=617 req_buf=617 resp_buf=0 pending=0 preview="POST /rest/user/login HTTP/1.1\r\nHost: localhost:3000\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64"
2026/04/29 23:19:47 event pid=96621 fd=24 gen=5 seq=1 dir=read kind=request routed=request size=535 req_buf=535 resp_buf=0 pending=0 preview="GET /rest/user/whoami HTTP/1.1\r\nHost: localhost:3000\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64"
2026/04/29 23:19:47 event pid=96621 fd=24 gen=5 seq=2 dir=write kind=response routed=response size=303 req_buf=0 resp_buf=303 pending=1 preview="HTTP/1.1 304 Not Modified\r\nAccess-Control-Allow-Origin: *\r\nX-Content-Type-Options: nosniff\r\nX-Fr"
================================================================
 TRAFFIC GET /rest/user/whoami -> 304 Not Modified
================================================================
{
  "_id": {
    "$oid": "811a4c8424c374e7a8729427"
  },
  "schema_version": "http.conversation.v1",
  "capture_source": "ebpf",
  "capture_mode": "container",
  "captured_at": {
    "$date": "2026-04-29T17:49:47.402448879Z"
  },
  "connection": {
    "src_ip": "172.17.0.2",
    "src_port": 3000,
    "dst_ip": "172.17.0.1",
    "dst_port": 43430,
    "protocol": "tcp",
    "family": "ipv6",
    "role": "outbound"
  },
  "process": {
    "pid": 96621,
    "name": "MainThread",
    "exe": "/nodejs/bin/node"
  },
  "container": {
    "id": "66822672338b7dc1b662b1ba416bcf207831157f02b87f04307f61d2d2b2006f"
  },
  "loss": {},
  "http": {
    "request": {
      "method": "GET",
      "url": "http://localhost:3000/rest/user/whoami",
      "host": "localhost:3000",
      "path": "/rest/user/whoami",
      "headers": {
        "Accept": [
          "application/json, text/plain, */*"
        ],
        "Accept-Encoding": [
          "gzip, deflate, br, zstd"
        ],
        "Accept-Language": [
          "en-US,en;q=0.9"
        ],
        "Connection": [
          "keep-alive"
        ],
        "Cookie": [
          "language=en; welcomebanner_status=dismiss; cookieconsent_status=dismiss"
        ],
        "If-None-Match": [
          "W/\"b-/5bSboVjVhGw3qRgvUfZjE1r1Ns\""
        ],
        "Priority": [
          "u=0"
        ],
        "Referer": [
          "http://localhost:3000/"
        ],
        "Sec-Fetch-Dest": [
          "empty"
        ],
        "Sec-Fetch-Mode": [
          "cors"
        ],
        "Sec-Fetch-Site": [
          "same-origin"
        ],
        "User-Agent": [
          "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0"
        ]
      }
    },
    "response": {
      "status": "304 Not Modified",
      "headers": {
        "Access-Control-Allow-Origin": [
          "*"
        ],
        "Connection": [
          "keep-alive"
        ],
        "Date": [
          "Wed, 29 Apr 2026 17:49:47 GMT"
        ],
        "Etag": [
          "W/\"b-/5bSboVjVhGw3qRgvUfZjE1r1Ns\""
        ],
        "Feature-Policy": [
          "payment 'self'"
        ],
        "Keep-Alive": [
          "timeout=5"
        ],
        "X-Content-Type-Options": [
          "nosniff"
        ],
        "X-Frame-Options": [
          "SAMEORIGIN"
        ],
        "X-Recruiting": [
          "/#/jobs"
        ]
      }
    }
  }
}
------------------------------------------------------------------------------------------------
2026/04/29 23:19:47 event pid=96621 fd=23 gen=6 seq=2 dir=write kind=response routed=response size=386 req_buf=0 resp_buf=386 pending=1 preview="HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Option"
2026/04/29 23:19:47 event pid=96621 fd=23 gen=6 seq=3 dir=write kind=unknown routed=response size=804 req_buf=0 resp_buf=1190 pending=1 preview="{\"authentication\":{\"token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF"

================================================================
 TRAFFIC POST /rest/user/login -> 200 OK
================================================================
{
  "_id": {
    "$oid": "df432f964b32bd6099100cfa"
  },
  "schema_version": "http.conversation.v1",
  "capture_source": "ebpf",
  "capture_mode": "container",
  "captured_at": {
    "$date": "2026-04-29T17:49:47.402342517Z"
  },
  "connection": {
    "src_ip": "172.17.0.2",
    "src_port": 3000,
    "dst_ip": "172.17.0.1",
    "dst_port": 43414,
    "protocol": "tcp",
    "family": "ipv6",
    "role": "outbound"
  },
  "process": {
    "pid": 96621,
    "name": "MainThread",
    "exe": "/nodejs/bin/node"
  },
  "container": {
    "id": "66822672338b7dc1b662b1ba416bcf207831157f02b87f04307f61d2d2b2006f"
  },
  "loss": {},
  "http": {
    "request": {
      "method": "POST",
      "url": "http://localhost:3000/rest/user/login",
      "host": "localhost:3000",
      "path": "/rest/user/login",
      "headers": {
        "Accept": [
          "application/json, text/plain, */*"
        ],
        "Accept-Encoding": [
          "gzip, deflate, br, zstd"
        ],
        "Accept-Language": [
          "en-US,en;q=0.9"
        ],
        "Connection": [
          "keep-alive"
        ],
        "Content-Length": [
          "49"
        ],
        "Content-Type": [
          "application/json"
        ],
        "Cookie": [
          "language=en; welcomebanner_status=dismiss; cookieconsent_status=dismiss"
        ],
        "Origin": [
          "http://localhost:3000"
        ],
        "Priority": [
          "u=0"
        ],
        "Referer": [
          "http://localhost:3000/"
        ],
        "Sec-Fetch-Dest": [
          "empty"
        ],
        "Sec-Fetch-Mode": [
          "cors"
        ],
        "Sec-Fetch-Site": [
          "same-origin"
        ],
        "User-Agent": [
          "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0"
        ]
      },
      "body": "{\n  \"email\": \"hello@gmail.com\",\n  \"password\": \"hello123\"\n}"
    },
    "response": {
      "status": "200 OK",
      "headers": {
        "Access-Control-Allow-Origin": [
          "*"
        ],
        "Connection": [
          "keep-alive"
        ],
        "Content-Length": [
          "804"
        ],
        "Content-Type": [
          "application/json; charset=utf-8"
        ],
        "Date": [
          "Wed, 29 Apr 2026 17:49:47 GMT"
        ],
        "Etag": [
          "W/\"324-V3K4aSx8JUCDsx6EMdru4A5m8iE\""
        ],
        "Feature-Policy": [
          "payment 'self'"
        ],
        "Keep-Alive": [
          "timeout=5"
        ],
        "Vary": [
          "Accept-Encoding"
        ],
        "X-Content-Type-Options": [
          "nosniff"
        ],
        "X-Frame-Options": [
          "SAMEORIGIN"
        ],
        "X-Recruiting": [
          "/#/jobs"
        ]
      },
      "body": "{\n  \"authentication\": {\n    \"token\": \"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjMsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJoZWxsb0BnbWFpbC5jb20iLCJwYXNzd29yZCI6ImYzMGFhN2E2NjJjNzI4Yjc0MDdjNTRhZTZiZmQyN2QxIiwicm9sZSI6ImN1c3RvbWVyIiwiZGVsdXhlVG9rZW4iOiIiLCJsYXN0TG9naW5JcCI6IjAuMC4wLjAiLCJwcm9maWxlSW1hZ2UiOiIvYXNzZXRzL3B1YmxpYy9pbWFnZXMvdXBsb2Fkcy9kZWZhdWx0LnN2ZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyNi0wNC0yOSAxNzo0OToyOS40MzcgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyNi0wNC0yOSAxNzo0OToyOS40MzcgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiaWF0IjoxNzc3NDg0OTg4fQ.KMpdUzJkWxjatjyR2L0O052H66aok19_wsLCsO_4zqjp_qgEvIwdvtphHFxCAPqugfkPooWFnVn1srtAd3GkJqSgSpNc9hQI7cORR3tPkBHcNfFc7UEmjej703FoEgCwiXwq3aBbLqryYaD9fwCKWYuRh2Dyz5gn0rMseoKI8Uw\",\n    \"bid\": 6,\n    \"umail\": \"hello@gmail.com\"\n  }\n}"
    }
  }
}
------------------------------------------------------------------------------------------------
2026/04/29 23:19:47 event pid=96621 fd=23 gen=6 seq=4 dir=read kind=request routed=request size=2043 req_buf=2043 resp_buf=0 pending=0 preview="GET /rest/user/whoami?fields=email HTTP/1.1\r\nHost: localhost:3000\r\nUser-Agent: Mozilla/5.0 (X11;"
2026/04/29 23:19:47 event pid=96621 fd=23 gen=6 seq=5 dir=write kind=response routed=response size=384 req_buf=0 resp_buf=384 pending=1 preview="HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Option"
2026/04/29 23:19:47 event pid=96621 fd=23 gen=6 seq=6 dir=write kind=unknown routed=response size=36 req_buf=0 resp_buf=420 pending=1 preview="{\"user\":{\"email\":\"hello@gmail.com\"}}"
================================================================
 TRAFFIC GET /rest/user/whoami?fields=email -> 200 OK
================================================================
{
  "_id": {
    "$oid": "809a6d37fb4d2dd13e3eb344"
  },
  "schema_version": "http.conversation.v1",
  "capture_source": "ebpf",
  "capture_mode": "container",
  "captured_at": {
    "$date": "2026-04-29T17:49:47.70997458Z"
  },
  "connection": {
    "src_ip": "172.17.0.2",
    "src_port": 3000,
    "dst_ip": "172.17.0.1",
    "dst_port": 43414,
    "protocol": "tcp",
    "family": "ipv6",
    "role": "outbound"
  },
  "process": {
    "pid": 96621,
    "name": "MainThread",
    "exe": "/nodejs/bin/node"
  },
  "container": {
    "id": "66822672338b7dc1b662b1ba416bcf207831157f02b87f04307f61d2d2b2006f"
  },
  "loss": {},
  "http": {
    "request": {
      "method": "GET",
      "url": "http://localhost:3000/rest/user/whoami?fields=email",
      "host": "localhost:3000",
      "path": "/rest/user/whoami?fields=email",
      "headers": {
        "Accept": [
          "application/json, text/plain, */*"
        ],
        "Accept-Encoding": [
          "gzip, deflate, br, zstd"
        ],
        "Accept-Language": [
          "en-US,en;q=0.9"
        ],
        "Authorization": [
          "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjMsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJoZWxsb0BnbWFpbC5jb20iLCJwYXNzd29yZCI6ImYzMGFhN2E2NjJjNzI4Yjc0MDdjNTRhZTZiZmQyN2QxIiwicm9sZSI6ImN1c3RvbWVyIiwiZGVsdXhlVG9rZW4iOiIiLCJsYXN0TG9naW5JcCI6IjAuMC4wLjAiLCJwcm9maWxlSW1hZ2UiOiIvYXNzZXRzL3B1YmxpYy9pbWFnZXMvdXBsb2Fkcy9kZWZhdWx0LnN2ZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyNi0wNC0yOSAxNzo0OToyOS40MzcgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyNi0wNC0yOSAxNzo0OToyOS40MzcgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiaWF0IjoxNzc3NDg0OTg4fQ.KMpdUzJkWxjatjyR2L0O052H66aok19_wsLCsO_4zqjp_qgEvIwdvtphHFxCAPqugfkPooWFnVn1srtAd3GkJqSgSpNc9hQI7cORR3tPkBHcNfFc7UEmjej703FoEgCwiXwq3aBbLqryYaD9fwCKWYuRh2Dyz5gn0rMseoKI8Uw"
        ],
        "Connection": [
          "keep-alive"
        ],
        "Cookie": [
          "language=en; welcomebanner_status=dismiss; cookieconsent_status=dismiss; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjMsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJoZWxsb0BnbWFpbC5jb20iLCJwYXNzd29yZCI6ImYzMGFhN2E2NjJjNzI4Yjc0MDdjNTRhZTZiZmQyN2QxIiwicm9sZSI6ImN1c3RvbWVyIiwiZGVsdXhlVG9rZW4iOiIiLCJsYXN0TG9naW5JcCI6IjAuMC4wLjAiLCJwcm9maWxlSW1hZ2UiOiIvYXNzZXRzL3B1YmxpYy9pbWFnZXMvdXBsb2Fkcy9kZWZhdWx0LnN2ZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyNi0wNC0yOSAxNzo0OToyOS40MzcgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyNi0wNC0yOSAxNzo0OToyOS40MzcgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiaWF0IjoxNzc3NDg0OTg4fQ.KMpdUzJkWxjatjyR2L0O052H66aok19_wsLCsO_4zqjp_qgEvIwdvtphHFxCAPqugfkPooWFnVn1srtAd3GkJqSgSpNc9hQI7cORR3tPkBHcNfFc7UEmjej703FoEgCwiXwq3aBbLqryYaD9fwCKWYuRh2Dyz5gn0rMseoKI8Uw"
        ],
        "If-None-Match": [
          "W/\"b-/5bSboVjVhGw3qRgvUfZjE1r1Ns\""
        ],
        "Referer": [
          "http://localhost:3000/"
        ],
        "Sec-Fetch-Dest": [
          "empty"
        ],
        "Sec-Fetch-Mode": [
          "cors"
        ],
        "Sec-Fetch-Site": [
          "same-origin"
        ],
        "User-Agent": [
          "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0"
        ]
      }
    },
    "response": {
      "status": "200 OK",
      "headers": {
        "Access-Control-Allow-Origin": [
          "*"
        ],
        "Connection": [
          "keep-alive"
        ],
        "Content-Length": [
          "36"
        ],
        "Content-Type": [
          "application/json; charset=utf-8"
        ],
        "Date": [
          "Wed, 29 Apr 2026 17:49:47 GMT"
        ],
        "Etag": [
          "W/\"24-z3aEBjUUDj5WOLMm0wjxFKitrIU\""
        ],
        "Feature-Policy": [
          "payment 'self'"
        ],
        "Keep-Alive": [
          "timeout=5"
        ],
        "Vary": [
          "Accept-Encoding"
        ],
        "X-Content-Type-Options": [
          "nosniff"
        ],
        "X-Frame-Options": [
          "SAMEORIGIN"
        ],
        "X-Recruiting": [
          "/#/jobs"
        ]
      },
      "body": "{\n  \"user\": {\n    \"email\": \"hello@gmail.com\"\n  }\n}"
    }
  }
}
------------------------------------------------------------------------------------------------
2026/04/29 23:19:47 event pid=96621 fd=22 gen=5 seq=3 dir=read kind=request routed=request size=2030 req_buf=2030 resp_buf=0 pending=0 preview="GET /rest/user/whoami HTTP/1.1\r\nHost: localhost:3000\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64"
2026/04/29 23:19:47 event pid=96621 fd=22 gen=5 seq=4 dir=write kind=response routed=response size=385 req_buf=0 resp_buf=385 pending=1 preview="HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Option"
2026/04/29 23:19:47 event pid=96621 fd=22 gen=5 seq=5 dir=write kind=unknown routed=response size=127 req_buf=0 resp_buf=512 pending=1 preview="{\"user\":{\"id\":23,\"email\":\"hello@gmail.com\",\"lastLoginIp\":\"0.0.0.0\",\"profileImage\":\"/assets/publi"
================================================================
 TRAFFIC GET /rest/user/whoami -> 200 OK
================================================================
{
  "_id": {
    "$oid": "384608a66298ef27b23c1b66"
  },
  "schema_version": "http.conversation.v1",
  "capture_source": "ebpf",
  "capture_mode": "container",
  "captured_at": {
    "$date": "2026-04-29T17:49:47.716432421Z"
  },
  "connection": {
    "src_ip": "172.17.0.2",
    "src_port": 3000,
    "dst_ip": "172.17.0.1",
    "dst_port": 43406,
    "protocol": "tcp",
    "family": "ipv6",
    "role": "outbound"
  },
  "process": {
    "pid": 96621,
    "name": "MainThread",
    "exe": "/nodejs/bin/node"
  },
  "container": {
    "id": "66822672338b7dc1b662b1ba416bcf207831157f02b87f04307f61d2d2b2006f"
  },
  "loss": {},
  "http": {
    "request": {
      "method": "GET",
      "url": "http://localhost:3000/rest/user/whoami",
      "host": "localhost:3000",
      "path": "/rest/user/whoami",
      "headers": {
        "Accept": [
          "application/json, text/plain, */*"
        ],
        "Accept-Encoding": [
          "gzip, deflate, br, zstd"
        ],
        "Accept-Language": [
          "en-US,en;q=0.9"
        ],
        "Authorization": [
          "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjMsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJoZWxsb0BnbWFpbC5jb20iLCJwYXNzd29yZCI6ImYzMGFhN2E2NjJjNzI4Yjc0MDdjNTRhZTZiZmQyN2QxIiwicm9sZSI6ImN1c3RvbWVyIiwiZGVsdXhlVG9rZW4iOiIiLCJsYXN0TG9naW5JcCI6IjAuMC4wLjAiLCJwcm9maWxlSW1hZ2UiOiIvYXNzZXRzL3B1YmxpYy9pbWFnZXMvdXBsb2Fkcy9kZWZhdWx0LnN2ZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyNi0wNC0yOSAxNzo0OToyOS40MzcgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyNi0wNC0yOSAxNzo0OToyOS40MzcgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiaWF0IjoxNzc3NDg0OTg4fQ.KMpdUzJkWxjatjyR2L0O052H66aok19_wsLCsO_4zqjp_qgEvIwdvtphHFxCAPqugfkPooWFnVn1srtAd3GkJqSgSpNc9hQI7cORR3tPkBHcNfFc7UEmjej703FoEgCwiXwq3aBbLqryYaD9fwCKWYuRh2Dyz5gn0rMseoKI8Uw"
        ],
        "Connection": [
          "keep-alive"
        ],
        "Cookie": [
          "language=en; welcomebanner_status=dismiss; cookieconsent_status=dismiss; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjMsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJoZWxsb0BnbWFpbC5jb20iLCJwYXNzd29yZCI6ImYzMGFhN2E2NjJjNzI4Yjc0MDdjNTRhZTZiZmQyN2QxIiwicm9sZSI6ImN1c3RvbWVyIiwiZGVsdXhlVG9rZW4iOiIiLCJsYXN0TG9naW5JcCI6IjAuMC4wLjAiLCJwcm9maWxlSW1hZ2UiOiIvYXNzZXRzL3B1YmxpYy9pbWFnZXMvdXBsb2Fkcy9kZWZhdWx0LnN2ZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyNi0wNC0yOSAxNzo0OToyOS40MzcgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyNi0wNC0yOSAxNzo0OToyOS40MzcgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiaWF0IjoxNzc3NDg0OTg4fQ.KMpdUzJkWxjatjyR2L0O052H66aok19_wsLCsO_4zqjp_qgEvIwdvtphHFxCAPqugfkPooWFnVn1srtAd3GkJqSgSpNc9hQI7cORR3tPkBHcNfFc7UEmjej703FoEgCwiXwq3aBbLqryYaD9fwCKWYuRh2Dyz5gn0rMseoKI8Uw"
        ],
        "If-None-Match": [
          "W/\"b-/5bSboVjVhGw3qRgvUfZjE1r1Ns\""
        ],
        "Referer": [
          "http://localhost:3000/"
        ],
        "Sec-Fetch-Dest": [
          "empty"
        ],
        "Sec-Fetch-Mode": [
          "cors"
        ],
        "Sec-Fetch-Site": [
          "same-origin"
        ],
        "User-Agent": [
          "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0"
        ]
      }
    },
    "response": {
      "status": "200 OK",
      "headers": {
        "Access-Control-Allow-Origin": [
          "*"
        ],
        "Connection": [
          "keep-alive"
        ],
        "Content-Length": [
          "127"
        ],
        "Content-Type": [
          "application/json; charset=utf-8"
        ],
        "Date": [
          "Wed, 29 Apr 2026 17:49:47 GMT"
        ],
        "Etag": [
          "W/\"7f-t80c0guu7D5V9b1TuJx0ubGtkGI\""
        ],
        "Feature-Policy": [
          "payment 'self'"
        ],
        "Keep-Alive": [
          "timeout=5"
        ],
        "Vary": [
          "Accept-Encoding"
        ],
        "X-Content-Type-Options": [
          "nosniff"
        ],
        "X-Frame-Options": [
          "SAMEORIGIN"
        ],
        "X-Recruiting": [
          "/#/jobs"
        ]
      },
      "body": "{\n  \"user\": {\n    \"id\": 23,\n    \"email\": \"hello@gmail.com\",\n    \"lastLoginIp\": \"0.0.0.0\",\n    \"profileImage\": \"/assets/public/images/uploads/default.svg\"\n  }\n}"
    }
  }
}
------------------------------------------------------------------------------------------------
2026/04/29 23:19:47 event pid=96621 fd=22 gen=5 seq=6 dir=read kind=request routed=request size=2040 req_buf=2040 resp_buf=0 pending=0 preview="GET /rest/products/search?q= HTTP/1.1\r\nHost: localhost:3000\r\nUser-Agent: Mozilla/5.0 (X11; Linux"
2026/04/29 23:19:47 event pid=96621 fd=23 gen=6 seq=7 dir=read kind=request routed=request size=2031 req_buf=2031 resp_buf=0 pending=0 preview="GET /api/Quantitys/ HTTP/1.1\r\nHost: localhost:3000\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; "
2026/04/29 23:19:47 event pid=96621 fd=24 gen=5 seq=3 dir=read kind=request routed=request size=2028 req_buf=2028 resp_buf=0 pending=0 preview="GET /rest/basket/6 HTTP/1.1\r\nHost: localhost:3000\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; r"
2026/04/29 23:19:47 event pid=96621 fd=22 gen=5 seq=7 dir=write kind=response routed=response size=306 req_buf=0 resp_buf=306 pending=1 preview="HTTP/1.1 304 Not Modified\r\nAccess-Control-Allow-Origin: *\r\nX-Content-Type-Options: nosniff\r\nX-Fr"
====================================================================
 TRAFFIC GET /rest/products/search?q= -> 304 Not Modified
====================================================================
{
  "_id": {
    "$oid": "2b82ab9c065421e57199b490"
  },
  "schema_version": "http.conversation.v1",
  "capture_source": "ebpf",
  "capture_mode": "container",
  "captured_at": {
    "$date": "2026-04-29T17:49:47.927280445Z"
  },
  "connection": {
    "src_ip": "172.17.0.2",
    "src_port": 3000,
    "dst_ip": "172.17.0.1",
    "dst_port": 43406,
    "protocol": "tcp",
    "family": "ipv6",
    "role": "outbound"
  },
  "process": {
    "pid": 96621,
    "name": "MainThread",
    "exe": "/nodejs/bin/node"
  },
  "container": {
    "id": "66822672338b7dc1b662b1ba416bcf207831157f02b87f04307f61d2d2b2006f"
  },
  "loss": {},
  "http": {
    "request": {
      "method": "GET",
      "url": "http://localhost:3000/rest/products/search?q=",
      "host": "localhost:3000",
      "path": "/rest/products/search?q=",
      "headers": {
        "Accept": [
          "application/json, text/plain, */*"
        ],
        "Accept-Encoding": [
          "gzip, deflate, br, zstd"
        ],
        "Accept-Language": [
          "en-US,en;q=0.9"
        ],
        "Authorization": [
          "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjMsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJoZWxsb0BnbWFpbC5jb20iLCJwYXNzd29yZCI6ImYzMGFhN2E2NjJjNzI4Yjc0MDdjNTRhZTZiZmQyN2QxIiwicm9sZSI6ImN1c3RvbWVyIiwiZGVsdXhlVG9rZW4iOiIiLCJsYXN0TG9naW5JcCI6IjAuMC4wLjAiLCJwcm9maWxlSW1hZ2UiOiIvYXNzZXRzL3B1YmxpYy9pbWFnZXMvdXBsb2Fkcy9kZWZhdWx0LnN2ZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyNi0wNC0yOSAxNzo0OToyOS40MzcgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyNi0wNC0yOSAxNzo0OToyOS40MzcgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiaWF0IjoxNzc3NDg0OTg4fQ.KMpdUzJkWxjatjyR2L0O052H66aok19_wsLCsO_4zqjp_qgEvIwdvtphHFxCAPqugfkPooWFnVn1srtAd3GkJqSgSpNc9hQI7cORR3tPkBHcNfFc7UEmjej703FoEgCwiXwq3aBbLqryYaD9fwCKWYuRh2Dyz5gn0rMseoKI8Uw"
        ],
        "Connection": [
          "keep-alive"
        ],
        "Cookie": [
          "language=en; welcomebanner_status=dismiss; cookieconsent_status=dismiss; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjMsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJoZWxsb0BnbWFpbC5jb20iLCJwYXNzd29yZCI6ImYzMGFhN2E2NjJjNzI4Yjc0MDdjNTRhZTZiZmQyN2QxIiwicm9sZSI6ImN1c3RvbWVyIiwiZGVsdXhlVG9rZW4iOiIiLCJsYXN0TG9naW5JcCI6IjAuMC4wLjAiLCJwcm9maWxlSW1hZ2UiOiIvYXNzZXRzL3B1YmxpYy9pbWFnZXMvdXBsb2Fkcy9kZWZhdWx0LnN2ZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyNi0wNC0yOSAxNzo0OToyOS40MzcgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyNi0wNC0yOSAxNzo0OToyOS40MzcgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiaWF0IjoxNzc3NDg0OTg4fQ.KMpdUzJkWxjatjyR2L0O052H66aok19_wsLCsO_4zqjp_qgEvIwdvtphHFxCAPqugfkPooWFnVn1srtAd3GkJqSgSpNc9hQI7cORR3tPkBHcNfFc7UEmjej703FoEgCwiXwq3aBbLqryYaD9fwCKWYuRh2Dyz5gn0rMseoKI8Uw"
        ],
        "If-None-Match": [
          "W/\"354c-dt0VTJdKkwcihGfxnmGhaIjLeBY\""
        ],
        "Referer": [
          "http://localhost:3000/"
        ],
        "Sec-Fetch-Dest": [
          "empty"
        ],
        "Sec-Fetch-Mode": [
          "cors"
        ],
        "Sec-Fetch-Site": [
          "same-origin"
        ],
        "User-Agent": [
          "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0"
        ]
      }
    },
    "response": {
      "status": "304 Not Modified",
      "headers": {
        "Access-Control-Allow-Origin": [
          "*"
        ],
        "Connection": [
          "keep-alive"
        ],
        "Date": [
          "Wed, 29 Apr 2026 17:49:47 GMT"
        ],
        "Etag": [
          "W/\"354c-dt0VTJdKkwcihGfxnmGhaIjLeBY\""
        ],
        "Feature-Policy": [
          "payment 'self'"
        ],
        "Keep-Alive": [
          "timeout=5"
        ],
        "X-Content-Type-Options": [
          "nosniff"
        ],
        "X-Frame-Options": [
          "SAMEORIGIN"
        ],
        "X-Recruiting": [
          "/#/jobs"
        ]
      }
    }
  }
}
------------------------------------------------------------------------------------------------
2026/04/29 23:19:48 event pid=96621 fd=24 gen=5 seq=4 dir=write kind=response routed=response size=385 req_buf=0 resp_buf=385 pending=1 preview="HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Option"
2026/04/29 23:19:48 event pid=96621 fd=24 gen=5 seq=5 dir=write kind=unknown routed=response size=154 req_buf=0 resp_buf=539 pending=1 preview="{\"status\":\"success\",\"data\":{\"id\":6,\"coupon\":null,\"UserId\":23,\"createdAt\":\"2026-04-29T17:49:47.49"
================================================================
 TRAFFIC GET /rest/basket/6 -> 200 OK
================================================================
{
  "_id": {
    "$oid": "09022b57efb16e9a62bed85e"
  },
  "schema_version": "http.conversation.v1",
  "capture_source": "ebpf",
  "capture_mode": "container",
  "captured_at": {
    "$date": "2026-04-29T17:49:47.927928603Z"
  },
  "connection": {
    "src_ip": "172.17.0.2",
    "src_port": 3000,
    "dst_ip": "172.17.0.1",
    "dst_port": 43430,
    "protocol": "tcp",
    "family": "ipv6",
    "role": "outbound"
  },
  "process": {
    "pid": 96621,
    "name": "MainThread",
    "exe": "/nodejs/bin/node"
  },
  "container": {
    "id": "66822672338b7dc1b662b1ba416bcf207831157f02b87f04307f61d2d2b2006f"
  },
  "loss": {},
  "http": {
    "request": {
      "method": "GET",
      "url": "http://localhost:3000/rest/basket/6",
      "host": "localhost:3000",
      "path": "/rest/basket/6",
      "headers": {
        "Accept": [
          "application/json, text/plain, */*"
        ],
        "Accept-Encoding": [
          "gzip, deflate, br, zstd"
        ],
        "Accept-Language": [
          "en-US,en;q=0.9"
        ],
        "Authorization": [
          "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjMsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJoZWxsb0BnbWFpbC5jb20iLCJwYXNzd29yZCI6ImYzMGFhN2E2NjJjNzI4Yjc0MDdjNTRhZTZiZmQyN2QxIiwicm9sZSI6ImN1c3RvbWVyIiwiZGVsdXhlVG9rZW4iOiIiLCJsYXN0TG9naW5JcCI6IjAuMC4wLjAiLCJwcm9maWxlSW1hZ2UiOiIvYXNzZXRzL3B1YmxpYy9pbWFnZXMvdXBsb2Fkcy9kZWZhdWx0LnN2ZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyNi0wNC0yOSAxNzo0OToyOS40MzcgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyNi0wNC0yOSAxNzo0OToyOS40MzcgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiaWF0IjoxNzc3NDg0OTg4fQ.KMpdUzJkWxjatjyR2L0O052H66aok19_wsLCsO_4zqjp_qgEvIwdvtphHFxCAPqugfkPooWFnVn1srtAd3GkJqSgSpNc9hQI7cORR3tPkBHcNfFc7UEmjej703FoEgCwiXwq3aBbLqryYaD9fwCKWYuRh2Dyz5gn0rMseoKI8Uw"
        ],
        "Connection": [
          "keep-alive"
        ],
        "Cookie": [
          "language=en; welcomebanner_status=dismiss; cookieconsent_status=dismiss; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjMsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJoZWxsb0BnbWFpbC5jb20iLCJwYXNzd29yZCI6ImYzMGFhN2E2NjJjNzI4Yjc0MDdjNTRhZTZiZmQyN2QxIiwicm9sZSI6ImN1c3RvbWVyIiwiZGVsdXhlVG9rZW4iOiIiLCJsYXN0TG9naW5JcCI6IjAuMC4wLjAiLCJwcm9maWxlSW1hZ2UiOiIvYXNzZXRzL3B1YmxpYy9pbWFnZXMvdXBsb2Fkcy9kZWZhdWx0LnN2ZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyNi0wNC0yOSAxNzo0OToyOS40MzcgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyNi0wNC0yOSAxNzo0OToyOS40MzcgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiaWF0IjoxNzc3NDg0OTg4fQ.KMpdUzJkWxjatjyR2L0O052H66aok19_wsLCsO_4zqjp_qgEvIwdvtphHFxCAPqugfkPooWFnVn1srtAd3GkJqSgSpNc9hQI7cORR3tPkBHcNfFc7UEmjej703FoEgCwiXwq3aBbLqryYaD9fwCKWYuRh2Dyz5gn0rMseoKI8Uw"
        ],
        "If-None-Match": [
          "W/\"9a-8Vn6YsZcgLxUpNgyOglFcpajQ1M\""
        ],
        "Referer": [
          "http://localhost:3000/"
        ],
        "Sec-Fetch-Dest": [
          "empty"
        ],
        "Sec-Fetch-Mode": [
          "cors"
        ],
        "Sec-Fetch-Site": [
          "same-origin"
        ],
        "User-Agent": [
          "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0"
        ]
      }
    },
    "response": {
      "status": "200 OK",
      "headers": {
        "Access-Control-Allow-Origin": [
          "*"
        ],
        "Connection": [
          "keep-alive"
        ],
        "Content-Length": [
          "154"
        ],
        "Content-Type": [
          "application/json; charset=utf-8"
        ],
        "Date": [
          "Wed, 29 Apr 2026 17:49:48 GMT"
        ],
        "Etag": [
          "W/\"9a-FBasyhcMDUsrbRaQk9rD6kfFEws\""
        ],
        "Feature-Policy": [
          "payment 'self'"
        ],
        "Keep-Alive": [
          "timeout=5"
        ],
        "Vary": [
          "Accept-Encoding"
        ],
        "X-Content-Type-Options": [
          "nosniff"
        ],
        "X-Frame-Options": [
          "SAMEORIGIN"
        ],
        "X-Recruiting": [
          "/#/jobs"
        ]
      },
      "body": "{\n  \"status\": \"success\",\n  \"data\": {\n    \"id\": 6,\n    \"coupon\": null,\n    \"UserId\": 23,\n    \"createdAt\": \"2026-04-29T17:49:47.498Z\",\n    \"updatedAt\": \"2026-04-29T17:49:47.498Z\",\n    \"Products\": []\n  }\n}"
    }
  }
}
```
