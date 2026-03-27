# Basic GET — httpbin echoes request info
GET https://dev.lo/get
HTTP 200
[Asserts]
jsonpath "$.url" exists

# POST with JSON body — httpbin echoes posted data
POST https://dev.lo/post
Content-Type: application/json
{"message": "hello from zlodev"}
HTTP 200
[Asserts]
jsonpath "$.json.message" == "hello from zlodev"

# Status code preservation
GET https://dev.lo/status/404
HTTP 404

# Response header forwarding
GET https://dev.lo/response-headers?X-Custom=hello
HTTP 200
[Asserts]
header "X-Custom" == "hello"

# Chunked transfer encoding
GET https://dev.lo/stream/5
HTTP 200
[Asserts]
body contains "url"
