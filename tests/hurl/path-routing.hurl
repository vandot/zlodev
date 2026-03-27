# Path route /api hits httpbin on port 9001 (SCRIPT_NAME=/api)
GET https://dev.lo/api/get
HTTP 200
[Asserts]
jsonpath "$.url" contains "/api/get"

# Non-matching path hits default upstream on port 9000
GET https://dev.lo/get
HTTP 200
[Asserts]
jsonpath "$.url" exists
