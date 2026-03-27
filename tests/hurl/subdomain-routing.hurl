# Subdomain route api.dev.lo hits httpbin on port 9002
GET https://api.dev.lo/get
HTTP 200
[Asserts]
jsonpath "$.url" exists
