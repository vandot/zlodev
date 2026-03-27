# Remote endpoint routing to httpbin.org
GET https://remote.dev.lo/get
HTTP 200
[Asserts]
jsonpath "$.url" exists
