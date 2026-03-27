# HTTP to HTTPS redirect
GET http://dev.lo/get
HTTP 302
[Asserts]
header "Location" == "https://dev.lo/get"
