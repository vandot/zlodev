#ifdef _WIN32
// Keep wincrypt.h (pulled in by windows.h) from defining X509_NAME and friends.
#define NOCRYPT
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif
#include <openssl/x509v3.h>
