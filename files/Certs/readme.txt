Example commands for generating test certificates used for gRPC mTLS remote connections.

Password to the .pfx files: test

Generate with commands:

openssl req -x509 -newkey rsa:2048 -keyout client-tls.key -out client-tls.crt -days 365 -nodes -subj "/CN=localhost"
openssl pkcs12 -export -out client-tls.p12 -inkey client-tls.key -in client-tls.crt -password pass:test

openssl req -x509 -newkey rsa:2048 -keyout server-tls.key -out server-tls.crt -days 365 -nodes -subj "/CN=localhost"
openssl pkcs12 -export -out server-tls.p12 -inkey server-tls.key -in server-tls.crt -password pass:test
