touch ca-db-index
echo 01 > ca-db-serial

# Certificate Authority
openssl req -nodes -x509 -newkey ec:<(openssl ecparam -name secp256r1) -days 3650 -keyout ca-key.pem -out ca-cert.pem -subj "/C=CN/ST=TEST/L=TEST/O=TEST/OU=TEST/CN=testca.test.com"

# Server Certificate
openssl req -nodes -new -newkey ec:<(openssl ecparam -name secp256r1) -keyout server-key.pem -out server.csr -subj "/C=CN/ST=TEST/L=TEST/O=TEST/OU=TEST/CN=testserver.test.com"

# Sign Server Certificate
openssl ca -config ca.conf -days 3650 -config ca.conf -in server.csr -out server-cert.pem

# Client Certificate
openssl req -nodes -new -newkey ec:<(openssl ecparam -name secp256r1) -keyout client-key.pem -out client.csr -subj "/C=CN/ST=TEST/L=TEST/O=TEST/OU=TEST/CN=testclient.test.com"

# Sign Client Certificate
openssl ca -config ca.conf -days 3650 -config ca.conf -in client.csr -out client-cert.pem
