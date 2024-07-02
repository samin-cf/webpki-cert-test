#!/bin/bash

# Set variables
CA_KEY="ca.key"
CA_CERT="ca.crt"
SERVER_KEY_PREFIX="server"
SERVER_CSR_PREFIX="server"
SERVER_CERT_PREFIX="server"
CONFIG_FILE="openssl.cnf"
DAYS_VALID=365

# Create the OpenSSL configuration file with SANs
cat > $CONFIG_FILE <<EOF
[req]
default_bits       = 2048
default_keyfile    = server.key
distinguished_name = req_distinguished_name
req_extensions     = req_ext
x509_extensions    = v3_ca
prompt             = no

[req_distinguished_name]
C  = US
ST = California
L  = San Francisco
O  = MyCompany
CN = localhost

[req_ext]
subjectAltName = @alt_names

[v3_ca]
subjectAltName = @alt_names
basicConstraints = CA:TRUE
keyUsage = digitalSignature, keyCertSign
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

# Generate a private key for the CA
openssl ecparam -genkey -name secp521r1 -out $CA_KEY

# Generate a self-signed CA certificate
openssl req -new -x509 -key $CA_KEY -sha512 -days $DAYS_VALID -out $CA_CERT -config $CONFIG_FILE -extensions v3_ca

# Function to generate a server key, CSR, and certificate
generate_server_cert() {
    local server_key=$1
    local server_csr=$2
    local server_cert=$3
    local sig_alg=$4

    # Generate a private key for the server
    openssl ecparam -genkey -name secp384r1 -out $server_key

    # Generate a certificate signing request (CSR) for the server
    openssl req -new -key $server_key -out $server_csr -config $CONFIG_FILE

    # Generate the server certificate signed by the CA
    openssl x509 -req -in $server_csr -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial -out $server_cert -days $DAYS_VALID -$sig_alg -extfile $CONFIG_FILE -extensions req_ext

    # Verify the generated server certificate
    openssl x509 -in $server_cert -text -noout
}

# Generate server certificates with different signature algorithms
generate_server_cert "${SERVER_KEY_PREFIX}_sha512.key" "${SERVER_CSR_PREFIX}_sha512.csr" "${SERVER_CERT_PREFIX}_sha512.crt" "sha512"
generate_server_cert "${SERVER_KEY_PREFIX}_sha256.key" "${SERVER_CSR_PREFIX}_sha256.csr" "${SERVER_CERT_PREFIX}_sha256.crt" "sha256"
generate_server_cert "${SERVER_KEY_PREFIX}_sha384.key" "${SERVER_CSR_PREFIX}_sha384.csr" "${SERVER_CERT_PREFIX}_sha384.crt" "sha384"

