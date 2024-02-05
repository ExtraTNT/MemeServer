openssl genrsa -out key.pem 2048
openssl req -x509 -new -key key.pem > cert.pem
