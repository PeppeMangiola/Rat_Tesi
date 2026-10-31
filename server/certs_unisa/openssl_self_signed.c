openssl req -x509 -newkey rsa:2048 -keyout server/certs_unisa/server.key \
  -out server/certs_unisa/server.crt -days 365 -nodes \
  -subj "/CN=192.168.42.124"
