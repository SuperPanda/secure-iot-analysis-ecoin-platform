make: collector.c
	gcc -std=gnu99 -Wall -o collector collector.c -lssl -lcrypto
	gcc -std=gnu99 -Wall -o collector-input collector-input.c
clean:
	rm coins/* & rm bad-coins/coins/* & rm socket-collector-* & rm ./collector & rm ./collector-input
cert: 
	openssl x509 -pubkey -noout -in truststore/bank.cert.pem > truststore/bank.pub.pem
