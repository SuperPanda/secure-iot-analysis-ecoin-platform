all: build cert
build: Bank.java Connection.java SocketUtil.java
	javac *.java
cert:
	# type "changeit" a heap of times
	openssl pkcs12 -export -in keystore/bank.cert.pem \
	-inkey private/bank.key.pem -out server.p12 -name bank-certificate
	openssl pkcs12 -export -in truststore/collector.cert.pem -out truststore/collector.p12 -name collector-certificate
	openssl pkcs12 -export -in truststore/analyst.cert.pem -out truststore/analyst.p12 -name analyst-certificate
	keytool -noprompt -destkeypass changeit -importkeystore -deststorepass changeit -destkeypass changeit -destkeystore bank.keystore \
	-srckeystore server.p12 -srcstoretype PKCS12 -srcstorepass changeit \
	-alias bank-certificate
	keytool -noprompt -destkeypass changeit -importkeystore -deststorepass changeit -destkeypass changeit -destkeystore bank.truststore \
	-srckeystore truststore/collector.p12 -srcstoretype PKCS12 -srcstorepass changeit \
	-alias collector-certificate
	keytool -noprompt -destkeypass changeit -importkeystore -deststorepass changeit -destkeypass changeit -destkeystore bank.truststore \
	-srckeystore truststore/analyst.p12 -srcstoretype PKCS12 -srcstorepass changeit \
	-alias analyst-certificate
	rm server.p12
	rm truststore/analyst.p12
	rm truststore/collector.p12
clean:
	rm *.class
clean-cert:
	rm bank.keystore &  rm bank.truststore & rm server.p12

