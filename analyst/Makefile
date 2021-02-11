all: build key
build: Analyst.java Connection.java SocketUtil.java
	javac *.java
key: truststore/bank.cert.pem
	openssl pkcs12 -export -in private/analyst.cert.pem -inkey private/analyst.key.pem -out private/analyst.p12 -name analyst-certificate
	keytool -noprompt -importkeystore -deststorepass changeit -srckeystore private/analyst.p12 -destkeypass changeit -destkeystore private/keystore.jks -srcstoretype PKCS12 -srcstorepass changeit -alias analyst-certificate
	keytool -noprompt -import -file truststore/bank.cert.pem -deststorepass changeit -destkeystore truststore/truststore.jks -srckeystore truststore/bank.p12 -srcstoretype PKCS12 -alias bank-certificate
clean:
	rm truststore/*.p12 & rm private/*.p12 & rm *.class

