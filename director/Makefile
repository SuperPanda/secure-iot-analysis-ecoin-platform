all: Director.java Connection.java SocketUtil.java
	javac *.java
cert:
	openssl genrsa -out director.key.pem 2048
	openssl req -new -x509 -days 3650 -key director.key.pem -sha256 -out director.cert.pem -subj "/C=AU/ST=WA/O=PANDASPORTAL/OU=DIRECTOR/CN=localhost"
	openssl pkcs12 -export -in director.cert.pem -inkey director.key.pem -out director.p12 -name director-certificate
	keytool -noprompt -importkeystore -deststorepass changeit -destkeypass changeit -destkeystore director.keystore -srckeystore director.p12 -srcstoretype PKCS12 -srcstorepass changeit -alias director-certificate
	rm director.p12
clean:
	rm *.class
