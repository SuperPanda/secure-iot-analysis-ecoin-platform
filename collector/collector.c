/**
 * AUTHOR: Andrew Briscoe (21332512)
 * FILE: collector.c
 * DATE: 2015-05-20
 *
 * The collector works by using looping bash scripts to act as a "collection source" that pipes output to: input-collector SOURCE
 * The collector can specify the source by using the -c argument and the service request by using the -s command
 * The collector can request 5 ecoins on startup by using -n5 argument, or whatever number is needed
 *
 * To load coins from none volatile memory, use -l
 *
 * Unimplemented: the sink (the output of the result) :( this could be used to daisy chain collectors
 * To see a list of all the possible commands: ./collector -h 
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <linux/limits.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <sys/select.h>
#include <sys/un.h>
#include <fcntl.h>

#define MAX_SIZE_BUFFER 2048

#define BANK_WITHDRAW 50
#define BANK_DISPENSE 56
#define BANK_DISPENSE_ACK 57
#define BANK_DISPENSE_DONE 58

#define SERVICE_REQ 300
#define SERVICE_READY 301
#define SERVICE_UNAVAILABLE 302
#define SERVICE_OPERATION 350
#define SERVICE_COMPLETE 360
#define SERVICE_ERROR 370
#define MALFORMED_PACKET_ERROR 910

#define PACKET_HEADER_SIZE 4
#define SERVICE_NAME_SIZE 16

#define COLLECT_BUFFER_SIZE 20000 //20kb

#define CHK_ERR(s,msg) { if (s==-1){ perror(msg);}}
#define SHOW_OUTBOUND(msg,code) { printf("Sent %s [%d]\n",msg,code); }
#define SHOW_INBOUND(msg,code) { printf("Recv'ed %s [%d]\n",msg,code); }

/**
 * All the defaults!!
 */
char  cwd[PATH_MAX];
const char* BANK_SERVER = "127.0.0.1";
const char* BANK_PORT = "29991";
const char* DIRECTOR_SERVER = "127.0.0.1";
const char* DIRECTOR_PORT = "29992";
const char* SERVICE_REQUIRED = "Test";
const char* COLLECTOR_INTERFACE = "./socket-collector-Test";

const char* BANK_CERTIFICATE = "truststore/bank.pub.pem\0";

RSA* BANK_PUBLIC_KEY = NULL;

typedef struct {
	int socket;
	SSL *sslHandle;
	SSL_CTX *sslContext;
} connection;


/**
 * An AES key and an IV walk into a bar... ;)
 */
typedef struct {
	unsigned char sk[32];
	unsigned char iv[16];
} enc_head;

// Documentation: https://www.openssl.org/docs/crypto/pem.html
// and help from:
// http://stackoverflow.com/questions/9406840/rsa-encrypt-decrypt
// and eventually derived from:
// http://hayageek.com/rsa-encryption-decryption-openssl-c/#public-encrypt
RSA* getPublicRSA(){
	if (BANK_PUBLIC_KEY != NULL) return BANK_PUBLIC_KEY;
	
	FILE *fp = fopen(BANK_CERTIFICATE,"rb");
	if (fp == NULL){
		printf("Error reading the bank's public key %s \n",BANK_CERTIFICATE);
		return NULL;
	}
	RSA *rsa = RSA_new();
	rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL,NULL);
	if (rsa == NULL)
		ERR_print_errors_fp(stderr);
	BANK_PUBLIC_KEY = rsa;
	fclose(fp);
	return BANK_PUBLIC_KEY;

}

// Elements Derived from:
// (1) SSL Programming Tutorial
// http://h71000.www7.hp.com/doc/83final/ba554_90007/ch04s03.html
// (2) Beej's Guide to Network Programming
int establishSocket(const char* netaddr,const char* port){
	int s;
	struct addrinfo hints;
	struct addrinfo *resolution;
	memset(&hints,0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	
	printf("Connecting to: %s:%s\n",netaddr,port);
	if (getaddrinfo(netaddr,port,&hints,&resolution) != 0){
		printf("Failure to get address information\n");
		exit(EXIT_FAILURE);
	}
	int i;
 	// make a socket file descriptor
	s = socket(resolution->ai_family,resolution->ai_socktype, resolution->ai_protocol);
	CHK_ERR(s, "socket");
	
	//connect(s, resolution->ai_addr, resolution->ai_addrlen);
	if ((i = connect(s, resolution->ai_addr, resolution->ai_addrlen)) == -1){
		perror("Unable to connect to remote server");
		exit(EXIT_FAILURE);
		
	}

	return s;
}



void initOpenSSL(){
	if(!SSL_library_init()){
		perror("Failed to start OpenSSL");
		exit(-1);
	}
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
}

SSL_CTX* InitCTX(){ 
	SSL_CTX *ctx;
	
	// Create context
	ctx = SSL_CTX_new(SSLv23_client_method());
	
	// load key - http://www.informit.com/articles/article.aspx?p=22078 
	SSL_CTX_use_certificate_file(ctx,"certs/collector.cert.pem",SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(ctx, "certs/collector.key.pem", SSL_FILETYPE_PEM);
	OpenSSL_add_all_algorithms(); 

	if (ctx == NULL){
		ERR_print_errors_fp(stderr);
		return NULL;
	}
	return ctx;	
}

// http://savetheions.com/2010/01/16/quickly-using-openssl-in-c/
connection* getConnection(const char* server, const char* port){
	connection *c;
	c = malloc(sizeof(connection));
	c->socket = establishSocket(server,port);
	c->sslHandle = NULL;
	c->sslContext = NULL;
	return c;
}

connection* getSSLConnection(const char* server,const char* port){
	initOpenSSL();
	connection *c;
	c = getConnection(server,port);
	if (c == NULL){
		perror("Unable to establish a connection\n");
		goto bad;
	}
	c->sslContext = InitCTX();

	// creates the ssl struct for the connection
	c->sslHandle = SSL_new(c->sslContext);	
	if (c->sslHandle == NULL){
		perror("Unable to create ssl handle");
		goto bad;
	}
	// attach struct to the socket - http://savetheions.com/2010/01/16/quickly-using-openssl-in-c/
	if (!SSL_set_fd(c->sslHandle,c->socket)) {
		perror("Unable to set the SSL handle to the socket");
		goto bad;
	}
	if (SSL_connect(c->sslHandle) != 1) {
		perror("Failed to connect");
		goto bad;
	}
	if (c->sslContext == NULL || c->sslHandle == NULL){
		printf("Unable to establish a secure SSL Connection\n");
		return NULL;
	}
	return c;

	bad:
	ERR_print_errors_fp(stderr);
	return NULL;
}

void closeConnection(connection *c){
	printf("Closing connection\n");
	if (c != NULL){
		if(c->sslHandle){
			SSL_shutdown(c->sslHandle);
			//SSL_free(c->sslHandle);
		}
		if (c->socket >= 0) close(c->socket);
		if (c->sslContext) SSL_CTX_free (c->sslContext);
	}
}

typedef struct {
	unsigned short length;
	unsigned short packet_type;
	unsigned short amount;
} bankPacket;

typedef struct {
	unsigned short length;
	unsigned short packet_type;
	char data[MAX_SIZE_BUFFER];
} packet;

typedef struct {
	unsigned short length;
	unsigned short packet_type;
	char service[SERVICE_NAME_SIZE];
	char data[COLLECT_BUFFER_SIZE];
} dataPacket;

//typedef struct Coin {
//	unsigned char *filename;
	//struct CoinChain *nextcoin;
//} coin;

static char wallet[10000][25];
static int walletSize = 0;


//http://stackoverflow.com/questions/13479760/c-socket-recv-and-send-all-data
//most helpful
int send_all(connection *c, void *buffer,int length){
	//printf("sending bytes %d\n",length);
	void *ptr;
	ptr = buffer; // = (char*)buffer;
	//char *ptr = (char*)buffer;
	while (length > 0){
		//int i = send(socket,ptr,length,0);
		int i = SSL_write(c->sslHandle,ptr,length);
		if(i<1) return 0;
		ptr += i;
		length -= i;
	}
	return 1;
}

int recv_all(connection *c, void *buffer, int length){
	void *ptr;
	ptr = buffer;
	while (length > 0){
		int x = SSL_read(c->sslHandle,ptr,length);
		if (x < 0){
			printf("Ungraceful disconnect\n");
			return -1;
		}
		//if (x != 0){ printf("[%d]/%d\n",x,length);}
		//if (x == 0) return -1;
		ptr += x;
		length -= x;
	}
	//printf("Filled recv buffer\n");
	return 1;
}

// maps 1-byte char, map to a 2-byte space (padding)
// used in early protocols
int charsToShort(char *c, int srcOffset, char *buffer, int destOffset, int length){
	// char[4] -> short[6], offset 1, length 4
	// a b c d  -> z k, 0 a, 0 b, 0 c, 0 d, x y
	// 
	//if (max < destOffset+2*length){
	//	perror("Out of bounds");
	//}
	int offset = 0;
	for (int i = 0; i<length;i++){
		//printf("%c\n",(char *)(&c+i));
		//printf("%c\n",c[i]);
		*(buffer+destOffset+i*2+1) = (unsigned short) c[srcOffset+i];
		*(buffer+destOffset+i*2) = '\0';
		offset += 2;
	}
	

	// 00 - pos 1
	// add 2 items
	// 00 01 02 - pos 3
	return offset;
}
// http://stackoverflow.com/questions/230062/whats-the-best-way-to-check-if-a-file-exists-in-c-cross-platform
int checkFile(char *filename){
	// http://stackoverflow.com/questions/13945341/c-check-if-a-file-exists-without-being-able-to-read-write-possible
	struct stat st;
	int result = stat(filename,&st);
	return result == 0;
}

void writeFile(char *filename,char* buffer,int length){
	FILE *fileOut;
	fileOut = fopen(filename,"w+");
	fwrite(buffer,1,length,fileOut);
	fclose(fileOut);		

}

int readFile(char *filename, unsigned char *destBuffer){
	FILE *fileIn;
	int bytes;
	fileIn = fopen(filename,"rb");
	int c = 0;
	while((bytes = fread(destBuffer,sizeof(unsigned char),BUFSIZ, fileIn)) > 0){
		c+=bytes;
	}
	fclose(fileIn);
	return c;
}

void setBadCoin(const char *c){
	const char prefix[]="./bad-coins/\0";
	char *filename;
	filename = malloc(strlen(prefix)+strlen(c)+1);
	strcpy(filename,prefix);
	strcat(filename, c);
	if (rename(c,filename) == 0){
		printf("The coin %s has been moved to %s\n",c,filename);
	} else {
		printf("Error setting coin status to bad\n");
	}
}
void addCoinToWallet(char *filename){
	//struct CoinChain *cl;
	//c = malloc(sizeof(coin));
	strcpy(wallet[walletSize++],filename);
	free(filename); // CHECK
}

/*
 * http://stackoverflow.com/questions/12489/how-do-you-get-a-directory-listing-in-c
 */
int readCoinsFromNonVolatileMemory(){
	DIR *dp;
	struct dirent *ep;
	const char prefix[] = "coins/\0";
	char* filename;
	int i = 0;
	dp = opendir("./coins");
	if (dp != NULL){
		while ((ep=readdir(dp))){
			if (strcmp(ep->d_name,".") == 0 || strcmp(ep->d_name,"..")==0) continue;
			filename = malloc(strlen(prefix)+strlen(ep->d_name)+1);
			strcpy(filename,prefix);
			strcat(filename,ep->d_name);
			//printf("Reading coin from file: %s\n",filename);
			addCoinToWallet(filename);
			i++;
		}
		closedir(dp);
	}
	return i;
}
void writeCoin(char* buffer, int length){
	char *COIN_DIR = strdup("coins/");
	char* outputFilename;
	char filename[length];
	for (int j=0;j<(length/2)-1;j++){
		filename[j] = (65+((unsigned short) buffer[j])%26);
	}
	outputFilename = malloc(1+strlen(COIN_DIR)+length/2);
	strcpy(outputFilename,COIN_DIR);
	strcat(outputFilename,filename);
	writeFile(outputFilename, buffer, length);

	addCoinToWallet(outputFilename);
	printf("Saved coin: %s\n",filename);
}

char* getCoin(){
	char *c;
	if (walletSize > 0){
		c = wallet[--walletSize];
		return c;
	} 
	return NULL;
}

int sendHeader(connection *c, unsigned short type){
	//printf("Sending MSG Code: %d\n",type);
	unsigned short *out;
	out = malloc(2*sizeof(unsigned short));
	memset(out,0,2*sizeof(unsigned short));
	out[0] = 0;	
	out[1] = type;
	if (send_all(c,out,PACKET_HEADER_SIZE)<= 0){
		printf("Error sending error\n");
		return -1;
	}
	//printf("Sent header: %d\n",type);
	free(out);
	return 1;
}

int bankProtocol_withdraw(connection *c, unsigned short amount){
	if (!SSL_CTX_load_verify_locations(c->sslContext,"truststore/bank.cert.pem",NULL)){
		perror("Unable to load truststore");
		ERR_print_errors_fp(stderr);
		return -1;
	}

	bankPacket *pkt;
	pkt = calloc(1,sizeof(bankPacket));
	//memset(pkt,0,sizeof(bankPacket));
	// 2-byte shorts || 1-byte chars map to 2-byte chars
	// how many bytes are in use
	// or header field later	
	// to allow for the creation of dataframes
	// that gradually fill up with data
	pkt->length = 1;
	pkt->packet_type = BANK_WITHDRAW;
	pkt->amount = amount;

	printf("Requesting %d ecoins from the bank\n",amount);
	if (send_all(c,pkt,3*sizeof(short)) <= 0){
		printf("Error sending request\n");
		return -1;
	}
	printf("Request sent.\n");
		
	free(pkt);
	
	unsigned short headbuf[3];
	if (recv_all(c,headbuf,PACKET_HEADER_SIZE+2)<=0){
		printf("Error retreiving coin length data\n");
	}
	//printf("1:%d\n",(int) headbuf[0]); // This will show the length of the data packet (0)
	//printf("2:%d\n", (int) headbuf[1]); // This will show the type of message WITHDRAW_REPLY (55)
	//printf("3:%d\n", (int) headbuf[2]); // This is a parameter for the coin sizes, unfornuately in terms of the number of java chars :(
	int coinLength = (int) headbuf[2];
	printf("coin length: %d\n",coinLength);
	char coinbuf[coinLength]; 

	if (recv_all(c,headbuf,PACKET_HEADER_SIZE)<0){
		printf("It's a sad world!\n");
	}
	
	for (int i = amount; i>0;i--){
		memset(coinbuf,0,coinLength);
		if (recv_all(c,&coinbuf,coinLength) == -1){ return -1; }
		writeCoin(coinbuf,coinLength);
		sendHeader(c,BANK_DISPENSE_ACK);
		//int status;
		memset(headbuf,0,PACKET_HEADER_SIZE);
		if (recv_all(c,headbuf,PACKET_HEADER_SIZE) <= 0){
			printf("Bank communication error\n");
			free(pkt);
			return -1;
		}
		//printf("Topic: %d\n",headbuf[1]);
		if ((int)headbuf[1] == BANK_DISPENSE_DONE){
			SHOW_INBOUND("BANK_DISPENSE_DONE",BANK_DISPENSE_DONE);
			printf("Successfully received coins\n");
			free(pkt);
			return 1;
		}
	}
	free(pkt);
	printf("No acknowledgement of bank shutdown\n");
	return 0;

}


int getCredit(unsigned short numCredits){
	connection *c;
	c = getSSLConnection(BANK_SERVER,BANK_PORT);
	if (c == NULL){
		printf("Unable to establish SSL connection to bank\n");
		exit(EXIT_FAILURE);
	}
	if (bankProtocol_withdraw(c,numCredits) == -1){
		perror("Error withdrawing credit from the bank");
		exit(EXIT_FAILURE);
	}
	closeConnection(c);
	return 1;
}


connection* locateService(const char* service){
	connection *c;
	char *text = strdup(service);

	packet *pkt;
	pkt = malloc(sizeof(packet));
	memset(pkt,1,sizeof(packet));
	pkt->packet_type = SERVICE_REQ;
	pkt->length = 0;
	int copyOffset = PACKET_HEADER_SIZE; // Gotta make some space in the payload for the header
	
	unsigned short charsToCopy = (unsigned short) strlen(text);
	int i = charsToShort(text, 0, pkt->data, copyOffset, charsToCopy);
	pkt->length = pkt->length+i;

	unsigned short *ptr;
	ptr = &pkt->data;

	// make the length field the right endian
	// and store in the space left in the output buffer packet
	unsigned short length = pkt->length; // So I can access the length before it is modified for network layout
	ptr[0] = pkt->length;
	ptr[1] = pkt->packet_type;

	send_probe:	

	c = getSSLConnection(DIRECTOR_SERVER,DIRECTOR_PORT);
	if (send_all(c,&pkt->data,(int)length+PACKET_HEADER_SIZE*2)<=0){
		printf("Error requesting service provider\n");
		goto fail;
	}
	
	unsigned short buf[MAX_SIZE_BUFFER];
	if (recv_all(c,buf,4)<0){
		goto fail;		
	}

	//printf("Response code from director: %d\n",(int)buf[1]);

	switch ((int)buf[1]){
		case SERVICE_UNAVAILABLE:
			SHOW_INBOUND("SERVICE_UNAVAILABLE",SERVICE_UNAVAILABLE);
			printf("Service currently unavailable\n");
			closeConnection(c);
			printf("Trying again in... ");
			for (int i = 5; i > 0; i--){
				printf("%d ",i);
				fflush(stdout);
				sleep(1);
			}
			printf("\nRetransmitting probe...\n");
			goto send_probe;
			//break;
		case SERVICE_READY:
			SHOW_INBOUND("SERVICE_READY",SERVICE_READY);
			printf("Service is ready!\n");
			goto done;
		default:
			printf("Response code from director: %d\n",(int)buf[1]);
			printf("Error communicating with director\n");
			goto fail;
	}

	fail:
	closeConnection(c);
	c = NULL;
	done:	
	free(text);
	free(pkt);
	return c;

	
}

/**
 * Special thanks to openssl.org/docs,
 * Valgrind,
 * eventually leading me to realise the problem wasn't with my data but
 * rsa was NULL
 * Then remembering to use ERR_print_errors_fp everywhere
 * and then life became easy... 3 hours later >.<
 *
 */
int encryptPayloadHeader(int len, unsigned char *fromData, unsigned char *toData){
	RSA *rsa;
	rsa = getPublicRSA(BANK_CERTIFICATE);
	if (rsa == NULL){
		printf("ERROR\n");
		return -1;
	}
	//https://www.openssl.org/docs/crypto/RSA_public_encrypt.html
	int i = RSA_public_encrypt(len,fromData,toData,rsa,RSA_PKCS1_PADDING);
	if (i == -1)
		ERR_print_errors_fp(stderr);
	return i;
	
}
// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
int encryptPayloadData(unsigned char* cleartext, int cleartext_length, enc_head *head, unsigned char* ciphertext){

	EVP_CIPHER_CTX *ctx;

	int len;
	int ciphertext_len;

	if (!(ctx = EVP_CIPHER_CTX_new())){
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(),NULL,head->sk,head->iv)!=1){
		ERR_print_errors_fp(stderr);
		return -1;
	}

	//TODO: make this loop?
	if (EVP_EncryptUpdate(ctx, ciphertext, &len, cleartext, cleartext_length)!=1){
		ERR_print_errors_fp(stderr);
		return -1;
	}
	ciphertext_len = len;
	if (EVP_EncryptFinal_ex(ctx, ciphertext+len,&len) != 1){
		ERR_print_errors_fp(stderr);
		return -1;
	}

	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
int decryptPayload(unsigned char *ciphertext, int ciphertext_length, enc_head *head, unsigned char* cleartext){
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	if(!(ctx = EVP_CIPHER_CTX_new())) {
		ERR_print_errors_fp(stderr);
		return -1;			
	}

	if (EVP_DecryptInit_ex(ctx,EVP_aes_256_cbc(),NULL, head->sk, head->iv)!=1){
		ERR_print_errors_fp(stderr);
		return -1;
	}
	if (EVP_DecryptUpdate(ctx,cleartext, &len, ciphertext, ciphertext_length)!=1){
		ERR_print_errors_fp(stderr);
		return -1;
	}
	if(EVP_DecryptFinal_ex(ctx, cleartext + len, &len)){
		ERR_print_errors_fp(stderr);
		return -1;
	}
	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
	
}

/*
 * The code for the collection of data via UNIX socket is derived from:
 * 	https://troydhanson.github.io/misc/Unix_domain_sockets.html
 * 	and
 *	https://github.com/troydhanson/misc/blob/master/network/unixdomain/srv.c
 */
int collectData(const char *sock_path, int timetosend, unsigned char *buffer){
	
	int dataSize = 0;

	fd_set readfds;
	struct timeval starttime, currenttime, tv;
	gettimeofday(&starttime,NULL);

	int fd,cl,rc;
	if ((fd = socket(AF_UNIX, SOCK_STREAM,0))==-1){
		perror("socket error!");
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));

	// COPY and PASTE, just wanted to get something working
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path,sock_path,sizeof(addr.sun_path)-1);
	unlink(sock_path);
	// End copy and paste

	int running = 1;

	fcntl(fd,F_SETFL,O_NONBLOCK);
	if (bind(fd,(struct sockaddr*)&addr, sizeof(addr)) == -1){
		perror("Bind error\n");
		running = 0;
	}

	if (listen(fd, 5) == -1){
		perror("listen error\n");
		running = 0;
	}

	FD_ZERO(&readfds);
	FD_SET(fd,&readfds);
	int n = fd+1; 

	while(running){	

		// Remove all fd's from the set of watched fd's
		FD_ZERO(&readfds);

		// Add fd to the set of file descriptors to be watched for read activitiy
		FD_SET(fd,&readfds);

		// load the current time
		gettimeofday(&currenttime,NULL);

		// set the timeout inteval to be the remaining time left until the data is due to be sent
		int interval = timetosend + starttime.tv_sec - currenttime.tv_sec;
		if (interval < 0) interval = 0; // in case the duration has elapsed
		tv.tv_sec = interval;
		tv.tv_usec = 0;

		//block until timeout or data enters the collection sink
		int rv=select(n,&readfds,NULL,NULL, &tv);
		if (rv == -1){
			perror("select");
			running = 0;
		} else if (rv == 0){
			running = 0;
		} else {
			if ((cl = accept(fd,NULL,NULL)) == -1){
				perror("accept error");
				continue;
			}
			unsigned char buf[1000];
			while ((rc=recv(cl,buf,sizeof(buf),0)) > 0){
				if (dataSize+rc >= COLLECT_BUFFER_SIZE){ running = 0; break; }
				printf("read %u bytes\n",rc);
				for (int i = 0; i < rc; i++){
					*(buffer+dataSize+i) = buf[i];
				}
				dataSize += rc;
			
			}
			if (rc ==-1){
				perror("read");
				//running = 0;
			}
			if (rc ==0){
				close(cl);
			}
		}
	}
	

	printf("collected data size: %d\n", dataSize);
	//for (int i = 0; i < dataSize;i++){
	//	printf("~~%c\n",buffer[i]);
	//}	
	//printf("\n");
	return dataSize;
}

int sendData(connection *c, const char *serviceProvider, unsigned char *buffer,int dataSize){
	dataPacket *pkt;
	pkt = calloc(1,sizeof(dataPacket));
	printf("service provider: %s\n",serviceProvider);
	memcpy(pkt->service,serviceProvider,strlen(serviceProvider));
	pkt->service[strlen(serviceProvider)] = '\0';
	pkt->packet_type = SERVICE_OPERATION;


	enc_head *encHead;
	encHead = malloc(sizeof(enc_head));

	if(RAND_bytes(encHead->iv,16) != 1){
		printf("Error generating IV for payload header\n");
	}
	
	char *cc;
	cc = getCoin();

	if (cc == NULL){ 
		printf("No coins available\n");
		return 1;
	}
	while(checkFile(cc) == 0 && walletSize > 0){
		printf("Coin has been used by another collector or has gone astray, skipping\n");
		cc = getCoin();
	}
	if (walletSize == 0 && checkFile(cc) == 0){
		printf("Out of coins\n");
		return 1;
	}

	// Read the coin into buffer
	unsigned char coinIn[32];
	if (readFile(cc,coinIn) != 32){
		printf("Error reading coin\n");
	}
	// copy coin into the payload headers symmetric key
	memcpy(encHead->sk,&coinIn,32);

	unsigned char *payloadHead; /** THE YING **/
	payloadHead = malloc(256);

	// encrypt the payload header with RSA using the banks public key
	int payloadHeadSize = encryptPayloadHeader(48,(unsigned char*) encHead,payloadHead);
	if (payloadHeadSize != 256){
		perror("Encrypted payload header is of invalid size");
		return -1;
	}

	unsigned char payloadData[COLLECT_BUFFER_SIZE]; /** THE YANG **/
	// encrypt the internal message data frame
	int payloadDataSize = encryptPayloadData(buffer,dataSize,encHead,payloadData);
	
	// the size of the entire message frame
	pkt->length = payloadDataSize + payloadHeadSize + SERVICE_NAME_SIZE;
	memcpy(pkt->data,payloadHead,payloadHeadSize);
	memcpy(pkt->data+payloadHeadSize,payloadData,payloadDataSize);

	if (send_all(c,pkt,pkt->length+PACKET_HEADER_SIZE) < 0){
		perror("If this doesn't work i hate everything :)");
	}

	unsigned short headbuf[2];
	if (recv_all(c,headbuf,4)<0){
		perror("Unable to received response");
	}
	
	int i = (int) headbuf[0];
	unsigned char responsebuf[i];
	
	unsigned char decryptedtext[COLLECT_BUFFER_SIZE]; // I'm sorry I have no idea why the decryptedtext needs to be so long :( but it fixes the seg fault sometimes
	int decryptedtext_size;

	switch (headbuf[1]){
		case SERVICE_COMPLETE:
			SHOW_INBOUND("SERVICE_COMPLETE",SERVICE_COMPLETE);
			if (recv_all(c,responsebuf,i) < 0){
				perror("Error reading response from analyst");
				break;
			}
 			decryptedtext_size = decryptPayload(responsebuf,i,encHead,decryptedtext);
			decryptedtext[decryptedtext_size] = '\0';

			printf("\n\n:::::::RESULT:::::::\n");
			printf("%s\n",decryptedtext);
			printf(":::::END RESULT:::::\n\n");

			if (remove(cc)==0){
				printf("The coin %s was deleted\n",cc);
			}
			break;

		case SERVICE_ERROR:
			SHOW_INBOUND("SERVICE_ERROR",SERVICE_ERROR);
			printf("There was an error in processing fulfilling the request\n");
			setBadCoin(cc);
			break;

		case SERVICE_UNAVAILABLE:
			SHOW_INBOUND("SERVICE_UNAVAILABLE",SERVICE_UNAVAILABLE);
			printf("The service is no longer available -- killing connection\n");
			walletSize++;
			return -1;

		case MALFORMED_PACKET_ERROR:
			SHOW_INBOUND("MALFORMED_PACKET_ERROR",MALFORMED_PACKET_ERROR);
			closeConnection(c);
			return -1;
		default:
			printf("Response code: %d\n",headbuf[1]);
			printf("An unknown error has occured!\n");
			closeConnection(c);
			return -1;
			break;
	}
	free(encHead);
	return 1;
}


int main(int argc, char *argv[]){

	int n = 0;
	int duration = 5;
	int loadNVMCoins = 0;
	char *buf;
	int newLength;
	char *source;
	const char prefix[] = "./socket-collector-\0";

	// http://www.codingunit.com/c-tutorial-command-line-parameter-parsing
	printf("Running: %s\n",argv[0]);
	while ((argc > 1) && (argv[1][0] == '-')){
		switch(argv[1][1]){
			case 'h':
				printf("Usage:\n");
				printf("-l (load coins from non volatile memory)\n");
				printf("-b<bank_addr>\n");
				printf("-d<director_addr>\n");
				printf("-s<service_required>\n");
				printf("-c<collection_source>\n");
				printf("-t<collection_duration_in_seconds>\n");
				printf("-n<num_of_coins_to_withdraw_from_bank>\n");
				exit(1);
			case 'b':
				printf("Set to use bank address: %s\n",&argv[1][2]);
				BANK_SERVER = strdup(&argv[1][2]);
				break;
			case 'l':
				loadNVMCoins = 1;
				break;
			case 'd':
				printf("Set to use director address: %s\n",&argv[1][2]);
				DIRECTOR_SERVER = strdup(&argv[1][2]);
				break;
			case 's':
				printf("Set to request service: %s\n",&argv[1][2]);
				SERVICE_REQUIRED = strdup(&argv[1][2]);
				break;
			case 'n':
				buf = strdup(&argv[1][2]);
				n = atoi(buf);
				printf("Set to obtain %d coins from the bank\n",n);
				break;
			case 't':
				buf = strdup(&argv[1][2]);
				duration = atoi(buf);
				printf("Set  collection duration to %d seconds\n",duration);
				break;
			case 'c':
				printf("Collector set to receive data on socket-collector-%s\n",&argv[1][2]);
				newLength = strlen(&argv[1][2])+strlen(prefix)+1;
				source = calloc(1,newLength);
				strcpy(source,prefix);
				strcat(source,&argv[1][2]);
				COLLECTOR_INTERFACE = source;
				printf("Collector set to receive data on %s\n",COLLECTOR_INTERFACE);
				break;
			default:
				printf("Your input is screwy\n");
				break;
		}
		++argv;
		--argc;
	}

	// http://stackoverflow.com/questions/298510/how-to-get-the-current-directory-in-a-c-program
	// In the name of academic honesty the getCWD bit is borrowed code
	// However, I made the decision to use it because it can
	// handle people trying to the load cwd in weird places
	if (getcwd(cwd,sizeof(cwd)) == NULL) {
		perror("getcwd() problems");
		exit(EXIT_FAILURE);
	}

	initOpenSSL();

	//wallet = malloc(sizeof(wallet));
	if (loadNVMCoins == 1){
		int coinsLoaded = readCoinsFromNonVolatileMemory();
		printf("Added %d coins from non-volatile memory\n",coinsLoaded);
	}
	
	if (n >0){ 
		printf("Attempting to withdraw credit from the bank...\n");
		getCredit(n); 
	} 
	connection *serviceProvider = NULL;	
	printf("Attempting to locate a service provider\n");
	serviceProvider = locateService(SERVICE_REQUIRED);
	unsigned char *collectBuffer;
	collectBuffer = (unsigned char*) malloc(COLLECT_BUFFER_SIZE);
	int dataSize;
	while (walletSize > 0 && serviceProvider != NULL){

		printf("Initiating data collection... [%d coins remaining]\n",walletSize);
		// collect and send data, if a critical error with the director, attempt reconnect
		dataSize = collectData(COLLECTOR_INTERFACE,duration,collectBuffer);
		if (sendData(serviceProvider,SERVICE_REQUIRED,collectBuffer,dataSize) == -1){
			serviceProvider = NULL;	
			serviceProvider = locateService(SERVICE_REQUIRED);
		}
	}
	if (serviceProvider == NULL){
		printf("Lost connection to the director\n");
	}
	if (walletSize == 0){
		printf("Out of credit\n");
 	}
	free(collectBuffer);
	closeConnection(serviceProvider);	
}
