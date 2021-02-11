/**
 * Author: Andrew Briscoe (21332512)
 * Date: 2015-05-20
 *
 * An analyst program must implement the interface IAnalyser which has two methods
 *  - byte[] analyse(byte[] in);
 *  - String getServiceName();
 *
 *  The main method should be similar to the following:
 *      IAnalyser analyser = new CustomAnalyser();
 *      Analyst.initArgs(args);
 *      Analyst analyst = new Analyst(analyser);
 *      analyst.startService();
 *
 */

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.IllegalStateException;
import java.lang.Integer;
import java.lang.Runnable;
import java.lang.System;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

public class Analyst {

    public final int REGISTER = 100;
    public final int REGISTER_SUCCESS = 101;
    public final int REGISTER_ERROR = 102;
    public final int POLL = 200;
    public final int POLL_ACK = 201;
    public final int SERVICE_OPERATION = 350;
    public final int SERVICE_COMPLETE = 360;
    public final int SERVICE_ERROR = 370;
    public final int TEST = 800;
    public final int ERROR = 900;
    public final int ERROR_UNKNOWN_PACKET_TYPE = 910;

    public static final int DEPOSIT = 700;
    public static final int DEPOSIT_SUCCESS = 710;
    public static final int DEPOSIT_FAILURE = 720;
    public static final int DEPOSIT_INVALID_COIN = 721;

    private String service = null;
    private Connection directorConnection = null;
    private Connection bankConnection = null;

    private IAnalyser anaylser = null;


    public static String bankAddr = "127.0.0.1";
    public static int bankPort = 29991;
    public static String directorAddr = "127.0.0.1";
    public static int directorPort = 29992;

    private InputStream istream;

    public Analyst(String service){
        initKeyStore();
        this.service = service;
    }

    public Analyst(IAnalyser analyser){
        initKeyStore();
        this.anaylser = analyser;
        this.service = analyser.getServiceName();
    }

    private static TrustManager trustEveryone = new X509TrustManager(){
        public X509Certificate[] getAcceptedIssuers(){
            return null;
        }
        public void checkClientTrusted(X509Certificate[] certs, String authType){

        }
        public void checkServerTrusted(X509Certificate[] certs, String authType){

        }
    };
    public String getServiceName(){
        return this.service;
    }
    public byte[] deposit(byte[] payload){
        byte[] header = null;
        try {
            SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket sock = (SSLSocket) sslSocketFactory.createSocket(Analyst.bankAddr,Analyst.bankPort);
            this.bankConnection = new Connection(sock);
            Connection.displayOutgoing("DEPOSIT",DEPOSIT);
            this.bankConnection.writeToSocket(DEPOSIT,payload);
            int msgLength = this.bankConnection.getNextInt();
            int responseCode = this.bankConnection.getNextInt();
            if (responseCode == DEPOSIT_FAILURE){
                Connection.displayIncoming("DEPOSIT_FAILURE",DEPOSIT_FAILURE);
                System.out.println("Malformed packet");
                return null;
            } else if (responseCode == DEPOSIT_INVALID_COIN){
                Connection.displayIncoming("DEPOSIT_INVALID_COIN", DEPOSIT_INVALID_COIN);
                System.out.println("The coin was invalid");
                return null;
            } else if (responseCode == DEPOSIT_SUCCESS){
                header = new byte[48];
                Connection.displayIncoming("DEPOSIT_SUCCESS", DEPOSIT_SUCCESS, msgLength);
                this.bankConnection.read(header);
                return header;
            }
            this.bankConnection.closeSocket();
        } catch (IOException e ){
            System.out.println("Great sadness from the bank");
            e.printStackTrace();
        }
        return header;
    }

    public byte[] packageReponse(byte[] in, byte[] symmetricKey, byte[] iv){
        byte[] out = null;
        try {
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(symmetricKey, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            c.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            out = c.doFinal(in);
        } catch (Exception e){
            e.printStackTrace();
        }
        return out;
    }

    public byte[] unpackageRequest(byte[] in, byte[] symmetricKey, byte[] iv){
        byte[] out = null;
        try {
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(symmetricKey, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            c.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            out = c.doFinal(in);
        } catch (Exception e){
            e.printStackTrace();
        }
        return out;
    }

    public boolean register(String address, int port) throws IOException{

            if (this.directorConnection == null){
                this.directorConnection = new Connection();
            }

            System.out.println("Registering Analyst");

            try {
                SSLContext sslContext = SSLContext.getInstance("SSL");
                sslContext.init(null, new TrustManager[]{trustEveryone}, null);
                this.directorConnection.connect(address, port, sslContext);
                Connection.displayOutgoing("REGISTER",REGISTER);
                this.directorConnection.writeToSocket(REGISTER, this.service.toCharArray());
            } catch (IllegalStateException e){
                System.out.println("Unable to establish a connection with the server.");
                return false;
            } catch (NoSuchAlgorithmException e){
                System.out.println("No such algorithm exception");
                e.printStackTrace();
                return false;
            } catch (KeyManagementException e){
                System.out.println("Key management exception");
                e.printStackTrace();
                return false;
            }

            int msgLength = this.directorConnection.getNextInt();
            int msgType = this.directorConnection.getNextInt();
            if (msgType == REGISTER_SUCCESS){
                Connection.displayIncoming("REGISTER_SUCCESS", REGISTER_SUCCESS);
                System.out.println("Registered as a service provider for: " + getServiceName());
                return true;
            }
            System.out.println("REGISTRATION FAILED");

            return false;
    }

    /* Change to poll for director */
     public void startService(){

         try {
             if (!register(Analyst.directorAddr,Analyst.directorPort)) return;

             BufferedReader in = this.directorConnection.getBufferedReader();
             int msgSize;

             boolean run = true;
             while (run) {

                 msgSize = this.directorConnection.getNextInt();
                 int msgType = this.directorConnection.getNextInt();

                 switch (msgType){

                     case TEST:
                         char c[] = new char[msgSize];
                         in.read(c);
                         System.out.println(c);
                         break;

                     case POLL:
                         Connection.displayIncoming("POLL",POLL);
                         Connection.displayOutgoing("POLL_ACK",POLL_ACK);
                         this.directorConnection.writeToSocket(POLL_ACK);
                         break;

                     case ERROR_UNKNOWN_PACKET_TYPE:
                         //run = false;
                         Connection.displayIncoming("ERROR_UNKNOWN_PACKET_TYPE", ERROR_UNKNOWN_PACKET_TYPE);
                         break;

                     case SERVICE_OPERATION:
                         Connection.displayIncoming("SERVICE_OPERATION",SERVICE_OPERATION,msgSize);

                         // Check if this is the valid service
                         byte[] withLove_theCollector = new byte[msgSize];
                         this.directorConnection.read(withLove_theCollector);
                         byte[] serviceReq = new byte[16];
                         byte[] payloadHeader = new byte[256];
                         byte[] payloadData = new byte[msgSize - 16 - 256];

                         // This is the service requested
                         System.arraycopy(withLove_theCollector, 0, serviceReq, 0, 16);

                         // This is the header encrypted with the public key of the bank
                         System.arraycopy(withLove_theCollector, 16, payloadHeader, 0, 256);

                         // This is the data encrypted with the symmetric key that
                         // will be returned by the bank
                         System.arraycopy(withLove_theCollector, 16 + 256, payloadData, 0, msgSize - 16 - 256);

                         byte[] header = deposit(payloadHeader);
                         if (header == null){
                             Connection.displayOutgoing("SERVICE_ERROR",SERVICE_ERROR);
                             this.directorConnection.writeToSocket(SERVICE_ERROR);
                         } else {

                             byte[] sk = new byte[32];
                             byte[] iv = new byte[16];
                             System.arraycopy(header,0,sk,0,32);
                             System.arraycopy(header, 32, iv, 0, 16);

                             byte[] msg;

                             if (this.anaylser == null) {
                                 msg = "Result: I love it when a plan comes together".getBytes("UTF-8");
                             } else {
                                 byte[] requestData = unpackageRequest(payloadData,sk,iv);
                                 msg = this.anaylser.analyse(requestData);
                             }
                             byte[] msgin = new byte[64];
                             System.arraycopy(msg,0,msgin,0,msg.length);
                             byte[] output = packageReponse(msgin,sk,iv);
                             if (output == null){
                                 System.out.println("Error generating encrypted payload for the collector");
                                 Connection.displayOutgoing("SERVICE_ERROR", SERVICE_ERROR);
                                 this.directorConnection.writeToSocket(SERVICE_ERROR);
                                 break;
                             }
                             Connection.displayOutgoing("SERVICE_COMPLETE",SERVICE_COMPLETE,output.length);
                             this.directorConnection.writeToSocket(SERVICE_COMPLETE,output);
                         }

                         break;
                     default:
                         // Run a poll and exit if fails
                         System.out.println("Unknown Code, polling");
                         if (!this.directorConnection.poll()){
                             run = false;
                             throw new SocketTimeoutException();
                         }

                 }
             }

         } catch (SocketTimeoutException e){
             System.out.println("Closing connection due to unresponsive director.");
             this.directorConnection.closeSocket();
         } catch (IOException e){
             System.out.println("Connection to director lost, shutting down");
             e.printStackTrace();
         }
    }

    public static void initKeyStore(){
        //System.setProperty("javax.net.debug","all");
        String trustStoreDirectory = System.getProperty("user.dir")+"/truststore";
        String trustStoreFile = "truststore.jks";
        String trustFilename = trustStoreDirectory + "/" + trustStoreFile;

        String keyStoreDirectory = System.getProperty("user.dir")+"/private";
        String keyStoreFile = "keystore.jks";
        String keyFilename = keyStoreDirectory + "/" + keyStoreFile;

        System.setProperty("javax.net.ssl.trustStore",trustFilename);
        System.setProperty("javax.net.ssl.trustStorePassword","changeit");
        System.setProperty("javax.net.ssl.keyStore",keyFilename);
        System.setProperty("javax.net.ssl.keyStorePassword","changeit");
    }

    public static void initArgs(String[] args){
        if (args.length>=4){
            Analyst.bankAddr = args[0];
            Analyst.bankPort = Integer.valueOf(args[1]);
            Analyst.directorAddr = args[2];
            Analyst.directorPort = Integer.valueOf(args[3]);
        }
    }

    public static void main(String[] args) {
        initArgs(args);
        Analyst analyst = new Analyst("Test");
        analyst.startService();
    }

}