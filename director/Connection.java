/**
 * The connection class that encapsulates the socket :) I like sockets.
 * @author Andrew Briscoe (21332512)
 * @date 2015-05-20
 */

import java.io.BufferedReader;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.Byte;
import java.lang.IllegalStateException;
import java.lang.String;
import java.lang.System;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class Connection {

    public final int POLL = 200;
    public final int POLL_ACK = 201;


    protected SSLSocket sock;
    protected InputStream istream;
    protected OutputStream ostream;
    protected BufferedReader bufferedReader;

    public static void displayIncoming(String msg, int code){
        System.out.println("Receiving message " + msg + " [" +code+"]");
    }
    public static void displayIncoming(String msg, int code, int size){
        System.out.println("Receiving message " + msg + " [" +code+"] of size: " + size);
    }
    public static void displayOutgoing(String msg, int code){
        System.out.println("Sending message " + msg + " [" +code+"]");
    }
    public static void displayOutgoing(String msg, int code, int size){
        System.out.println("Sending message " + msg + " [" +code+"] of size: " + size);
    }

    public Connection(SSLSocket socket){
        this.sock = socket;
        try {
            istream = this.sock.getInputStream();
            ostream = this.sock.getOutputStream();
            bufferedReader = new BufferedReader(new InputStreamReader(istream));
        } catch (IOException e){
            System.out.println("Error establishing input and output streams");
            e.printStackTrace();
        }
    }

    public Connection(){
        this.sock =  null;
        this.istream = null;
        this.ostream = null;
    }

    public void connect(String host, int port, SSLContext sslContext){
        try {
            SSLSocketFactory sslSocketFactory=(SSLSocketFactory) sslContext.getSocketFactory();
            this.sock = (SSLSocket) sslSocketFactory.createSocket(host,port);
            this.istream = this.sock.getInputStream();
            this.ostream = this.sock.getOutputStream();
            this.bufferedReader = new BufferedReader(new InputStreamReader(istream));
        } catch (IOException e){
            System.out.println("Error establishing input and output streams while connecting");
            System.out.println(e);
        }
    }


    @Override
    public String toString(){
        return this.sock.getInetAddress().getHostAddress()+":"+this.sock.getPort();
    }

    public void writeToSocket(int type, char[] text){
        if (this.ostream == null) throw new IllegalStateException();
        try {
            SocketUtil.writeToSocket(this.ostream, type, text);
        } catch (IOException e){
            System.out.println("Error writing to socket");
            e.printStackTrace();
        }
    }

    public void writeToSocket(int type, byte[] data){
        if (this.ostream == null) throw new IllegalStateException();
        try {
            SocketUtil.writeToSocket(this.ostream, type, data);
        } catch (IOException e){
            System.out.println("Error writing to socket");
            e.printStackTrace();
        }
    }

    public void writeToSocket(int type, char[] text, byte[] data){
        if (this.ostream == null) throw new IllegalStateException();
        try {
            SocketUtil.writeToSocket(this.ostream, type, text, data);
        } catch (IOException e){
            System.out.println("Error writing to socket");
            e.printStackTrace();
        }
    }

    public void writeToSocket(int type, int value){
        try {
            SocketUtil.writeToSocket(this.ostream,type,value);
        } catch (IOException e){
            System.out.println("Error writing value to socket");
            e.printStackTrace();
        }

    }

    public void writeToSocket(int type){
        if (this.ostream == null) throw new IllegalStateException();
        try {
            SocketUtil.writeToSocket(this.ostream,type);
        } catch (IOException e){
            System.out.println("Error writing to socket");
            e.printStackTrace();
        }
    }

    public InputStream getInputStream(){
        return this.istream;
    }

    public BufferedReader getBufferedReader(){
          return this.bufferedReader;
    }

    public void flushOutbound(){
        try {
            this.ostream.flush();
        } catch (IOException e){
            System.out.println("It's all clogged up, unable to flush outbound");
            e.printStackTrace();
        }
    }

    public int getNextInt() throws SocketTimeoutException{
        try {
            int n = SocketUtil.readInt(this.istream);
            return n;
        } catch (IOException e){
            System.out.println("Unable to retrieve next integer");
            e.printStackTrace();
            return -1;
        }
    }
    public byte getNextByte(){
        try {
            return new DataInputStream(this.istream).readByte();
        } catch (IOException e){
            System.out.println("Unable to retrieve next byte");
            e.printStackTrace();
            return '\0';
        }
    }
    public String read(char[] buffer){
        try {
            getBufferedReader().read(buffer);
        } catch (IOException e){
            System.out.println("Parsing Error");
            return null;
        }
        char[] out = new char[buffer.length/2];
        for (int i = 0; i<out.length;i++){
            out[i] = buffer[i*2+1];
        }
        return String.valueOf(out);
    }

    public int read(byte[] buffer){
        int count = 0;
        try {
            DataInputStream dis = new DataInputStream(this.istream);
            for (int i = 0; i<buffer.length;i++){
                buffer[i] = dis.readByte();
                count++;
            }

        } catch (IOException e){
            System.out.println("Error reading data stream");
        }
        return count;
    }

    public boolean poll() throws SocketException{
        try {
            this.sock.setSoTimeout(5000);
            System.out.println("POLLING");
            this.writeToSocket(POLL);
            int msgLength = this.getNextInt();
            int msgType = this.getNextInt();
            if (msgType == POLL_ACK){
                System.out.println("POLL ACK RECEIVED");
                this.sock.setSoTimeout(0);
                return true;
            }

        } catch (SocketTimeoutException e){
            System.out.println("Socket timeout");
            return false;
        } catch (IOException e) {
            System.out.println("Unable to poll connection");
            throw new SocketException();
        }

        System.out.println("Invalid Poll Acknowledgement packet");
        return false;
    }

    public void closeSocket(){
        try {
            if (this.ostream!=null) this.ostream.close();
            if (this.istream!=null) this.istream.close();
            if (this.sock.isConnected()) this.sock.close();
        } catch (IOException e){
            System.out.println("Error closing socket");
            e.printStackTrace();
        }
    }

}
