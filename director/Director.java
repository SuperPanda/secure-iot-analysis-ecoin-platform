/**
 * The director of 'not-yet-implemented' malevolent deeds, the rest is implemented though
 * @author Andrew Briscoe (21332512)
 * @date 2015-05-20
 */
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.Exception;
import java.lang.IllegalStateException;
import java.lang.Runnable;
import java.lang.String;
import java.lang.System;
import java.lang.Thread;
import java.lang.reflect.Array;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.HashMap;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;


public class Director {

    public final int REGISTER = 100;
    public final int REGISTER_SUCCESS = 101;
    public final int REGISTER_ERROR = 102;
    public final int POLL = 200;
    public final int POLL_ACK = 201;
    public final int SERVICE_REQ = 300;
    public final int SERVICE_READY = 301;
    public final int SERVICE_UNAVAILABLE = 302;
    public final int SERVICE_OPERATION = 350;
    public final int SERVICE_COMPLETE = 360;
    public final int SERVICE_ERROR = 370;
    public final int TEST = 800;
    public final int TEST_SHOW_PROVIDERS = 801;
    public final int ERROR = 900;
    public final int ERROR_UNKNOWN_PACKET_TYPE = 910;


    /**
     * The phonebook of service providers
     */
    public static ServiceDirectory serviceDirectory;

    // Maps CollectorConnection to AnalystConnection
    public static HashMap<Connection,Connection> activeLinks = new HashMap<Connection,Connection>();

    public Director(){
        this.serviceDirectory = new ServiceDirectory();
    }

    /**
     * The phonebook class
     */
    private class ServiceDirectory{

        // A mapping between the service and the supposedly available providers
        HashMap<String,LinkedList<Connection>> serviceProviders = new HashMap<String,LinkedList<Connection>>();

        // Add a connection to the phonebook
        public void registerProvider(String service, Connection c) throws IllegalStateException{

            // if there isn't a service listing, add one
            if (!serviceProviders.containsKey(service)){
                System.out.println("Creating new service: " + service);
                serviceProviders.put(service,new LinkedList<Connection>());
            }
            // if the service provider is already in the list, get upset
            if (serviceProviders.get(service).contains(c)) throw new IllegalStateException();

            System.out.println("Adding connection to service directory");
            serviceProviders.get(service).add(c);
        }

        public boolean hasService(String service){
            return this.serviceProviders.containsKey(service);
        }

        /**
         * Checks for closed connections in the service directory and removes them accordingly
         * If there are no more service providers the service is removed from the serviceDirectory
         * @param service A string that represents the services to be polled
         */
        public Connection pollConnections(String service) throws SocketException, IOException{
            System.out.println("Searching for service: " + service);
            if (!this.serviceProviders.containsKey(service)) return null;
            int i = 0;
            while (this.serviceProviders.get(service).size()>i) {
                Connection c = this.serviceProviders.get(service).get(i);
                try {
                    // If active link go to next
                    if (!Director.activeLinks.containsKey(c) && c.poll()) {
                        return c;
                    } else {
                        i++;
                    }
                } catch (SocketException e){
                    this.serviceProviders.get(service).remove(i);
                    c.closeSocket();
                }
            }
            if(this.serviceProviders.get(service).size() == 0) {
                this.serviceProviders.remove(service);
            }
            return null;
        }


        @Override
        public String toString(){
            String out = "";
            for (String e : serviceProviders.keySet()){
                out += "\nService: ";
                out += e;
                int i = 0;
                for (Connection s : serviceProviders.get(e)) {
                    out += "\nProvider ("+ ++i +"): ";
                    out += s;

                }
            }
            return out;
        }
    }


    /**
     * When a connection needs to be serviced or listened to let this handle it
     */
    private class ConnectionHandler implements Runnable {

        // Determines if the connection should keep listening
        private boolean running;

        // The connection being handled
        Connection conn = null;

        public ConnectionHandler(Connection conn) throws IOException{
            this.conn = conn;
        }

        public void listen() throws IOException{

            String serviceName;
            int messageLength = this.conn.getNextInt();
            if (messageLength == -1){
                System.out.println("Remote host has disconnected");
                if (Director.activeLinks.containsKey(this.conn)){
                    Connection.displayOutgoing("SERVICE_UNAVAILABLE",SERVICE_UNAVAILABLE);
                    Director.activeLinks.get(this.conn).writeToSocket(SERVICE_UNAVAILABLE);
                    Director.activeLinks.remove(this.conn);
                }
                running = false;
                return;
            }
            int type = this.conn.getNextInt();
            if (type == -1){
                System.out.println("Remote host has disconnected");
            }

            char buffer[];
            switch (type) {
                case 0:
                    running = false;
                    System.out.println(this.conn);
                    System.out.println("Connection closed");
                    break;
                case REGISTER:
                    Connection.displayIncoming("REGISTER",REGISTER,messageLength);
                    buffer = new char[messageLength];
                    for (int i = 0; i<messageLength;i++){
                        buffer[i] = (char) this.conn.getNextByte();
                        //System.out.println("Char %c: " + buffer[i]);
                    }

                    serviceName = new String(buffer);
                    System.out.println("Registering: " + this.conn);
                    System.out.println("Service: " + serviceName);

                    //Notify that it has been registered before actually
                    // adding to register to prevent deadlock
                    Connection.displayOutgoing("REGISTER_SUCCESS",REGISTER_SUCCESS);
                    this.conn.writeToSocket(REGISTER_SUCCESS);
                    try {
                        Director.serviceDirectory.registerProvider(serviceName, this.conn);
                        //System.out.println(new String(buffer));
                    } catch (IllegalStateException e){
                        running=false;
                        Connection.displayOutgoing("REGISTER_ERROR",REGISTER_ERROR);
                        this.conn.writeToSocket(REGISTER_ERROR);
                    }
                    running = false;
                    break;

                case TEST_SHOW_PROVIDERS:
                    Director.serviceDirectory.toString();
                    break;
                case SERVICE_REQ:
                    Connection.displayIncoming("SERVICE_REQ",SERVICE_REQ);
                    buffer = new char[messageLength];
                    String str = this.conn.read(buffer);
                    System.out.println("Service requested: " + str + " (length: " + str.length()+")");
                    //System.out.println();
                    if (Director.serviceDirectory.hasService(str) && Director.serviceDirectory.pollConnections(str) != null){
                        Connection.displayOutgoing("SERVICE_READY",SERVICE_READY);
                        this.conn.writeToSocket(SERVICE_READY);
                    } else {
                        running = false;
                        Connection.displayOutgoing("SERVICE_UNAVAILAABLE",SERVICE_UNAVAILABLE);
                        this.conn.writeToSocket(SERVICE_UNAVAILABLE);
                    }
                    break;

                case SERVICE_OPERATION:
                    //c.getInputBuffer();
                    Connection.displayIncoming("SERVICE_OPERATION",SERVICE_OPERATION,messageLength);
                    byte[] data = new byte[messageLength];
                    this.conn.read(data);
                    // Get the service name
                    byte[] b = new byte[32];
                    System.arraycopy(data,0,b,0,32);
                    serviceName = SocketUtil.byteToString(b);
                    Connection c = Director.serviceDirectory.pollConnections(serviceName);
                    if (c == null) {
                        Connection.displayOutgoing("SERVICE_UNAVAILABLE",SERVICE_UNAVAILABLE);
                        this.conn.writeToSocket(SERVICE_UNAVAILABLE);
                        break;
                    }
                    Director.activeLinks.put(c, this.conn);
                    Connection.displayOutgoing("SERVICE_OPERATION",SERVICE_OPERATION,messageLength);
                    c.writeToSocket(SERVICE_OPERATION, data);
                    new Thread(new ConnectionHandler(c)).run(); // turn the listen handle for the service provider back on
                    break;
                case SERVICE_COMPLETE:
                    Connection.displayIncoming("SERVICE_COMPLETE", SERVICE_COMPLETE, messageLength);
                    byte[] response = new byte[messageLength];
                    this.conn.read(response);
                    Connection.displayOutgoing("SERVICE_COMPLETE", SERVICE_COMPLETE, messageLength);
                    Director.activeLinks.get(this.conn).writeToSocket(type, response);
                    Director.activeLinks.remove(this.conn);
                    running = false;
                    break;
                case SERVICE_ERROR:
                    Connection.displayIncoming("SERVICE_ERROR",SERVICE_ERROR);
                    Connection.displayOutgoing("SERVICE_ERROR", SERVICE_ERROR);
                    Director.activeLinks.get(this.conn).writeToSocket(type);
                    // Removing active link
                    Director.activeLinks.remove(this.conn);
                    running = false;
                    break;
                case POLL:
                    Connection.displayIncoming("POLL", POLL);
                    Connection.displayOutgoing("POLL_ACK", POLL_ACK);
                    this.conn.writeToSocket(POLL_ACK);
                    break;
                case POLL_ACK:
                    Connection.displayIncoming("POLL_ACK", POLL_ACK);
                    break;
                default:
                    running = false;
                    if (Director.activeLinks.containsKey(this.conn)){
                        Connection.displayOutgoing("SERVICE_UNAVAILABLE",SERVICE_UNAVAILABLE);
                        Director.activeLinks.get(this.conn).writeToSocket(SERVICE_UNAVAILABLE);
                        Director.activeLinks.remove(this.conn);
                    }
                    Connection.displayOutgoing("ERROR_UNKNOWN_PACKET_TYPE",ERROR_UNKNOWN_PACKET_TYPE);
                    this.conn.writeToSocket(ERROR_UNKNOWN_PACKET_TYPE);
                    System.out.println("Unrecognised format");
                    break;
            }


        }

        public void run(){
            running = true;
            try {
                while(running) {
                    listen();
                }
            } catch (Exception e){
                System.out.println("All the exceptions");
                System.out.println(e);
            }
            //System.out.println("Probably stopped running here");
        }
    }

    int myport = 29992;
    SSLServerSocket sock = null;
    SSLSocket newconn = null;

    public void startServer(){
        SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        try {
            sock = (SSLServerSocket) sslServerSocketFactory.createServerSocket(myport);

            /**
             * http://www.java2s.com/Tutorial/Java/0320__Network/GetIPaddressfromNetworkInterfaceandcreateserversocket.htm
             */
            Enumeration<NetworkInterface> e = NetworkInterface.getNetworkInterfaces();
            if (!e.hasMoreElements())
                throw new Exception("No Network Interfaces");
            while (e.hasMoreElements()) {
                Enumeration<InetAddress> iae = e.nextElement().getInetAddresses();
                while (iae.hasMoreElements()) {
                    System.out.println("Listening to: " + iae.nextElement().getHostAddress() + " ["+myport+"]");
                }
            }

        } catch (Exception e){
            e.printStackTrace();
            return;
        } finally {

        }


        while(true){ runServer(); }
    }

    public void runServer(){
        try {
            newconn = (SSLSocket) sock.accept();
            System.out.println("Incoming connection from: " + newconn.getInetAddress().getHostAddress() + ":" + newconn.getPort());
            new Thread(new ConnectionHandler(new Connection(newconn))).start();
        } catch (IOException e){
            e.printStackTrace();
        }

    }


    public static void main(String[] args) {
        String keyStoreDirectory = System.getProperty("user.dir");
        String keyStoreFile = "director.keystore";
        String trustFilename = keyStoreDirectory + "/" + keyStoreFile;
        System.setProperty("javax.net.ssl.keyStore",trustFilename);
        System.setProperty("javax.net.ssl.keyStorePassword","changeit");
        //System.setProperty("javax.net.debug","all");
        Director director = new Director();
        director.startServer();
    }

}