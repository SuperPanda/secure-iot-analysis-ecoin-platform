/**
 * The BANK!
 * @author Andrew Briscoe (21332512)
 * @date 2015-05-20
 */
// import sun.security.tools.KeyStoreUtil;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.lang.Exception;
import java.lang.Integer;
import java.lang.String;
import java.lang.System;
import java.lang.reflect.Array;;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.SocketException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Random;
import java.net.Socket;
import javax.crypto.Cipher;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509KeyManager;
import java.math.BigInteger;
import java.security.MessageDigest;

public class Bank {

	public static final int WITHDRAW = 50;
	public static final int WITHDRAW_REPLY = 55;
	public static final int WITHDRAW_DISPENSE = 56;
	public static final int WITHDRAW_DISPENSE_ACK = 57;
	public static final int WITHDRAW_DONE = 58;

	public static final int DEPOSIT = 700;
	public static final int DEPOSIT_SUCCESS = 710;
	public static final int DEPOSIT_FAILURE = 720;
	public static final int DEPOSIT_INVALID_COIN = 721;

	public static final int TEST = 800;

	public static HashSet<String> ledger = new HashSet<String>();

	final int COIN_LENGTH = 256/8;
	final int COIN_IN_BYTES = 32;

	private class ConnectionHandler implements Runnable {
		Connection conn = null;
		ConnectionHandler(Connection conn){
			this.conn = conn;
		}

		public void run(){
			try {

				int messageLength = this.conn.getNextInt();
				if (messageLength < 0){
					System.out.println("Error reading message");
					throw new Exception();
				}
				int type = this.conn.getNextInt();

				switch (type){
					case WITHDRAW:
						Connection.displayIncoming("WITHDRAW",WITHDRAW);
						int amount = this.conn.getNextInt();
						System.out.println("requesting withdrawal of: " + amount);
						Coin coins[] = bundleCoins(amount);
						// Let the client know the size of the coins
						// but that's old code now
						this.conn.writeToSocket(WITHDRAW_REPLY, COIN_IN_BYTES);

						for (int i = 0; i < amount; i++) {
							Connection.displayOutgoing("WITHDRAW_DISPENSE",WITHDRAW_DISPENSE);
							this.conn.writeToSocket(WITHDRAW_DISPENSE, coins[i].getCoin());

							//System.out.println("Awaiting Ack...");

							this.conn.getInputStream().skip(2); // skip header

							int code = this.conn.getNextInt();
							if (code != WITHDRAW_DISPENSE_ACK){
								System.out.println("No Acknowledgement!");
								return;
							}
							Connection.displayIncoming("WTIHDRAW_DISPENSE_ACK",WITHDRAW_DISPENSE_ACK);
							//System.out.println("Ack received.");
							System.out.println("Adding to ledger: " + coins[i]);
							ledger.add(coins[i].toString());
						}
						Connection.displayOutgoing("WITHDRAW_DONE",WITHDRAW_DONE);
						this.conn.writeToSocket(WITHDRAW_DONE);
						break;

					case DEPOSIT:
						Connection.displayIncoming("DEPOSIT",DEPOSIT);

						// Read in raw data
						byte[] data = new byte[messageLength];
						this.conn.read(data);

						// setup an array for the coin
						byte[] coinBlob = new byte[COIN_LENGTH];


						// decrypt the coin/SK and the IV using the banks private key
						byte[] decryptedData = Bank.decrypt(data);

						// If decryption was unsuccessful
						if (decryptedData == null){
							Connection.displayOutgoing("DEPOSIT_FAILURE",DEPOSIT_FAILURE);
							this.conn.writeToSocket(DEPOSIT_FAILURE);
							return;
						}

						// copy the coin component of the decrypted data
						// to its rightful place
						System.arraycopy(decryptedData, 0, coinBlob, 0, COIN_LENGTH);
						String coin = new Coin(coinBlob).toString();

						// Check that the coin is in circulation
						if (ledger.contains(coin)){
							System.out.println("VALID COIN: " + coin);

							// Remove from circulation
							ledger.remove(coin);

							byte[] header = new byte[48]; // 32 bit SYMMETRIC KEY, 16 bit coin

							// copy the relevant decrypted data bytes to send back to
							// the analyst
							System.arraycopy(decryptedData, 0, header, 0, 48);
							Connection.displayOutgoing("DEPOSIT_SUCCESS",DEPOSIT_SUCCESS);
							this.conn.writeToSocket(DEPOSIT_SUCCESS,header);
						} else { // The coin is not in circulation

							// Inform the analyst the coin was invalid
							Connection.displayOutgoing("DEPOSIT_INVALID_COIN",DEPOSIT_INVALID_COIN);
							this.conn.writeToSocket(DEPOSIT_INVALID_COIN);
							System.out.println(coin);

						}
						break;
					case TEST:
						System.out.println("Test!");
						break;
					default:
						break;
				}

			} catch (Exception e){
				e.printStackTrace();
			} finally {
				this.conn.closeSocket();
				System.out.println("Disconnected");
			}
		}
	}

	Random r = new Random();

	/**
	 * https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
	 * @param ciphertext The data to be decrypted
	 * @param key The key to use to perform the decryption
	 * @return the value
	 */
	public static byte[] decrypt(byte[] ciphertext){

		byte[] decryptedtext = null;
		try {
			KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			keystore.load(new FileInputStream("bank.keystore"), "changeit".toCharArray());
			PrivateKey key = (PrivateKey) keystore.getKey("bank-certificate","changeit".toCharArray());
			final Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE,key);
			decryptedtext = cipher.doFinal(ciphertext);
		} catch (Exception e){
			e.printStackTrace();
		}
		return decryptedtext;
	}

	/**
	 * Being a coin... and stuff
	 */
	private class Coin{

		// this is where the random bytes go
		private byte[] serial = new byte[COIN_LENGTH];

		public Coin(byte[] value){
			System.arraycopy(value,0,this.serial,0,COIN_LENGTH);
		}
		public Coin(){
			r.nextBytes(serial);
		}
		public byte[] getCoin(){
			return serial;
		}

		@Override
		public String toString(){
			String out = "";
			// Format bytes as hex values

			try {
				MessageDigest md = MessageDigest.getInstance("MD5");
				md.reset();
				md.update(this.serial);
				return new BigInteger(1,md.digest()).toString(16);
			} catch (NoSuchAlgorithmException ignored) {

			}

			/**
			 * Backup representation.
			 * Works just the same.
			 */
			int i = 0;
			for (byte c : this.serial) {
				out += String.format("%02x",c) + " ";
				i = (i+1)%8;
				if (i == 0) {
					out += "\n";
				}
			}
			return out;
		}
	}

	/**
	 * Get a lot of coins at once :)
	 * @param numCoins the number of coins
	 * @return an array of Coin's (Coin[])
	 */
	private Coin[] bundleCoins(int numCoins){
		Coin coins[] = new Coin[numCoins];
		for (int i=0; i<numCoins; i++){
			coins[i] = new Coin();
		}
		return coins;
	}


	/**
 	* Server stuff
 	* Attributions to the lecture slides and Beejs Guide to networking
 	*/
	int myport = 29991;
	SSLServerSocket sock = null;
	SSLSocket newconn = null;

	public void startServer(){
		SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		try {

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

			sock = (SSLServerSocket) sslServerSocketFactory.createServerSocket(myport,20);

			// This ensures the connection is from a pre-approved party
			sock.setNeedClientAuth(true);

		} catch (Exception e){
			e.printStackTrace();
			System.out.println("$H1T!");
			return;
		} finally {

		}
		while(true){ runServer(); }
	}

	public void runServer(){
			try {
				newconn = (SSLSocket) sock.accept();
				System.out.println("Incoming connection from: " + newconn.getInetAddress() + ":" + newconn.getPort());
				new Thread(new ConnectionHandler(new Connection(newconn))).start();
			} catch (IOException e){
				System.out.println("IOException!");
				System.out.println(e);
			}

	}

	/**
	 * Only accept connections with certificates issued by the bank :)
	 * Sort of like a unique ID in your credit card so the bank knows who you are
	 * But then the merchant is also issued some ID
	 * @param args
	 */
	public static void main(String[] args){
		String keyStoreDirectory = System.getProperty("user.dir");
		String keyStoreFile = "bank.keystore";
		String keyStoreFilename = keyStoreDirectory + "/" + keyStoreFile;
		System.setProperty("javax.net.ssl.keyStore",keyStoreFilename);
		System.setProperty("javax.net.ssl.trustStore",keyStoreFilename);
		System.setProperty("javax.net.ssl.keyStorePassword","changeit");
		System.setProperty("javax.net.ssl.trustStorePassword","changeit");
		//System.setProperty("javax.net.debug","all");
		Bank bank = new Bank();
		bank.startServer();
	
	}
}
