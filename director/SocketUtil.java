/**
 * A useful socket utility class to ensure a common language between applications
 * @author Andrew Briscoe (21332512)
 * @date 2015-05-20
 */
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.lang.Byte;
import java.net.Inet4Address;
import java.net.Socket;
import java.net.SocketException;

public class SocketUtil {

    public static String byteToString(byte[] service) {
        int count = 0;
        String serviceName = "";
        while (count < service.length && service[count] != '\0') {
            //System.out.println("%c: " + service[count]);
            serviceName += (char) service[count];
            count++;
        }
        return serviceName;
    }

    public static void writeInt(DataOutputStream out, int i) throws IOException {
        byte[] b = new byte[2];
        b[0] = (byte) (i % 256);
        //System.out.println("Writing int: " + i);
        b[1] = (byte) (i / 256);
        out.write(b);
        out.flush();
    }


    public static int readInt(InputStream istream) throws IOException {
        byte[] b = new byte[2];
        int out = 0;
        DataInputStream dis = new DataInputStream(istream);
        b[0] = dis.readByte();
        b[1] = dis.readByte();
        out += ((int) b[0] > 0) ? (int) b[0] : (int) (b[0] & 0xff);
        out += ((int) b[1] > 0) ? (int) b[1] * 256 : (int) (b[1] & 0xff) * 256;

        //System.out.println("Received an int: " + out);
        return out;
    }

    public static void displayAllTheBytes(byte[] in) {

        String out = "";
        int i = 0;
        for(
        byte c : in)
        {
            out += String.format("%02x", c) + " ";
            i = (i + 1) % 8;
            if (i == 0) {
                out += "\n";
            }
        }
        System.out.println(out);
    }

    public static void writeToSocket(OutputStream ostream, int type, char[] text) throws IOException {
        //System.out.println("Writing: [" + type + "] " + String.valueOf(text));
            DataOutputStream dos = new DataOutputStream(ostream);
            writeInt(dos, text.length);
            writeInt(dos, type);
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(ostream));
            out.write(text);
            out.flush();
            dos.flush();
    }

    public static void writeToSocket(OutputStream ostream, int type, byte[] data) throws IOException {
        //System.out.println("Writing byte stream [" + type + "] of size " + data.length);
        DataOutputStream dos = new DataOutputStream(ostream);
        writeInt(dos, data.length);
        writeInt(dos, type);
        dos.write(data);
    }

    public static void writeToSocket(OutputStream ostream, int type, char[] text, byte[] data) throws IOException {
        //System.out.println("Writing byte stream [" + type + "] of size " + data.length);
        DataOutputStream dos = new DataOutputStream(ostream);
        writeInt(dos, data.length);
        writeInt(dos, type);
        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(ostream));
        out.write(text);
        dos.write(data);
    }

    public static void writeToSocket(OutputStream ostream, int type, int value) throws IOException{
        //System.out.println("Writing: [" + type + "] "+value);
        DataOutputStream out = new DataOutputStream(ostream);
        writeInt(out,0);
        writeInt(out, type);
        writeInt(out, value);
        out.flush();
    }

    public static void writeToSocket(OutputStream ostream, int type) throws IOException {
            //System.out.println("Writing: [" + type + "] ");
            DataOutputStream dos = new DataOutputStream(ostream);
            writeInt(dos, 0);
            writeInt(dos, type);
            dos.flush();
    }
}