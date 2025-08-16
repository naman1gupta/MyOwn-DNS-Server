import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;

public class Main {
  public static void main(String[] args){
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    System.out.println("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    try(DatagramSocket serverSocket = new DatagramSocket(2053)) {
      while(true) {
        final byte[] buf = new byte[512];
        final DatagramPacket packet = new DatagramPacket(buf, buf.length);
        serverSocket.receive(packet);
        System.out.println("Received data");

        // Build DNS response with header + question section
        // Domain name: \x0ccodecrafters\x02io\x00 = 12 + 2 + 1 = 15 bytes
        // Type: 2 bytes, Class: 2 bytes
        // Total question section: 19 bytes
        final byte[] response = new byte[12 + 19]; // 12 byte header + 19 byte question
        
        // Header section (12 bytes)
        // Transaction ID: 1234 (0x04D2)
        response[0] = 0x04;
        response[1] = (byte) 0xD2;
        // Flags: QR=1 (response), all others 0 => 0x8000
        response[2] = (byte) 0x80;
        response[3] = 0x00;
        // QDCOUNT: 1 question
        response[4] = 0x00;
        response[5] = 0x01;
        // ANCOUNT, NSCOUNT, ARCOUNT are already 0 by default

        // Question section (19 bytes)
        int offset = 12;
        // Domain name: codecrafters.io encoded as labels
        // \x0ccodecrafters
        response[offset++] = 0x0c; // length of "codecrafters"
        byte[] codecrafters = "codecrafters".getBytes();
        System.arraycopy(codecrafters, 0, response, offset, codecrafters.length);
        offset += codecrafters.length;
        
        // \x02io
        response[offset++] = 0x02; // length of "io"
        byte[] io = "io".getBytes();
        System.arraycopy(io, 0, response, offset, io.length);
        offset += io.length;
        
        // Null terminator
        response[offset++] = 0x00;
        
        // Type: 1 (A record) - 2 bytes big-endian
        response[offset++] = 0x00;
        response[offset++] = 0x01;
        
        // Class: 1 (IN) - 2 bytes big-endian
        response[offset++] = 0x00;
        response[offset++] = 0x01;

        final DatagramPacket packetResponse = new DatagramPacket(response, response.length, packet.getSocketAddress());
        serverSocket.send(packetResponse);
      }
    } catch (IOException e) {
        System.out.println("IOException: " + e.getMessage());
    }
  }
}
