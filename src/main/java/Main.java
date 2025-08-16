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

        // Build a 12-byte DNS header response
        final byte[] response = new byte[12];
        // Transaction ID: echo back the ID from the request (first 2 bytes)
        response[0] = buf[0];
        response[1] = buf[1];
        // Flags: QR=1 (response), all others 0 => 0x8000
        response[2] = (byte) 0x80;
        response[3] = 0x00;
        // QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT are already 0 by default

        final DatagramPacket packetResponse = new DatagramPacket(response, response.length, packet.getSocketAddress());
        serverSocket.send(packetResponse);
      }
    } catch (IOException e) {
        System.out.println("IOException: " + e.getMessage());
    }
  }
}
