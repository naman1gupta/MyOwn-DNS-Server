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

        // Parse incoming DNS packet
        // Extract ID (first 2 bytes)
        byte idByte1 = buf[0];
        byte idByte2 = buf[1];
        
        // Extract flags from bytes 2-3
        byte flags1 = buf[2];
        byte flags2 = buf[3];
        
        // Extract OPCODE (bits 1-4 of first flags byte)
        int opcode = (flags1 >> 3) & 0x0f;
        
        // Extract RD (bit 8 of first flags byte) 
        int rd = flags1 & 0x01;
        
        // Determine RCODE: 0 if OPCODE is 0 (standard query), else 4 (not implemented)
        int rcode = (opcode == 0) ? 0 : 4;

        // Build DNS response with header + question section + answer section
        // Domain name: \x0ccodecrafters\x02io\x00 = 1 + 12 + 1 + 2 + 1 = 17 bytes
        // Type: 2 bytes, Class: 2 bytes
        // Total question section: 17 + 2 + 2 = 21 bytes
        // Answer section: Name (17) + Type (2) + Class (2) + TTL (4) + Length (2) + Data (4) = 31 bytes
        final byte[] response = new byte[12 + 21 + 31]; // 12 byte header + 21 byte question + 31 byte answer
        
        // Header section (12 bytes)
        // Transaction ID: Echo back from request
        response[0] = idByte1;
        response[1] = idByte2;
        
        // Flags: QR=1, OPCODE from request, AA=0, TC=0, RD from request
        // First flags byte: QR(1) + OPCODE(4) + AA(1) + TC(1) + RD(1) = 1xxxxxx0 + RD
        response[2] = (byte) (0x80 | (opcode << 3) | rd);
        
        // Second flags byte: RA(1) + Z(3) + RCODE(4) = 0000xxxx
        response[3] = (byte) rcode;
        // QDCOUNT: 1 question
        response[4] = 0x00;
        response[5] = 0x01;
        // ANCOUNT: 1 answer
        response[6] = 0x00;
        response[7] = 0x01;
        // NSCOUNT, ARCOUNT are already 0 by default

        // Question section (21 bytes)
        int offset = 12;
        // Domain name: codecrafters.io encoded as labels
        // \x0ccodecrafters
        response[offset] = 0x0c; // length of "codecrafters"
        offset++;
        byte[] codecrafters = "codecrafters".getBytes();
        System.arraycopy(codecrafters, 0, response, offset, codecrafters.length);
        offset += codecrafters.length;
        
        // \x02io
        response[offset] = 0x02; // length of "io"
        offset++;
        byte[] io = "io".getBytes();
        System.arraycopy(io, 0, response, offset, io.length);
        offset += io.length;
        
        // Null terminator
        response[offset] = 0x00;
        offset++;
        
        // Type: 1 (A record) - 2 bytes big-endian
        response[offset] = 0x00;
        offset++;
        response[offset] = 0x01;
        offset++;
        
        // Class: 1 (IN) - 2 bytes big-endian
        response[offset] = 0x00;
        offset++;
        response[offset] = 0x01;
        offset++;

        // Answer section (31 bytes)
        // Name: codecrafters.io encoded as labels (same as question)
        // \x0ccodecrafters
        response[offset] = 0x0c; // length of "codecrafters"
        offset++;
        System.arraycopy(codecrafters, 0, response, offset, codecrafters.length);
        offset += codecrafters.length;
        
        // \x02io
        response[offset] = 0x02; // length of "io"
        offset++;
        System.arraycopy(io, 0, response, offset, io.length);
        offset += io.length;
        
        // Null terminator
        response[offset] = 0x00;
        offset++;
        
        // Type: 1 (A record) - 2 bytes big-endian
        response[offset] = 0x00;
        offset++;
        response[offset] = 0x01;
        offset++;
        
        // Class: 1 (IN) - 2 bytes big-endian
        response[offset] = 0x00;
        offset++;
        response[offset] = 0x01;
        offset++;
        
        // TTL: 60 seconds - 4 bytes big-endian
        response[offset] = 0x00;
        offset++;
        response[offset] = 0x00;
        offset++;
        response[offset] = 0x00;
        offset++;
        response[offset] = 0x3c; // 60 in hex
        offset++;
        
        // Length: 4 bytes (length of IP address) - 2 bytes big-endian
        response[offset] = 0x00;
        offset++;
        response[offset] = 0x04;
        offset++;
        
        // Data: IP address 8.8.8.8 - 4 bytes
        response[offset] = 0x08;
        offset++;
        response[offset] = 0x08;
        offset++;
        response[offset] = 0x08;
        offset++;
        response[offset] = 0x08;

        final DatagramPacket packetResponse = new DatagramPacket(response, response.length, packet.getSocketAddress());
        serverSocket.send(packetResponse);
      }
    } catch (IOException e) {
        System.out.println("IOException: " + e.getMessage());
    }
  }
}
