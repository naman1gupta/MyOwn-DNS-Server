import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.ArrayList;
import java.util.List;

public class Main {
  
  static class DomainName {
    byte[] data;
    int length;
    
    DomainName(byte[] data, int length) {
      this.data = data;
      this.length = length;
    }
  }
  
  static class Question {
    DomainName name;
    int type;
    int qclass;
    
    Question(DomainName name, int type, int qclass) {
      this.name = name;
      this.type = type;
      this.qclass = qclass;
    }
  }
  
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
        
        // Extract QDCOUNT (bytes 4-5)
        int qdcount = ((buf[4] & 0xFF) << 8) | (buf[5] & 0xFF);
        
        // Determine RCODE: 0 if OPCODE is 0 (standard query), else 4 (not implemented)
        int rcode = (opcode == 0) ? 0 : 4;
        
        // Parse questions
        List<Question> questions = new ArrayList<>();
        int offset = 12; // Start after header
        
        for (int i = 0; i < qdcount; i++) {
          DomainName domainName = parseDomainName(buf, offset);
          offset += domainName.length;
          
          // Extract type and class (4 bytes total)
          int type = ((buf[offset] & 0xFF) << 8) | (buf[offset + 1] & 0xFF);
          int qclass = ((buf[offset + 2] & 0xFF) << 8) | (buf[offset + 3] & 0xFF);
          offset += 4;
          
          questions.add(new Question(domainName, type, qclass));
        }

        // Calculate response size
        int questionSectionSize = 0;
        int answerSectionSize = 0;
        
        for (Question q : questions) {
          // Question: uncompressed domain name + type (2) + class (2)
          questionSectionSize += q.name.data.length + 4;
          // Answer: uncompressed domain name + type (2) + class (2) + TTL (4) + length (2) + data (4)
          answerSectionSize += q.name.data.length + 14;
        }
        
        final byte[] response = new byte[12 + questionSectionSize + answerSectionSize];
        
        // Header section (12 bytes)
        // Transaction ID: Echo back from request
        response[0] = idByte1;
        response[1] = idByte2;
        
        // Flags: QR=1, OPCODE from request, AA=0, TC=0, RD from request
        response[2] = (byte) (0x80 | (opcode << 3) | rd);
        
        // Second flags byte: RA(1) + Z(3) + RCODE(4) = 0000xxxx
        response[3] = (byte) rcode;
        
        // QDCOUNT: number of questions
        response[4] = (byte) ((qdcount >> 8) & 0xFF);
        response[5] = (byte) (qdcount & 0xFF);
        
        // ANCOUNT: number of answers (same as questions)
        response[6] = (byte) ((qdcount >> 8) & 0xFF);
        response[7] = (byte) (qdcount & 0xFF);
        
        // NSCOUNT, ARCOUNT are already 0 by default

        // Question sections
        int responseOffset = 12;
        for (Question q : questions) {
          // Domain name: copy uncompressed domain
          System.arraycopy(q.name.data, 0, response, responseOffset, q.name.data.length);
          responseOffset += q.name.data.length;
          
          // Type: copy from question
          response[responseOffset] = (byte) ((q.type >> 8) & 0xFF);
          responseOffset++;
          response[responseOffset] = (byte) (q.type & 0xFF);
          responseOffset++;
          
          // Class: copy from question
          response[responseOffset] = (byte) ((q.qclass >> 8) & 0xFF);
          responseOffset++;
          response[responseOffset] = (byte) (q.qclass & 0xFF);
          responseOffset++;
        }

        // Answer sections
        for (Question q : questions) {
          // Name: same uncompressed domain name as question
          System.arraycopy(q.name.data, 0, response, responseOffset, q.name.data.length);
          responseOffset += q.name.data.length;
          
          // Type: 1 (A record) - 2 bytes big-endian
          response[responseOffset] = 0x00;
          responseOffset++;
          response[responseOffset] = 0x01;
          responseOffset++;
          
          // Class: 1 (IN) - 2 bytes big-endian
          response[responseOffset] = 0x00;
          responseOffset++;
          response[responseOffset] = 0x01;
          responseOffset++;
          
          // TTL: 60 seconds - 4 bytes big-endian
          response[responseOffset] = 0x00;
          responseOffset++;
          response[responseOffset] = 0x00;
          responseOffset++;
          response[responseOffset] = 0x00;
          responseOffset++;
          response[responseOffset] = 0x3c; // 60 in hex
          responseOffset++;
          
          // Length: 4 bytes (length of IP address) - 2 bytes big-endian
          response[responseOffset] = 0x00;
          responseOffset++;
          response[responseOffset] = 0x04;
          responseOffset++;
          
          // Data: IP address 8.8.8.8 - 4 bytes
          response[responseOffset] = 0x08;
          responseOffset++;
          response[responseOffset] = 0x08;
          responseOffset++;
          response[responseOffset] = 0x08;
          responseOffset++;
          response[responseOffset] = 0x08;
          responseOffset++;
        }

        final DatagramPacket packetResponse = new DatagramPacket(response, response.length, packet.getSocketAddress());
        serverSocket.send(packetResponse);
      }
    } catch (IOException e) {
        System.out.println("IOException: " + e.getMessage());
    }
  }
  
  // Parse domain name with compression support
  static DomainName parseDomainName(byte[] buf, int startOffset) {
    List<Byte> uncompressedName = new ArrayList<>();
    int offset = startOffset;
    boolean jumped = false;
    int originalOffset = startOffset;
    
    while (true) {
      int lengthByte = buf[offset] & 0xFF;
      
      if (lengthByte == 0) {
        // End of name
        uncompressedName.add((byte) 0);
        offset++;
        break;
      } else if ((lengthByte & 0xC0) == 0xC0) {
        // Compression pointer: bits 11xxxxxx xxxxxxxx
        int pointer = ((lengthByte & 0x3F) << 8) | (buf[offset + 1] & 0xFF);
        
        if (!jumped) {
          originalOffset = offset + 2; // Remember where to continue after decompression
          jumped = true;
        }
        
        offset = pointer; // Jump to the pointed location
        continue;
      } else {
        // Regular label
        uncompressedName.add((byte) lengthByte);
        offset++;
        
        for (int i = 0; i < lengthByte; i++) {
          uncompressedName.add(buf[offset]);
          offset++;
        }
      }
    }
    
    // Convert List<Byte> to byte array
    byte[] nameData = new byte[uncompressedName.size()];
    for (int i = 0; i < uncompressedName.size(); i++) {
      nameData[i] = uncompressedName.get(i);
    }
    
    // Calculate the length consumed in the original message
    int consumedLength = jumped ? (originalOffset - startOffset) : (offset - startOffset);
    
    return new DomainName(nameData, consumedLength);
  }
}
