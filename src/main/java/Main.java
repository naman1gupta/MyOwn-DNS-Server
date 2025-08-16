import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
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
  
  static class Answer {
    DomainName name;
    int type;
    int aclass;
    int ttl;
    int rdlength;
    byte[] rdata;
    
    Answer(DomainName name, int type, int aclass, int ttl, int rdlength, byte[] rdata) {
      this.name = name;
      this.type = type;
      this.aclass = aclass;
      this.ttl = ttl;
      this.rdlength = rdlength;
      this.rdata = rdata;
    }
  }
  
  public static void main(String[] args){
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    System.out.println("Logs from your program will appear here!");

    // Parse command line arguments
    String resolverAddress = null;
    int resolverPort = 53;
    
    for (int i = 0; i < args.length; i++) {
      if ("--resolver".equals(args[i]) && i + 1 < args.length) {
        String[] parts = args[i + 1].split(":");
        resolverAddress = parts[0];
        if (parts.length > 1) {
          resolverPort = Integer.parseInt(parts[1]);
        }
        break;
      }
    }
    
    boolean forwardingMode = (resolverAddress != null);

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

        byte[] response;
        
        if (forwardingMode && rcode == 0) {
          // Only forward standard queries (OPCODE=0), otherwise handle locally
          response = handleForwarding(questions, idByte1, idByte2, opcode, rd, resolverAddress, resolverPort);
        } else {
          response = handleLocalResponse(questions, idByte1, idByte2, opcode, rd, rcode, qdcount);
        }

        final DatagramPacket packetResponse = new DatagramPacket(response, response.length, packet.getSocketAddress());
        serverSocket.send(packetResponse);
      }
    } catch (IOException e) {
        System.out.println("IOException: " + e.getMessage());
    }
  }
  
  static byte[] handleForwarding(List<Question> questions, byte idByte1, byte idByte2, int opcode, int rd, String resolverAddress, int resolverPort) throws IOException {
    List<Answer> allAnswers = new ArrayList<>();
    
    // Forward each question separately
    for (Question question : questions) {
      // Create single question packet
      byte[] queryPacket = createSingleQuestionPacket(question, (short) 1234, opcode, rd);
      
      // Send to resolver
      try (DatagramSocket socket = new DatagramSocket()) {
        InetAddress resolverAddr = InetAddress.getByName(resolverAddress);
        DatagramPacket queryPacketUDP = new DatagramPacket(queryPacket, queryPacket.length, resolverAddr, resolverPort);
        socket.send(queryPacketUDP);
        
        // Receive response
        byte[] responseBuffer = new byte[512];
        DatagramPacket responsePacketUDP = new DatagramPacket(responseBuffer, responseBuffer.length);
        socket.receive(responsePacketUDP);
        
        // Parse response to extract answers
        List<Answer> answers = parseAnswersFromResponse(responseBuffer);
        allAnswers.addAll(answers);
      }
    }
    
    // Build merged response
    return buildMergedResponse(questions, allAnswers, idByte1, idByte2, opcode, rd);
  }
  
  static byte[] createSingleQuestionPacket(Question question, short id, int opcode, int rd) {
    int packetSize = 12 + question.name.data.length + 4;
    byte[] packet = new byte[packetSize];
    
    // Header
    packet[0] = (byte) ((id >> 8) & 0xFF);
    packet[1] = (byte) (id & 0xFF);
    packet[2] = (byte) ((opcode << 3) | rd);
    packet[3] = 0x00;
    packet[4] = 0x00; // QDCOUNT = 1
    packet[5] = 0x01;
    // ANCOUNT, NSCOUNT, ARCOUNT = 0
    
    // Question
    int offset = 12;
    System.arraycopy(question.name.data, 0, packet, offset, question.name.data.length);
    offset += question.name.data.length;
    
    packet[offset] = (byte) ((question.type >> 8) & 0xFF);
    packet[offset + 1] = (byte) (question.type & 0xFF);
    packet[offset + 2] = (byte) ((question.qclass >> 8) & 0xFF);
    packet[offset + 3] = (byte) (question.qclass & 0xFF);
    
    return packet;
  }
  
  static List<Answer> parseAnswersFromResponse(byte[] response) {
    List<Answer> answers = new ArrayList<>();
    
    // Extract ANCOUNT
    int ancount = ((response[6] & 0xFF) << 8) | (response[7] & 0xFF);
    
    // Skip header (12 bytes) and question section
    int offset = 12;
    
    // Skip question section - find the question
    DomainName questionName = parseDomainName(response, offset);
    offset += questionName.length + 4; // +4 for type and class
    
    // Parse answers
    for (int i = 0; i < ancount; i++) {
      DomainName answerName = parseDomainName(response, offset);
      offset += answerName.length;
      
      int type = ((response[offset] & 0xFF) << 8) | (response[offset + 1] & 0xFF);
      int aclass = ((response[offset + 2] & 0xFF) << 8) | (response[offset + 3] & 0xFF);
      int ttl = ((response[offset + 4] & 0xFF) << 24) | 
                ((response[offset + 5] & 0xFF) << 16) |
                ((response[offset + 6] & 0xFF) << 8) |
                (response[offset + 7] & 0xFF);
      int rdlength = ((response[offset + 8] & 0xFF) << 8) | (response[offset + 9] & 0xFF);
      
      offset += 10;
      
      byte[] rdata = new byte[rdlength];
      System.arraycopy(response, offset, rdata, 0, rdlength);
      offset += rdlength;
      
      answers.add(new Answer(answerName, type, aclass, ttl, rdlength, rdata));
    }
    
    return answers;
  }
  
  static byte[] buildMergedResponse(List<Question> questions, List<Answer> answers, byte idByte1, byte idByte2, int opcode, int rd) {
    // Calculate response size
    int questionSectionSize = 0;
    int answerSectionSize = 0;
    
    for (Question q : questions) {
      questionSectionSize += q.name.data.length + 4;
    }
    
    for (Answer a : answers) {
      answerSectionSize += a.name.data.length + 10 + a.rdlength;
    }
    
    byte[] response = new byte[12 + questionSectionSize + answerSectionSize];
    
    // Header
    response[0] = idByte1;
    response[1] = idByte2;
    response[2] = (byte) (0x80 | (opcode << 3) | rd);
    response[3] = 0x00;
    response[4] = (byte) ((questions.size() >> 8) & 0xFF);
    response[5] = (byte) (questions.size() & 0xFF);
    response[6] = (byte) ((answers.size() >> 8) & 0xFF);
    response[7] = (byte) (answers.size() & 0xFF);
    
    int offset = 12;
    
    // Questions
    for (Question q : questions) {
      System.arraycopy(q.name.data, 0, response, offset, q.name.data.length);
      offset += q.name.data.length;
      response[offset] = (byte) ((q.type >> 8) & 0xFF);
      response[offset + 1] = (byte) (q.type & 0xFF);
      response[offset + 2] = (byte) ((q.qclass >> 8) & 0xFF);
      response[offset + 3] = (byte) (q.qclass & 0xFF);
      offset += 4;
    }
    
    // Answers
    for (Answer a : answers) {
      System.arraycopy(a.name.data, 0, response, offset, a.name.data.length);
      offset += a.name.data.length;
      response[offset] = (byte) ((a.type >> 8) & 0xFF);
      response[offset + 1] = (byte) (a.type & 0xFF);
      response[offset + 2] = (byte) ((a.aclass >> 8) & 0xFF);
      response[offset + 3] = (byte) (a.aclass & 0xFF);
      response[offset + 4] = (byte) ((a.ttl >> 24) & 0xFF);
      response[offset + 5] = (byte) ((a.ttl >> 16) & 0xFF);
      response[offset + 6] = (byte) ((a.ttl >> 8) & 0xFF);
      response[offset + 7] = (byte) (a.ttl & 0xFF);
      response[offset + 8] = (byte) ((a.rdlength >> 8) & 0xFF);
      response[offset + 9] = (byte) (a.rdlength & 0xFF);
      offset += 10;
      System.arraycopy(a.rdata, 0, response, offset, a.rdlength);
      offset += a.rdlength;
    }
    
    return response;
  }
  
  static byte[] handleLocalResponse(List<Question> questions, byte idByte1, byte idByte2, int opcode, int rd, int rcode, int qdcount) {
    // Calculate response size
    int questionSectionSize = 0;
    int answerSectionSize = 0;
    
    for (Question q : questions) {
      // Question: uncompressed domain name + type (2) + class (2)
      questionSectionSize += q.name.data.length + 4;
      // Answer: uncompressed domain name + type (2) + class (2) + TTL (4) + length (2) + data (4)
      answerSectionSize += q.name.data.length + 14;
    }
    
    byte[] response = new byte[12 + questionSectionSize + answerSectionSize];
    
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
    
    return response;
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
