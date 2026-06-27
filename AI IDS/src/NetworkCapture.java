import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.*;
import java.util.List;
import java.util.Scanner;

public class NetworkCapture{

    static List<PcapNetworkInterface> interfaces;
    public static void listInterfaces() throws Exception{

        interfaces = Pcaps.findAllDevs();

        System.out.println("=====================================");
        System.out.println("   All available network interfaces  ");
        System.out.println("=====================================");

        for(int i=0; i<interfaces.size(); i++){
            PcapNetworkInterface iface = interfaces.get(i);
            System.out.println(i+": " + iface.getName() + " - " + iface.getDescription());

        }//end for loop

    }//end listInterfaces()

    public static void processPacket(byte[] rawData, PcapHandle handle) {
        //Note: we have to go layer by layer: Ethernet(layer 2) -> IpV4(layer 3) -> TCP/UDP (layer 4)
        try {
            Packet packet = EthernetPacket.newPacket(rawData,0,rawData.length); //Take these raw bytes and interpret them as an Ethernet frame.

            IpV4Packet ipPacket= packet.get(IpV4Packet.class); //search the packet to find IpV4 (ARP or IpV6 returns null)
            if(ipPacket ==null)return;

            String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
            String dstIp = ipPacket.getHeader().getDstAddr().getHostAddress();
            int protocol = ipPacket.getHeader().getProtocol().value(); //6   → TCP, 17  → UDP, 1   → ICMP


            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            UdpPacket udpPacket = packet.get(UdpPacket.class);

            //fallback values
            int srcPort=0, dstPort=0;
            String flag ="OTH";
            String service="other";

            if(tcpPacket != null){
                srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
                dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
                flag=extractFlag(tcpPacket);
                service=portToService(dstPort);

            }else if(udpPacket !=null){
                srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
                dstPort = udpPacket.getHeader().getDstPort().valueAsInt();
                service= portToService(dstPort);
            }//end if

            int payloadLength = ipPacket.getPayload() !=null ? ipPacket.getPayload().length(): 0; //Payload = everything inside IP after the header, and may be null if no deeper protocol is parsed.
            System.out.printf("%-15s → %-15s  proto=%d  sport=%d  dport=%d  flag=%s  service=%s  bytes=%d%n", srcIp, dstIp, protocol, srcPort, dstPort, flag, service, payloadLength);

        }catch (IllegalRawDataException ex1){
            System.out.println(ex1.getMessage());
        }//end catch
    }//end processPacket

    public static String extractFlag(TcpPacket tcpPacket){
        TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();

        boolean syn = tcpHeader.getSyn();
        boolean ack = tcpHeader.getAck();
        boolean fin = tcpHeader.getFin();
        boolean rst = tcpHeader.getRst();

        if(syn && !ack) return "S0";
        if(syn && ack && !fin && !rst) return "S1";
        if(!syn && ack && fin && !rst) return "SF";
        if(rst && !syn) return "REJ";
        if(syn && fin) return "SH";
        if(rst && syn) return "RSTO";
        return "OTH";


    }

    public static String portToService(int port){

        switch(port){
            case 80: return "http";
            case 443: return "http_443";
            case 20: return "ftp_data";
            case 21: return "ftp";
            case 22: return "ssh";
            case 23: return "telnet";
            case 25: return "smtp";
            case 53: return "domain_u";
            case 110: return "pop_3";
            case 143: return "imap4";
            case 161: return "snmp";
            default: return port<1024? "private" : "other";

        }//end switch
    }//end portToService

    public static void main(String [] args) throws Exception{


        listInterfaces();
        System.out.println("Please choose an interface: ");
        int input = new Scanner(System.in).nextInt();

        PcapNetworkInterface device = interfaces.get(input);

        PcapHandle handle =device.openLive(65536, PromiscuousMode.PROMISCUOUS,10);
        System.out.println("Capturing on: " + device.getDescription());

        // Capture 100 packets then stop (-1 = capture forever)
        handle.loop(100, (RawPacketListener) rawPacket ->{
            processPacket(rawPacket, handle);
        });

        handle.close();

    }//end main

}//end class NetworkCapture
