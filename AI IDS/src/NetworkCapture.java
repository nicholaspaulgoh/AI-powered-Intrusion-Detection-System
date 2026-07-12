import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.*;
import java.util.List;
import java.util.Scanner;

public class NetworkCapture{

    static List<PcapNetworkInterface> interfaces;

    private static final ConnectionTracker tracker = new ConnectionTracker();

    public static void listInterfaces() throws Exception{

        interfaces = Pcaps.findAllDevs();   //Pcaps.findAllDevs() :Ask the operating system for every network
                                            // interface (network device) that can capture packets.
                                            //returns list

        System.out.println("=====================================");
        System.out.println("   All available network interfaces  ");
        System.out.println("=====================================");

        for(int i=0; i<interfaces.size(); i++){
            PcapNetworkInterface iface = interfaces.get(i);
            System.out.println(i+": " + iface.getName() + " - " + iface.getDescription());

        }//end for loop

    }//end listInterfaces()

    public static void processPacket(byte[] rawData) {
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

            double[] features = buildFeatureVector(srcIp,dstIp,protocol,srcPort,dstPort,flag,service,payloadLength);
            LiveDetection.analyze(features,srcIp,dstIp,service,flag);


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

    public static double[] buildFeatureVector(String srcIp, String dstIp,int protocol,
                                              int srcPort, int dstPort,String flag, String service, int payloadBytes){

        boolean isSynError = flag.equals("S0") || flag.equals("S1") || flag.equals("SH");
        boolean isRejError = flag.equals("REJ");
        tracker.recordConnection(dstIp, service, isSynError, isRejError);

        double[] raw = new double[41];

        // [0] duration — unknown from single packet
        raw[0] = 0.0;

        // [1] protocol_type — tcp=0, udp=1, icmp=2
        raw[1] = protocol == 6? 0.0: protocol ==17? 1.0:2.0;

        // [2] service — use Preprocessor's service map
        raw[2] =Preprocessor.serviceMap.getOrDefault(service.toLowerCase(),6.0);

        // [3] flag — use Preprocessor's flag map
        raw[3] =Preprocessor.flagMap.getOrDefault(flag,-1.0);

        // [4] src_bytes — payload length as approximation
        raw[4] = payloadBytes;

        // [5] dst_bytes — unknown from single captured packet
        raw[5] =0.0;

        // [6] land — 1 if src==dst (loopback attack indicator)
        raw[6] = srcIp.equals(dstIp) && srcPort == dstPort ?1.0 :0.0;

        // [7-21] connection-level features — default 0 (require full session state)
        // wrong_fragment, urgent, hot, num_failed_logins, logged_in,
        // num_compromised, root_shell, su_attempted, num_root,
        // num_file_creations, num_shells, num_access_files,
        // num_outbound_cmds, is_hot_login, is_guest_login
        for(int i=0; i<22; i++) raw[i] =0.0;

        // [22] count — connections to same dst in last 2 seconds
        raw[22] = tracker.getCount(dstIp);

        // [23] srv_count — same service connections to same dst
        raw[23] =tracker.getSrvCount(dstIp,service);

        // [24] serror_rate
        raw[24] = tracker.getSErrorRate(dstIp);

        // [25] srv_serror_rate — approximate as same as serror_rate
        raw[25] = raw[24];

        // [26] rerror_rate
        raw[26] = tracker.getRErrorRate(dstIp);

        // [27] srv_rerror_rate — approximate as same
        raw[27] = raw[26];

        // [28] same_srv_rate
        raw[28] = tracker.getSameSrvRate(dstIp, service);

        // [29] diff_srv_rate
        raw[29] = 1.0-raw[28];

        // [30] srv_diff_host_rate — 0 (would need multi-host tracking)
        raw[30]=0.0;

        // [31-40] dst_host features — approximate using same window stats
        raw[31] = raw[22]; // dst_host_count ≈ count
        raw[32] = raw[23]; // dst_host_srv_count ≈ srv_count
        raw[33] = raw[28]; // dst_host_same_srv_rate
        raw[34] = raw[29]; // dst_host_diff_srv_rate
        raw[35] = 0.0;     // dst_host_same_src_port_rate
        raw[36] = 0.0;     // dst_host_srv_diff_host_rate
        raw[37] = raw[24]; // dst_host_serror_rate
        raw[38] = raw[24]; // dst_host_srv_serror_rate
        raw[39] = raw[26]; // dst_host_rerror_rate
        raw[40] = raw[26]; // dst_host_srv_rerror_rate

        return Preprocessor.engineerFeatures(raw);


    }//end buildFeatureVector

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
