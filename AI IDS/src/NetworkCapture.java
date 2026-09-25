import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.*;
import java.util.*;

public class NetworkCapture{

    static List<PcapNetworkInterface> interfaces;

    static final ConnectionTracker tracker = new ConnectionTracker();

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

    // Skip known local network noise — these are never attack traffic
// and don't map to NSL-KDD features meaningfully
    private static final Set<Integer> NOISE_PORTS = Set.of(
            5353,   // mDNS — local device discovery
            1900,   // SSDP — UPnP device discovery
            5355,   // LLMNR — local name resolution
            67, 68, // DHCP — IP address assignment
            137, 138, 139, // NetBIOS — Windows local network
            3702    // WS-Discovery — Windows device discovery
    );

    public static void processPacket(byte[] rawData) {
        //Note: we have to go layer by layer: Ethernet(layer 2) -> IpV4(layer 3) -> TCP/UDP (layer 4)
        try {
            Packet packet = EthernetPacket.newPacket(rawData,0,rawData.length); //Take these raw bytes and interpret them as an Ethernet frame.

            IpV4Packet ipPacket= packet.get(IpV4Packet.class); //search the packet to find IpV4 (ARP or IpV6 returns null)
            if(ipPacket ==null)return;

            String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
            String dstIp = ipPacket.getHeader().getDstAddr().getHostAddress();
            int protocol = ipPacket.getHeader().getProtocol().value(); //6   → TCP, 17  → UDP, 1   → ICMP

            //getMoreFragmentFlag() -> Returns true if there are more fragments after this packet.
            //getFragmentOffset() -> Checks whether this packet is not the first fragment.
                                 // If the offset is greater than 0, it means this packet is part of a fragmented packet.
            int wrongFragments =( ipPacket.getHeader().getMoreFragmentFlag() ||
                                    ipPacket.getHeader().getFragmentOffset() !=0) ? 1 :0;


            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            UdpPacket udpPacket = packet.get(UdpPacket.class);

            //fallback values
            int srcPort=0, dstPort=0;
            String flag ="OTH";
            String service="other";
            boolean isUrgent=false; //is packet is UDP isUrgent -> false

            if(tcpPacket != null){
                srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
                dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
                flag=extractFlag(tcpPacket);

                service=portToService(dstPort);

                //Fallback
                //Server (80) -------> Client (52341) srcPort =80 dstPort =52341, to prevent it from being "other" all the time:
                //Ports 0–1023 are called well-known ports.
                //Client computers almost never use these as their temporary (ephemeral) source ports.
                if(service.equals("other") && srcPort<1024){
                    service=portToService(srcPort);
                }
                isUrgent =tcpPacket.getHeader().getUrg();

            }else if(udpPacket !=null){
                srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
                dstPort = udpPacket.getHeader().getDstPort().valueAsInt();
                service= portToService(dstPort);
            }//end if

            // Filter noise before classification
            if(NOISE_PORTS.contains(dstPort) || NOISE_PORTS.contains(srcPort)){
                return;//skip silently — not meaningful for IDS
            }

            // Filter IGMP, multicast, and broadcast — not meaningful for IDS
            if (protocol == 2) return; // IGMP protocol number

            if (dstIp.startsWith("224.") || dstIp.startsWith("225.") ||
                    dstIp.startsWith("226.") || dstIp.startsWith("239.") ||
                    dstIp.equals("255.255.255.255") || dstIp.endsWith(".255")) {
                return; // multicast / broadcast
            }

            int payloadLength = ipPacket.getPayload() !=null ? ipPacket.getPayload().length(): 0; //Payload = everything inside IP after the header, and may be null if no deeper protocol is parsed.

            boolean isSynError = flag.equals("S0") || flag.equals("SH");
            boolean isRejError = flag.equals("REJ");
            boolean isClosing = false;

            if(tcpPacket != null){

                TcpPacket.TcpHeader h = tcpPacket.getHeader();

                isClosing = h.getFin() || h.getRst();
            }
            // Removed RSTR — your extractFlag() never produces it


            boolean isForwardDirection =ConnectionTracker.connectionKey(srcIp, srcPort,dstIp, dstPort,protocol).startsWith(srcIp+":" +srcPort);

            // Update connection state — accumulates bytes across packets
            ConnectionTracker.ConnectionState connState =tracker.updateConnectionState(srcIp, srcPort,dstIp, dstPort,protocol, payloadLength,
                    isForwardDirection, wrongFragments, isUrgent,service);

            // Record this connection only if it hasn't been counted already
            boolean isNewConnection =tracker.recordConnectionIfNew(
                    srcIp,
                    srcPort,
                    dstIp,
                    dstPort,
                    protocol,
                    service,
                    isSynError,
                    isRejError
            );

            if(tcpPacket != null){

                TcpPacket.TcpHeader h = tcpPacket.getHeader();

                tracker.updateTcpState(
                        connState,
                        h.getSyn(),
                        h.getAck(),
                        h.getFin(),
                        h.getRst()
                );
            }

            // Classify only on clean connection close
            if (isClosing) {
                if (tracker.shouldClassify(srcIp, srcPort, dstIp, dstPort, protocol)) {
                    connState.finalFlag = tracker.computeFinalFlag(connState);
                    double[] features = buildFeatureVector(
                            srcIp, dstIp, protocol, srcPort, dstPort,
                            connState.finalFlag, service, connState);

                    System.out.println("========== LIVE FEATURES ==========");
                    String[] names = {
                            "duration","protocol_type","service","flag","src_bytes","dst_bytes",
                            "land","wrong_fragment","urgent",
                            "hot","num_failed_logins","logged_in","num_compromised",
                            "root_shell","su_attempted","num_root","num_file_creations",
                            "num_shells","num_access_files","num_outbound_cmds",
                            "is_host_login","is_guest_login",
                            "count","srv_count","serror_rate","srv_serror_rate",
                            "rerror_rate","srv_rerror_rate","same_srv_rate",
                            "diff_srv_rate","srv_diff_host_rate",
                            "dst_host_count","dst_host_srv_count",
                            "dst_host_same_srv_rate","dst_host_diff_srv_rate",
                            "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
                            "dst_host_serror_rate","dst_host_srv_serror_rate",
                            "dst_host_rerror_rate","dst_host_srv_rerror_rate"
                    };

                    for (int i = 0; i < 41; i++) {
                        System.out.printf("%-30s : %.4f%n", names[i], features[i]);
                    }
                    LiveDetection.analyze(features, srcIp, dstIp, srcPort, dstPort,
                            service, connState.finalFlag);
                }
                tracker.removeRecordedConnection(srcIp, srcPort, dstIp, dstPort, protocol);
            }



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

    public static String portToService(int port) {
        switch (port) {
            case 80:   return "http";
            case 443:  return "http_443";
            case 20:   return "ftp_data";
            case 21:   return "ftp";
            case 22:   return "ssh";
            case 23:   return "telnet";
            case 25:   return "smtp";
            case 53:   return "domain_u";
            case 110:  return "pop_3";
            case 143:  return "imap4";
            case 161:  return "snmp";
            case 194:  return "irc";
            case 389:  return "ldap";
            case 445:  return "netbios_ssn";
            case 587:  return "smtp";   // SMTP submission
            case 993:  return "imap4";  // IMAP over SSL
            case 995:  return "pop_3";  // POP3 over SSL
            case 3306: return "sql_net";
            case 3389: return "private"; // RDP
            case 8080: return "http";
            case 8443: return "http_443";
            default:   return port < 1024 ? "private" : "other";
        }
    }

    public static double[] buildFeatureVector(String srcIp, String dstIp,int protocol,
                                              int srcPort, int dstPort,String flag, String service, ConnectionTracker.ConnectionState connState){


        double[] raw = new double[41];

        // [0] duration — unknown from single packet
        raw[0] = connState.getDurationSeconds();

        // [1] protocol_type — tcp=0, udp=1, icmp=2
        raw[1] = protocol == 6? 0.0: protocol ==17? 1.0:2.0;

        // [2] service — use Preprocessor's service map
        raw[2] =Preprocessor.serviceMap.getOrDefault(service.toLowerCase(),6.0);

        // [3] flag — use Preprocessor's flag map
        raw[3] =Preprocessor.flagMap.getOrDefault(flag,9.0);

        // [4] src_bytes — payload length
        raw[4] = connState.srcBytes;

        // [5] dst_bytes
        raw[5] =connState.dstBytes;

        // [6] land — 1 if src==dst (loopback attack indicator)
        raw[6] = srcIp.equals(dstIp) && srcPort == dstPort ?1.0 :0.0;

        // [7] wrong_fragment — accumulated across connection
        raw[7] = connState.wrongFragments;

        // [8] urgent — accumulated urgent packet count
        raw[8] = connState.urgentCount;

        // [9-21] application-layer features — 0 (require payload inspection)
        // wrong_fragment, urgent, hot, num_failed_logins, logged_in,
        // num_compromised, root_shell, su_attempted, num_root,
        // num_file_creations, num_shells, num_access_files,
        // num_outbound_cmds, is_hot_login, is_guest_login
        for(int i=9; i<22; i++) raw[i] =0.0;

        String serverIp = connState.serverIp;

        raw[22] = tracker.getCount(serverIp);
        raw[23] = tracker.getSrvCount(serverIp, service);

        if (connState.finalFlag != null && connState.finalFlag.equals("SF")) {
            raw[24] = 0.0;
            raw[25] = 0.0;
            raw[37] = 0.0;
            raw[38] = 0.0;
        } else {
            raw[24] = tracker.getSErrorRate(serverIp);
            raw[25] = raw[24];
            raw[37] = raw[24];
            raw[38] = raw[24];
        }


        raw[26] = tracker.getRErrorRate(serverIp);
        raw[27] = raw[26];
        raw[28] = tracker.getSameSrvRate(serverIp, service);
        raw[29] = 1.0 - raw[28];
        raw[30] = 0.0;
        raw[31] = raw[22];
        raw[32] = raw[23];
        raw[33] = raw[28];
        raw[34] = raw[29];
        raw[35] = 0.0;     // dst_host_same_src_port_rate
        raw[36] = 0.0;     // dst_host_srv_diff_host_rate

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
            processPacket(rawPacket);
        });

        handle.close();

    }//end main

}//end class NetworkCapture
