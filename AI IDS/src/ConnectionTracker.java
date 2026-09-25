import java.util.*;
import java.util.concurrent.*;

public class ConnectionTracker {

    private final Map<String, List<Long>> recentConnections = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> synErrors = new ConcurrentHashMap<>();
    private final Map<String,List<Long>> rejErrors = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> serviceConnections = new ConcurrentHashMap<>();

    private final Map<String,Long> recordedConnections = new ConcurrentHashMap<>();

    private static final long  WINDOW_MS =2000;

    //per-connection state tracking
    public static class ConnectionState{
        public final long startTime;
        public long lastPacketTime;
        public long srcBytes;
        public long dstBytes;
        public int wrongFragments;
        public int urgentCount;
        // Store metadata so timeout thread doesn't need to parse the key
        public final String srcIp;
        public final int    srcPort;
        public final String dstIp;
        public final int    dstPort;
        public final int    protocol;
        public       String service;
        public boolean seenSyn = false;
        public boolean seenSynAck = false;
        public boolean seenAck = false;
        public boolean seenFin = false;
        public boolean seenRst = false;
        public String finalFlag = "OTH";
        public final String serverIp;

        public ConnectionState(String srcIp, int srcPort, String dstIp, int dstPort, int protocol, String service) {
            long now           = System.currentTimeMillis();
            this.startTime     = now;
            this.lastPacketTime = now;
            this.srcBytes      = 0;
            this.dstBytes      = 0;
            this.wrongFragments = 0;
            this.urgentCount   = 0;
            this.srcIp         = srcIp;
            this.srcPort       = srcPort;
            this.dstIp         = dstIp;
            this.dstPort       = dstPort;
            this.protocol      = protocol;
            this.service       = service;
            this.serverIp = (dstPort <= srcPort) ? dstIp : srcIp;
        }

        public double getDurationSeconds(){
            return(System.currentTimeMillis() -startTime)/1000.0;
        }

        public long getIdleMS(){
            return System.currentTimeMillis() - lastPacketTime;
        }
    }
    /*
     * Records connection only if new in current 2-second window. Prevent duplicate counting of the same TCP connection.
     * Uses Map<String, Long> so entries expire and can be re-counted
     * when the same connection reappears after the window rolls over.
     */

    public boolean recordConnectionIfNew(String srcIp, int srcPort, String dstIp, int dstPort,
                                         int protocol, String service,
                                         boolean isSynError, boolean isRejError) {
        String key    = connectionKey(srcIp, srcPort, dstIp, dstPort, protocol);
        long now      = System.currentTimeMillis();
        long cutoff   = now - WINDOW_MS;
        Long lastSeen = recordedConnections.get(key);

        if (lastSeen == null || lastSeen <= cutoff) {
            recordedConnections.put(key, now);
            // Always record using server IP for consistent direction-independent lookup
            String serverIp = (dstPort <= srcPort) ? dstIp : srcIp;
            recordConnectionTimestamps(serverIp, service, isSynError, isRejError);
            return true;
        }
        return false;
    }

    /*
     * Encapsulated removal — called by NetworkCapture on connection close.
     * NetworkCapture should never touch internal maps directly.
     */

    public void removeRecordedConnection(String srcIp, int srcPort, String dstIp, int dstPort, int protocol) {
        String key= connectionKey(srcIp, srcPort, dstIp, dstPort, protocol);
        recordedConnections.remove(key);
        connectionStates.remove(key);
    }

    /*
     * Returns a snapshot of all connection states for the timeout thread.
     * Returns a copy so the timeout thread doesn't need to hold the lock.
     */
    public List<ConnectionState> getIdleConnections(long idleThresholdMS){
        List<ConnectionState> idle = new ArrayList<>();
        for(ConnectionState state : connectionStates.values() ) {
            if (state.getIdleMS() >= idleThresholdMS) {
                idle.add(state);
            }
        }
            return idle;
    }
    private final Map<String,ConnectionState> connectionStates = new ConcurrentHashMap<>(); //to map connection to its metadata

    /*
     * Builds the 5-tuple key that uniquely identifies a connection.
     * We always order src/dst so that reverse packets map to same connection:
     * srcIp:srcPort → dstIp:dstPort becomes the canonical form only if
     * it matches the original direction; reverse packets use the flipped key.
     */
    public static String connectionKey(String srcIp, int srcPort,
                                       String dstIp, int dstPort, int protocol) {

        //Smaller Endpoint - Larger Endpoint
        //192... comes after 10... -> compareTo >0 -> true -> swap -> 10.0.0.5 - 192.168.1.10
        //10... comes before 192... -> compareTo <0 -> false -> no swap -> 10.0.0.5 - 192.168.1.10

        //if both IPs are identical
        //compareTo return 0, so we check port
        //eg srcPort= 6000, dstPort =80, 6000 >80? -> true -> swap and vice versa
        boolean swap = srcIp.compareTo(dstIp) > 0 || (srcIp.equals(dstIp) && srcPort > dstPort);

        if(swap){
            //Put destination first
            return dstIp + ":" + dstPort + "-" + srcIp + ":" + srcPort + "-" + protocol;
        }
        return srcIp + ":" + srcPort + "-" + dstIp + ":" + dstPort + "-" + protocol;
    }

    /*
     * Gets or creates connection state for a 5-tuple.
     * Updates src_bytes or dst_bytes depending on direction.
     */

    public ConnectionState updateConnectionState(
            String srcIp, int srcPort,
            String dstIp, int dstPort,
            int protocol, int payloadBytes,
            boolean isForwardDirection,
            int wrongFragments, boolean isUrgent, String service) {

        String key = connectionKey(srcIp, srcPort, dstIp, dstPort,protocol);

        ConnectionState state =connectionStates.get(key);

        //if state didnt exist before
        if(state ==null){
            state=new ConnectionState(srcIp,srcPort,dstIp,dstPort,protocol,service);
            connectionStates.put(key,state);
        }
        // Update idle timer on every packet (SYN -> SYN-ACK -> ACK -> FIN..)
        state.lastPacketTime = System.currentTimeMillis();

        // Accumulate bytes by direction
        if (isForwardDirection){ //Client → Server
            state.srcBytes += payloadBytes;
        }else{ //Server -> Client
            state.dstBytes += payloadBytes;
        }
        state.wrongFragments += wrongFragments;

        if(isUrgent){
            state.urgentCount++;
        }

        return state;
    }

    public void updateTcpState(ConnectionState state, boolean syn,
                               boolean ack,
                               boolean fin,
                               boolean rst){

        if(syn && !ack)
            state.seenSyn = true;

        if(syn && ack)
            state.seenSynAck = true;

        if(ack)
            state.seenAck = true;

        if(fin)
            state.seenFin = true;

        if(rst)
            state.seenRst = true;
    }

    public String computeFinalFlag(ConnectionState state){

        if(state.seenRst)
            return "REJ";

        if(state.seenSyn &&
                state.seenSynAck &&
                state.seenFin)
            return "SF";

        if(state.seenSyn &&
                !state.seenSynAck)
            return "S0";

        if(state.seenSyn &&
                state.seenSynAck)
            return "S1";

        return "OTH";
    }

    private final Map<String, Long> recentlyClassified = new ConcurrentHashMap<>();

    /*
     * Returns true if this connection should be classified (first time closing).
     * Returns false if already classified within the last 5 seconds.
     */
    public boolean shouldClassify(String srcIp, int srcPort,
                                  String dstIp, int dstPort, int protocol) {
        String key = connectionKey(srcIp, srcPort, dstIp, dstPort, protocol);
        long now    = System.currentTimeMillis();

        Long lastClassified = recentlyClassified.get(key);
        if (lastClassified != null && now - lastClassified < 5000) {
            return false; // already classified this connection recently
        }

        recentlyClassified.put(key, now);
        return true;
    }

     /*
    Removes completed connections (FIN/RST seen) to save memory.

     public void closeConnection(String srcIp, int srcPort,
                                 String dstIp, int dstPort, int proto) {
         String key = connectionKey(srcIp, srcPort, dstIp, dstPort, proto);
        connectionStates.remove(key);

         //if doesnt exist -> return null (does not throw exception) hence safe
     }
     */


    public int getCount(String dstIp){
           return getWindowCount(recentConnections,dstIp);
    }// end getCount()

    public void recordConnectionTimestamps(String dstIp, String service, boolean isSynError, boolean isRejError){
        long now = System.currentTimeMillis();

        recentConnections.computeIfAbsent(dstIp, k -> Collections.synchronizedList(new ArrayList<>())).add(now);

        serviceConnections.computeIfAbsent(dstIp +":" + service, k-> Collections.synchronizedList(new ArrayList<>())).add(now);
        if(isSynError){
            synErrors.computeIfAbsent(dstIp, k-> Collections.synchronizedList(new ArrayList<>())).add(now);
        }//end

        if(isRejError){
            rejErrors.computeIfAbsent(dstIp, k -> Collections.synchronizedList(new ArrayList<>())).add(now);
        }

    }// end recordConnection

    public double getSErrorRate(String dstIp){

       int total= getCount(dstIp);
       if(total ==0) return 0.0;

       int serrors = getWindowCount(synErrors, dstIp);
       return (double)serrors/total;
    }//getSErrorRate

    public double getRErrorRate(String dstIp){

        int total= getCount(dstIp);
        if(total ==0) return 0.0;

        int rerrors = getWindowCount(rejErrors, dstIp);
        return (double)rerrors/total;
    }//getRErrorRate

    public int getSrvCount(String dstIp, String service){

        return getWindowCount(serviceConnections,dstIp +":" + service);
    }//getSrvCount

    public double getSameSrvRate(String dstIp, String service){

        double total = getCount(dstIp);
        if(total==0.0) return 0.0;

        return getSrvCount(dstIp, service)/total;

    }//getSameSrvRate

    private int getWindowCount(Map <String, List<Long>> map, String key){
        long cutoff = System.currentTimeMillis() - WINDOW_MS;

        List<Long> times= map.computeIfAbsent(key, k -> Collections.synchronizedList(new ArrayList<>()));

        synchronized(times){

            times.removeIf(time -> time <=cutoff);
            return times.size();
        }
    }// end getWindowCount
}//end ConnectionTracker
