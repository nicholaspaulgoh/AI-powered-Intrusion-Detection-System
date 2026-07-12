import java.util.*;
import java.util.concurrent.*;

public class ConnectionTracker {

    private final Map<String, List<Long>> recentConnections = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> synErrors = new ConcurrentHashMap<>();
    private final Map<String,List<Long>> rejErrors = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> serviceConnections = new ConcurrentHashMap<>();

    private static final long  WINDOW_MS =2000;

    public int getCount(String dstIp){
           return getWindowCount(recentConnections,dstIp);
    }// end getCount()

    public void recordConnection(String dstIp,String service, boolean isSynError, boolean isRejError){
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

        int rerrors = getWindowCount(synErrors, dstIp);
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
