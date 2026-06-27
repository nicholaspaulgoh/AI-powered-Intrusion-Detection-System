import java.util.*;
import java.util.concurrent.*;

public class ConnectionTracker {

    private final Map<String, List<Long>> recentConnections = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> synError = new ConcurrentHashMap<>();


    public int getCount(String dstIp){
         long now =System.currentTimeMillis();
         long twoSecondsAgo =now -2000;

       List<Long> times = recentConnections.computeIfAbsent(dstIp, k-> Collections.synchronizedList( new ArrayList<>())); //returns recentConnections or []

        synchronized(times) {
            times.removeIf(t -> t <= twoSecondsAgo);
            return times.size();
        }
    }// end getCount()

    public void recordConnection(String dstIp, boolean isSynError){

        recentConnections.computeIfAbsent(dstIp, k -> Collections.synchronizedList(new ArrayList<>())).add(System.currentTimeMillis());


        if(isSynError){
            synError.computeIfAbsent(dstIp, k-> Collections.synchronizedList(new ArrayList<>())).add(System.currentTimeMillis());
        }//end


    }// end recordConnection

    public double getSErrorRate(String dstIp){
        long now =System.currentTimeMillis();
        long twoSecondsAgo =now -2000;

       int total= getCount(dstIp);
       if(total ==0) return 0.0;

       List<Long> synErrorCount = synError.computeIfAbsent(dstIp,k-> Collections.synchronizedList(new ArrayList<>()));
       int errors;
       synchronized(synErrorCount) {
           synErrorCount.removeIf(t -> t <= twoSecondsAgo);
          errors= synErrorCount.size();
       }

       return (double)errors/total;
    }//getSErrorRate
}//end ConnectionTracker
