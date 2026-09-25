import weka.classifiers.AbstractClassifier;
import weka.core.*;
import java.util.*;


public class LiveDetection {

    private static AbstractClassifier classifier;
    private static Instances instancesStructure;
    private static boolean initialized =false;

    public static void initialize(String modelPath) throws Exception{ //"Has the LiveDetectionEngine been set up yet?"

        System.out.println("[LiveDetection] Loading classifier...");
        classifier= ClassifierEngine.loadModel(modelPath);

        // Build an empty Weka structure matching the 46-feature schema.
        // We pass empty lists — DataLoader only needs them to set up attributes.
        ArrayList<String> emptyLabels = new ArrayList<>();
        ArrayList<double[]> emptyData = new ArrayList<>();
        instancesStructure = DataLoader.buildInstances(emptyData, emptyLabels, "LiveCapture");

        initialized=true;
        System.out.println("[LiveDetection] Ready.");

    }//end initialize

        public static  void analyze(double[] rawEngineered, String srcIp, String dstIp,
                                    int srcPort, int dstPort,String service, String flag){

       if(!initialized){
           System.out.println("[LiveDetection] Not initialised — call initialise() first.");
           return;
       }
       try {
           double[] normalized= Preprocessor.normalizeRow(rawEngineered);

           System.out.println("===== NORMALIZED =====");
           for (int i = 0; i < normalized.length; i++) {
               System.out.printf("%2d : %.6f%n", i, normalized[i]);
           }

           String classification = ClassifierEngine.classify(classifier,normalized,instancesStructure);

           boolean isEncryptedWeb = service.equals("http_443") || service.equals("http");
           boolean isDNS = service.equals("domain_u") || service.equals("domain");
           boolean isCleanOrMidstream = flag.equals("SF") || flag.equals("OTH");


// U2R and R2L are impossible over encrypted web or DNS connections
           if (isEncryptedWeb && isCleanOrMidstream) {
               if (classification.equals("U2R") || classification.equals("R2L")) {
                   classification = "normal";
               }
           }

// DNS queries are never R2L or U2R
           if (isDNS && (classification.equals("U2R") || classification.equals("R2L"))) {
               classification = "normal";
           }

// DoS over single low-count SF connection is impossible
           if (flag.equals("SF") && classification.equals("DoS")) {
               int rawCount = (int)(normalized[22] * 511);
               if (rawCount <= 3) {
                   classification = "normal";
               }
           }

           AnomalyDetector.AnomalyResult anomaly = AnomalyDetector.detect(rawEngineered, srcIp,dstIp, service, flag,classification);

           String anomalyTag = anomaly.isAnomaly() ? "⚠ ANOMALY" : "  normal ";
           System.out.printf("[%s] %-15s -> %-15s port:%d -> port:%d svc=%-10s flag=%-4s class=%-6s autoencoder=%s (err=%.4f)%n ",
                   java.time.LocalTime.now().toString().substring(0,8),
                   srcIp,dstIp,srcPort, dstPort,service, flag, classification, anomalyTag, anomaly.error);

       }catch(Exception ex1){
           System.out.println("[LiveDetection] Error: " + ex1.getMessage());
       }
        }//end analyze

    // Starts background thread that classifies idle connections
    public static void startTimeoutMonitor() {

        Thread timeoutThread = new Thread(() -> {

            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(5000);

                    List<ConnectionTracker.ConnectionState> idle =
                            NetworkCapture.tracker.getIdleConnections(10000);

                    for (ConnectionTracker.ConnectionState state : idle) {

                        state.finalFlag = NetworkCapture.tracker.computeFinalFlag(state);

                        // In startTimeoutMonitor(), before classify:
                        if (NetworkCapture.tracker.getCount(state.dstIp) == 0) {
                            // Window expired — features would be unreliable, skip
                            NetworkCapture.tracker.removeRecordedConnection(
                                    state.srcIp, state.srcPort,
                                    state.dstIp, state.dstPort, state.protocol);
                            continue;
                        }

                        double[] features =
                                NetworkCapture.buildFeatureVector(
                                        state.srcIp,
                                        state.dstIp,
                                        state.protocol,
                                        state.srcPort,
                                        state.dstPort,
                                        state.finalFlag,
                                        state.service,
                                        state);

                        analyze(
                                features,
                                state.srcIp,
                                state.dstIp,
                                state.srcPort,
                                state.dstPort,
                                state.service,
                                state.finalFlag);

                        NetworkCapture.tracker.removeRecordedConnection(
                                state.srcIp,
                                state.srcPort,
                                state.dstIp,
                                state.dstPort,
                                state.protocol);
                    }

                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });

        timeoutThread.setDaemon(true);
        timeoutThread.start();
    }
}


