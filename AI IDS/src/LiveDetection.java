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
                                    String service, String flag){

       if(!initialized){
           System.out.println("[LiveDetection] Not initialised — call initialise() first.");
           return;
       }
       try {
           double[] normalized= Preprocessor.normalizeRow(rawEngineered);

           AnomalyDetector.AnomalyResult anomaly = AnomalyDetector.detect(normalized);

           String classification = ClassifierEngine.classify(classifier,rawEngineered,instancesStructure);

           String anomalyTag = anomaly.isAnomaly() ? "⚠ ANOMALY" : "  normal ";
           System.out.printf("[%s] %-15s -> %-15s svc=%-10s flag=%-4s class=%-6s autoencoder=%s (err=%.4f)%n ",
                   java.time.LocalTime.now().toString().substring(0,8),
                   srcIp,dstIp,service, flag, classification, anomalyTag, anomaly.error);

       }catch(Exception ex1){
           System.out.println("[LiveDetection] Error: " + ex1.getMessage());
       }
        }//end analyze

}
