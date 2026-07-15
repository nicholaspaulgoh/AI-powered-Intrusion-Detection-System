import java.io.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class AnomalyDetector {
    private static final String FLASK_URL ="http://localhost:5000/detect";
    private static final String HEALTH_URL = "http://localhost:5000/health";

    //Create one client to prevent waste
    //connectTimeout : "If you cannot establish a connection within 5 seconds, stop trying and throw an exception."
    //prevents it from trying to connect forever
    //Duration.ofSeconds : instead of writing 5000
    private static final HttpClient client = HttpClient.newBuilder()
                                                         .connectTimeout(Duration.ofSeconds(5))
                                                         .build();


    public static class AnomalyResult{
        public final String verdict;
        public final double error;

        public AnomalyResult(String verdict, double error){
            this.verdict=verdict;
            this.error=error;


        }//end constructor

        public boolean isAnomaly(){
            return verdict.equals("anomaly");
        }

        @Override
        public String toString(){
            return String.format("%s (error=%.6f)", verdict,error);
        }
    }//end class Anomaly Result

    public static AnomalyResult detect(double[] features, String srcIp, String dstIp,
                                       String service, String flag, String classification) throws Exception{

        if(features.length !=46){
            throw new IllegalArgumentException("Expected 46 features, got " + features.length);
        }
        //Preparing the data
        // Build JSON body manually — no external library needed
        //String Builder is use for performance, concatenation of new String will
        // create a new memory every time it runs ->unnecessary memory allocation
        StringBuilder sb = new StringBuilder();

        sb.append("{");
        sb.append("\"features\":[");

        for(int i=0; i<features.length;i++){
            sb.append(features[i]);

            if(i<features.length-1)
                sb.append(",");
        }
        sb.append("],");
        sb.append("\"srcIp\":\"").append(srcIp).append("\",");
        sb.append("\"dstIp\":\"").append(dstIp).append("\",");
        sb.append("\"service\":\"").append(service).append("\",");
        sb.append("\"flag\":\"").append(flag).append("\",");
        sb.append("\"classification\":\"").append(classification).append("\"");
        sb.append("}");

        String json=sb.toString();

        //Preparing the request (like a package/ envelope for the data
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(FLASK_URL)) //where does the request go?
                .timeout(Duration.ofSeconds(10))//after 10 seconds java will throw an error -> too long
                .header("Content-Type","application/json") //like a packaging label
                .POST(HttpRequest.BodyPublishers.ofString(json)) //BodyPublisher -> HTTP client expects something capable of publishing (streaming) the request body.
                .build();

        //Sending the request and storing the response in HttpResponse<String>
        HttpResponse<String> response =client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200){
            throw new RuntimeException("Flask returned HTTP " +
                    response.statusCode() + ": " + response.body());
        }

        //extracting the values from the JSON Response
        String body=response.body(); //{"verdict":"normal","error":0.001234}
        String verdict = extractJsonString(body,"verdict");
        double error = extractJsonDouble(body,"error");
        return new AnomalyResult(verdict,error);
    }//end detect

    private static AnomalyResult detect(double[]featureVector) throws Exception{
        return detect(featureVector, "?", "?", "?", "?", "unknown");
    }
    public static boolean isFlaskRunning(){

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(HEALTH_URL))
                    .timeout(Duration.ofSeconds(3))
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            return response.statusCode() == 200;
        }catch(Exception ex1){
            return false;
        }
    }

    public static void  smokeTest(double[] featureVector){

            if (!isFlaskRunning()) {
                System.out.println("Flask is not running at " + FLASK_URL);
                System.out.println("Start it with: python flask_server.py");
                return;
            }

            try{
                AnomalyResult result = detect(featureVector);
                System.out.println("Verdict:             " + result.verdict);
                System.out.printf ("Reconstruction error: %.6f%n", result.error);
                System.out.println("Is anomaly:          " + result.isAnomaly());
                } catch (Exception e) {
                System.out.println("Smoke test failed: " + e.getMessage());
                }

    }
    private static String extractJsonString(String json, String key){
        String search ="\"" + key + "\":\""; //end "verdict":"
        int start =json.indexOf(search) +search.length(); //12
        int end=json.indexOf("\"",start); //search for " starting from the start point
        return json.substring(start,end); //cuts the result ex normal, end is exclusive
    }//end extractJsonString

    //reminder: numbers in json don't have quotation marks
    private static double extractJsonDouble(String json,String key){
        String search = "\""+ key + "\":";
        int start =json.indexOf(search) + search.length();
        int commaEnd = json.indexOf(",",start);
        int braceEnd =json.indexOf("}", start);

        //{
        //    "error":0.001234,
        //    "threshold":0.005
        //}
        //there would be a comma hence:
        int end = (commaEnd ==-1)? braceEnd: Math.min(commaEnd,braceEnd);
        String val = json.substring(start,end).replace(",", "").trim();
        return Double.parseDouble(val);
    }
}//end class AnomalyDetector
