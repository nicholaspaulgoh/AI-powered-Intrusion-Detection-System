import java.io.*;

public class AnomalyDetector {

    // Path to your Python executable inside the venv
    private static final String PYTHON_PATH =
            "C:\\Users\\SAUS\\Documents\\AI-powered-Intrusion-Detection-System\\" +
                    "AI_IDS_Autoencoder\\.venv\\Scripts\\python.exe";

    // Path to detect_anomaly.py
    private static final String SCRIPT_PATH =
            "C:\\Users\\SAUS\\Documents\\AI-powered-Intrusion-Detection-System\\" +
                    "AI_IDS_Autoencoder\\detect_anomaly.py";


    public static class AnomalyResult{
        public final String verdict; // "normal" or "anomaly"
        public final double error;

        public AnomalyResult(String verdict, double error){
            this.verdict=verdict;
            this.error=error;

        }//end constructor

        public boolean isAnomaly(){
            return verdict.equals("anomaly");
        }//end isAnomaly

        @Override
        public String toString(){
            return String.format("%s (error=%.6f)", verdict, error);

        }//end toString
    }//end AnomalyDetector

    /*
     * Calls detect_anomaly.py with the 46 engineered features.
     * Features must be in the same order as Java's engineerFeatures()
     * and must NOT yet be normalised — Python handles normalisation internally.
     *
     * @param features double[46] — raw engineered feature vector
     * @return AnomalyResult with verdict and reconstruction error
     */

    public static AnomalyResult detect(double[] features) throws Exception{

        if(features.length != 46){
            throw new IllegalArgumentException("Expected 46 features, got :" + features.length);
        }

        // --- Build the command ---
        // ProcessBuilder takes a list: ["python.exe", "script.py", "f0", "f1", ...]

        String[] command =new String[48]; //python + script name + 46 features
        command[0] = PYTHON_PATH;
        command[1]= SCRIPT_PATH;

        for(int i=0; i<features.length; i++){
            command[i+2] = String.valueOf(features[i]);
        }

        // process is basically a program
        ProcessBuilder pb = new ProcessBuilder(command);
        // send this to python terminal : python detect_anomaly.py 0 1 0 0 181 5450 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 8 8 0 0 0 0 1 0 0 9 9 1 0 0.11 0 0 0 0 0 181 0 0 0 0

        // Merge stderr into stdout so Python warnings don't block the pipe
        // (TF warnings go to stderr — without this they can cause deadlock)
        pb.redirectErrorStream(true);

        // --- Start the process ---
        Process process = pb.start();

        // --- Read stdout ---
        // Python prints one line: "verdict|error" e.g. "anomaly|0.023456"
        BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));

        String line;
        String resultLine =null;

        while((line=br.readLine()) != null){
            // Skip any TF warning lines, grab the verdict line
            if(line.startsWith("normal") || line.startsWith("anomaly") || line.startsWith("ERROR")){
                resultLine = line;
            }
        }

        process.waitFor();

        if(resultLine==null){
           throw new RuntimeException("No output from detect_anomaly.py");
        }

        if(resultLine.startsWith("ERROR")){
            throw new RuntimeException("Python error: " + resultLine);
        }

        // Split "anomaly|0.023456" into ["anomaly", "0.023456"]
        String[] parts=resultLine.split("\\|");

        if (parts.length != 2) {
            throw new RuntimeException("Unexpected output format: " + resultLine);
        }

        String verdict= parts[0].trim();
        double error = Double.parseDouble(parts[1].trim());

        return new AnomalyResult(verdict,error);



    }//end detect

    public static void  smokeTest( double[] featureVector){

        try{
            AnomalyResult result= detect(featureVector);
            System.out.println("Verdict: " + result.verdict);
            System.out.printf("\nReconstruction Error: %.6f%n", result.error);
            System.out.println("is Anomaly? -> " + result.isAnomaly());


        }catch(Exception ex1){
            System.out.println("Smoke test failed: " + ex1.getMessage());
        }
    }

}
