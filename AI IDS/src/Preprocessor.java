//Note: Machine learning models cannot understand: "tcp","udp"....They only understand numbers.
//so basically: Convert messy network CSV data into clean numeric vectors for AI

import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;


public class Preprocessor {

    static HashMap<String, Double> protocolMap = new HashMap<>();
    static HashMap<String, Double> serviceMap = new HashMap<>();
    static HashMap<String, Double> flagMap = new HashMap<>();

    static {
        protocolMap.put("tcp", 0.0);
        protocolMap.put("udp", 1.0);
        protocolMap.put("icmp", 2.0);

        serviceMap.put("http", 0.0);
        serviceMap.put("ftp", 1.0);
        serviceMap.put("smtp", 2.0);
        serviceMap.put("ssh", 3.0);
        serviceMap.put("domain_u", 4.0);
        serviceMap.put("ftp_data", 5.0);
        serviceMap.put("other", 6.0);
        serviceMap.put("private", 7.0);
        serviceMap.put("http_443", 8.0);
        serviceMap.put("telnet", 9.0);
        serviceMap.put("finger", 10.0);
        serviceMap.put("pop_3", 11.0);
        serviceMap.put("pop_2", 12.0);
        serviceMap.put("imap4", 13.0);
        serviceMap.put("auth", 14.0);
        serviceMap.put("uucp", 15.0);
        serviceMap.put("kshell", 16.0);
        serviceMap.put("klogin", 17.0);
        serviceMap.put("shell", 18.0);
        serviceMap.put("login", 19.0);
        serviceMap.put("exec", 20.0);
        serviceMap.put("remote_job", 21.0);
        serviceMap.put("rje", 22.0);
        serviceMap.put("netbios_ssn", 23.0);
        serviceMap.put("netbios_dgm", 24.0);
        serviceMap.put("netbios_ns", 25.0);
        serviceMap.put("domain", 26.0);
        serviceMap.put("dns", 27.0);
        serviceMap.put("ntp_u", 28.0);
        serviceMap.put("tftp_u", 29.0);
        serviceMap.put("echo", 30.0);
        serviceMap.put("discard", 31.0);
        serviceMap.put("daytime", 32.0);
        serviceMap.put("time", 33.0);
        serviceMap.put("systat", 34.0);
        serviceMap.put("netstat", 35.0);
        serviceMap.put("whois", 36.0);
        serviceMap.put("gopher", 37.0);
        serviceMap.put("printer", 38.0);
        serviceMap.put("nntp", 39.0);
        serviceMap.put("nnsp", 40.0);
        serviceMap.put("bgp", 41.0);
        serviceMap.put("ldap", 42.0);
        serviceMap.put("iso_tsap", 43.0);
        serviceMap.put("csnet_ns", 44.0);
        serviceMap.put("sql_net", 45.0);
        serviceMap.put("sunrpc", 46.0);
        serviceMap.put("vmnet", 47.0);
        serviceMap.put("uucp_path", 48.0);
        serviceMap.put("courier", 49.0);
        serviceMap.put("efs", 50.0);
        serviceMap.put("hostnames", 51.0);
        serviceMap.put("name", 52.0);
        serviceMap.put("link", 53.0);
        serviceMap.put("ctf", 54.0);
        serviceMap.put("supdup", 55.0);
        serviceMap.put("mtp", 56.0);
        serviceMap.put("IRC", 57.0);
        serviceMap.put("X11", 58.0);
        serviceMap.put("Z39_50", 59.0);
        serviceMap.put("eco_i", 60.0);
        serviceMap.put("ecr_i", 61.0);
        serviceMap.put("urh_i", 62.0);
        serviceMap.put("urp_i", 63.0);
        serviceMap.put("red_i", 64.0);
        serviceMap.put("tim_i", 65.0);
        serviceMap.put("pm_dump", 66.0);
        serviceMap.put("harvest", 67.0);
        serviceMap.put("http_2784", 68.0);
        serviceMap.put("http_8001", 69.0);
        serviceMap.put("aol", 70.0);

        flagMap.put("SF", 0.0); // Normal established connection
        flagMap.put("S0", 1.0); // No response — SYN flood indicator
        flagMap.put("REJ", 2.0); // Connection rejected
        flagMap.put("RSTO", 3.0); // Reset by originator
        flagMap.put("RSTR", 4.0); // Reset by responder
        flagMap.put("SH", 5.0); // Originator sent SYN then FIN
        flagMap.put("S1", 6.0);
        flagMap.put("S2", 7.0);
        flagMap.put("S3", 8.0);
        flagMap.put("OTH", 9.0);
        flagMap.put("RSTOS0", 10.0);
    }

    public static double safeParseDouble(String value) {
        try {
            return Double.parseDouble(value.trim());
        } catch (NumberFormatException e) { //Example Double.parseDouble("abc")
            return 0.0;
        }
    }// end safeParseDouble


    //["0","tcp","ftp_data","SF","491",...] (one raw CSV row) >>> [0.0,0.0,5.0,0.0,491.0,...] (numeric feature vector)
    public static double[] processRow(String[] values) {

        double[] features = new double[41]; //so only train AI with input 0-40 (42 is the label >>answer);

        features[0] = safeParseDouble(values[0]); //using safeParseDouble which has trim >> trim not needed

        features[1]= protocolMap.getOrDefault(values[1].trim(),-1.0);
        // if there's a protocol that is not listed in the map it will return -1.0 example "weird_protocol"
        //.get will return null

        features[2] = serviceMap.getOrDefault(values[2].trim(), 6.0); //6.0 =other

        features[3] = flagMap.getOrDefault(values[3].trim(), -1.0);

        for(int i=4; i<features.length;i++){
            features[i]= safeParseDouble(values[i]);
        }
        return features;
    }

    public static ArrayList<double[]> loadDataset (String filepath){

        ArrayList<double[]> processed = new ArrayList<>();

        try{
            BufferedReader br = new BufferedReader (new FileReader(filepath));
            String line;
            int rowNum=0;


            while((line =br.readLine()) != null){
                String[] values = line.split(",");

                for(int i=0; i<values.length;i++){ //removes hidden spaces from EVERY column.
                    values[i]= values[i].trim();

                    /*String name = " John ";
                    name.trim();
                    System.out.println(name);
                    output: " John "
                    hence why reassigning is important so after trimming String it becomes "John"
                     */
                }

                if (values.length <42){ //Corrupted Row like 0,tcp,http can crash the program
                    System.out.println("Skipping malformed row" + rowNum);
                    continue;
                }


                double[] features = processRow(values); //input ["0","tcp","http",...] >> output: [0.0,0.0,0.0,...]
                processed.add(features);

                /*processed
                 |─ row1 features: [0.0,...]
                 ├── row2 features: [0.0,...]
                 ├── row3 features: [0.0,...]
                */

                rowNum++;
            }
                System.out.println("Processed " +processed.size() + " rows successfully");


            br.close();
        }catch (Exception e){
            System.out.println(e.getMessage());
        }
        return processed;
    }

    // normalise all numeric features
    public static void normalise (ArrayList<double[]> dataset) {

        int numFeatures = 41;

        // Step 1 — find min and max for each feature
        double[] min = new double[numFeatures];
        double[] max = new double[numFeatures];

        // Initialise min to very large, max to very small
        for (int i = 0; i < numFeatures; i++) {
            min[i] = Double.MAX_VALUE;
            max[i] = -Double.MAX_VALUE;
        }

        // First pass — scan entire dataset for min/max
        for (double[] row : dataset) {
            for (int i = 0; i < numFeatures; i++) {
                if (row[i] < min[i]) min[i] = row[i];
                if (row[i] > max[i]) max[i] = row[i];
            }
        }

        // Step 2 — normalise every value
        for (double[] row : dataset) {
            for (int i = 0; i < numFeatures; i++) {
                double range = max[i] - min[i];
                if (range == 0) {
                    row[i] = 0.0; // if all values are the same, set to 0
                } else {
                    double normalised = (row[i] - min[i]) / range;
                    row[i] = Math.min(normalised, 1.0);
                }
            }
        }

        System.out.println("Normalisation complete.");
        System.out.println("Sample — feature 4 (src_bytes) range after normalisation:");
        System.out.printf("  First row value: %.10f%n", dataset.get(0)[4]);
    }

    public static void main(String[] args) {
        String filepath = "C:\\Users\\SAUS\\Documents\\AI-powered-Intrusion-Detection-System\\data\\KDDTrain+.txt";
        ArrayList<double[]> dataset = loadDataset(filepath);
        normalise(dataset);

        int i = 0;
        while (i != 6) {
            System.out.print("Row " + i + ": [ ");
            for (int j = 0; j < dataset.get(i).length; j++) {
                System.out.print(dataset.get(i)[j]);

                if (j != dataset.get(i).length - 1) {
                    System.out.print(", ");
                } else {
                    System.out.print(" ]");
                }

            }
            System.out.println();
            i++;
        }


    }
}
