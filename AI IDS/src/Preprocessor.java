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
        serviceMap.put("dns", 4.0);
        serviceMap.put("ftp_data", 5.0);
        serviceMap.put("other", 6.0);
        serviceMap.put("private", 7.0);
        serviceMap.put("http_443", 8.0);
        serviceMap.put("domain_u", 9.0);

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

        features[2] = serviceMap.getOrDefault(values[2].trim(), 6.0);

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

    public static void main(String[] args){
        String filepath="C:\\Users\\SAUS\\Documents\\AI-powered-Intrusion-Detection-System\\data\\KDDTrain+.txt";
        ArrayList<double[]> dataset = loadDataset(filepath);

        int i=0;
        while(i !=6){
            System.out.print("Row " + i +": [ ");
            for(int j=0; j<dataset.get(i).length; j++){
                System.out.print(dataset.get(i)[j]);

                if(j != dataset.get(i).length -1){
                    System.out.print(", ");
                }else{
                    System.out.print(" ]");
                }

            }
            System.out.println();
            i++;
        }
    }

}
