import java.util.*;
import java.io.*;

public class Preprocessor{

    static HashMap<String, Double>protocolMap = new HashMap<>();
    static HashMap<String, Double>serviceMap = new HashMap<>();
    static HashMap<String, Double>flagMap = new HashMap<>();

    static HashMap<String,String>attackMap = new HashMap<>();

    static double[] trainMax;
    static double[] trainMin;

    static ArrayList<String> trainLabels = new ArrayList<>();
    static ArrayList<String> testLabels = new ArrayList<>();

    static{

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
        serviceMap.put("irc", 57.0);
        serviceMap.put("x11", 58.0);
        serviceMap.put("z39_50", 59.0);
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

        attackMap.put("normal", "normal");

        for(String attack : new String []{"neptune","smurf","pod","teardrop","land","back","apache2","udpstorm","processtable","mailbomb"})
            attackMap.put( attack, "DoS");

        for(String attack : new String []{"ipsweep","portsweep","nmap","satan","mscan","saint"})
            attackMap.put( attack, "Probe");

        for(String attack : new String []{ "guess_passwd","ftp_write","imap","phf","multihop","warezmaster","warezclient","spy","xlock","xsnoop","snmpgetattack","named","sendmail","httptunnel","worm","snmpguess"})
            attackMap.put( attack, "R2L");

        for(String attack : new String []{"buffer_overflow","rootkit","loadmodule","perl", "xterm","ps","sqlattack"})
            attackMap.put(attack, "U2R");
    }

    public static String mapCategory(String attack){
        return attackMap.getOrDefault(attack, "unknown");

    }



    public static double safeParseDouble(String value){

        try{
            return Double.parseDouble(value.trim());
        }catch(Exception ex1){
            return Double.NaN;
        }

    }

    public static double[] getFeatures(String[] dataset){

        int datasetFeatures =41;
        double[] features = new double[datasetFeatures];

        features[0] = safeParseDouble(dataset[0]);

        features[1] = protocolMap.getOrDefault(dataset[1].trim(),-1.0); //decided not to put Double.NaN to prevent data loss
        features[2] = serviceMap.getOrDefault(dataset[2].trim().toLowerCase(), 6.0); //6.0==other
        features[3] = flagMap.getOrDefault(dataset[3].trim(), -1.0);

        for(int i =4; i<41; i++){ //we only want 41 rows, KDDTrain+.txt has 43 rows in total

            features[i] = safeParseDouble(dataset[i]);
        }//end for


        return features;



    }//end getFeatures

    public static void computeMaxMin(ArrayList <double[]> processed){

        int featuresNum=41;
        trainMax= new double[featuresNum];
        trainMin = new double[featuresNum];

        for(int i=0; i<featuresNum; i++){
            trainMax[i] = Double.NEGATIVE_INFINITY;
            trainMin[i] = Double.POSITIVE_INFINITY;
        }

        for(double[]row :processed){	//Go through each row: 1st iteration= 1st row[0.0,1.0,..] 2nd i = 2nd row[0.0,2.0...]
            for(int i =0; i<featuresNum; i++){		// Then check each feature whether it is larger or smaller, if it is then store
                if(row[i]>trainMax[i]) trainMax[i]=row[i];	//Then go to second row and start the whole process again
                if(row[i]<trainMin[i]) trainMin[i]=row[i];	//This is to get the max and min of each feature
            }
        }
        System.out.println("\n[2] Min/Max computed from: " + processed.size() + " rows");
        System.out.println("src_bytes ranges from: " + trainMin[4]+ " to " + trainMax[4]);
        System.out.println("duration ranges from: " + trainMin[0]+ " to " + trainMax[0]);
        System.out.println("count ranges from: " + trainMin[22]+ " to " + trainMax[22]);

    }

    public static void normalize(ArrayList <double[]> processed){

        for(double[] row :processed){
            for(int i=0; i<41; i++){
                double range=trainMax[i]-trainMin[i];

                if(range==0){		//all values identical, example feature 1 =[0,0,0,0,0] so max =0, min=0 range =0
                    row[i]=0.0;	//row[i] -min[i]/ 0 is wrong, so directly give it the value of 0.0
                }else{
                    row[i]=Math.min((row[i]-trainMin[i])/range,1.0);

                    if (row[i]<0){
                        row[i]=0.0;

                    }

                }//end else
            }//end inner loop
        }

        System.out.println("Total rows normalize: " + processed.size());
    }// end normalize



    public static ArrayList<double[]> processRow(String filepath, ArrayList<String>labels){

        String line;
        String[] dataset;
        ArrayList<double[]> processed = new ArrayList<>();
        int malformedRow=0;
        int corruptedRow=0;

        try(BufferedReader br = new BufferedReader(new FileReader(filepath))){

            while((line=br.readLine()) != null){

                dataset = line.split(",");


                if(dataset.length <42){ //41 features + label
                    malformedRow++;
                    System.out.println("malformed row detected: row " + line);
                    continue;
                }//end if


                double[]features =getFeatures(dataset);

                boolean skipRow=false;

                for(double f : features){
                    if(Double.isNaN(f)){
                        corruptedRow++;
                        skipRow=true;
                        break;
                    }
                }

                if(skipRow){
                    System.out.println("corrupted row detected: row  " + line);
                    continue;
                }

                labels.add(dataset[41].trim());

                processed.add(features);
            }//end while

            System.out.println("Total processed rows: " + processed.size());
            System.out.println("Total malformed rows: " + malformedRow);
            System.out.println("Total corrupted rows: " + corruptedRow);
        }catch(Exception ex1){
            System.out.println("Error: " + ex1.getMessage());
        }
        return processed;
    }//end processRow


    public static void main(String [] args){

        String trainPath="C:\\Users\\SAUS\\Documents\\AI-powered-Intrusion-Detection-System\\data\\KDDTrain+.txt";
        String testPath="C:\\Users\\SAUS\\Documents\\AI-powered-Intrusion-Detection-System\\data\\KDDTest+.txt";



        System.out.println("========================================");
        System.out.println("  NSL-KDD PREPROCESSING PIPELINE");
        System.out.println("========================================");
        System.out.println("\n[1] Training Set: ");
        System.out.println();
        ArrayList<double[]> processed_Train = processRow(trainPath,trainLabels);

        System.out.println();
        computeMaxMin(processed_Train);

        System.out.println("\n[3] Normalization - Training Set: ");
        normalize(processed_Train);

        System.out.println("\n[4] Loading and Normalising - Test Set: ");
        ArrayList<double[]> processed_Test = processRow(testPath,testLabels);
        normalize(processed_Test);

        System.out.println("\n[5] Verification first 3 training rows: ");
        for(int i=0; i<3;i++){
            System.out.println("Row " + i+"  label: " + trainLabels.get(i) +"  Category: " + mapCategory(trainLabels.get(i)));
            System.out.println("features[0-5]: ");
            for(int j=0; j<6;j++){
                System.out.print(processed_Train.get(i)[j] +" ");
            }//end inner loop
            System.out.println();
        }//end outer loop



        System.out.println("\n[6]  Range check — all values should be 0.0 to 1.0: ");
        int outOfRange=0;


        for( double[] row : processed_Train){
            for(double feature :row){
                if( feature<0.0 || feature>1.0) outOfRange++;
            }//end inner loop
        }//end outer loop

        System.out.println("Training set out-of-range values: " + outOfRange);
        outOfRange=0;
        for(double[] row : processed_Test){
            for(double feature :row){
                if( feature<0.0 || feature>1.0) outOfRange++;
            }//end inner loop
        }//end outer loop

        System.out.println("Test set out-of-range values: " + outOfRange);


        System.out.println("\n[7] Training set class distribution:");
        HashMap<String, Integer> catCount = new HashMap<>();

        for(String attack : trainLabels){
            String category = mapCategory(attack);
            catCount.put(category, catCount.getOrDefault(category,0)+1);
        }//end loop


        catCount.forEach((key,value) ->{
            double percentage= ((double)value/processed_Train.size())*100;
            System.out.println();
            System.out.printf("%s:\t%d (%.2f%%)%n",key,value,percentage);

        });

        System.out.println("\n========================================");
        System.out.println("  PREPROCESSING COMPLETE");
        System.out.println("  Training rows: " + processed_Train.size());
        System.out.println("  Test rows:     " + processed_Test.size());
        System.out.println("  Ready for Weka classifier");
        System.out.println("========================================");
    }//end main

}//end class

		
		