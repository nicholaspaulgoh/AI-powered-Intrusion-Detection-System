import java.io.*;

public class dataReader {
    public static void main( String [] args){

        String filepath="C:\\Users\\SAUS\\Documents\\AI-powered-Intrusion-Detection-System\\data\\KDDTrain+.txt";

        int lineCount=0;

        try{
            BufferedReader br = new BufferedReader(new FileReader(filepath));

            String line;
            while((line= br.readLine()) != null){
               String[] values=line.split(",");

               String label = values[41];

               String duration = values[0];
               String protocolType = values[1];
               String service = values [2];

               if (lineCount<5){
                   System.out.println("====Row " + (lineCount+1) +" ====");
                           System.out.println("Duration: " + duration);
                   System.out.println("Protocol Type: " + protocolType);
                   System.out.println("Service: " + service);
               }
               lineCount++;

            }

            br.close();
        }catch(Exception e){
            System.out.println(e.getMessage());
        }
        System.out.println("\nTotal Rows " + lineCount);
    }
}
