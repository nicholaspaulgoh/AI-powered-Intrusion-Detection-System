import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;

public class combinedExamples{
    public static void main(String [] args){

        String filePath="C:\\Users\\SAUS\\Documents\\AI-powered-Intrusion-Detection-System\\data\\KDDTrain+.txt";
        String line;

        ArrayList<String[]> dataset = new ArrayList<>();
        HashMap<String,Integer> labelCounts = new HashMap<>();
        try{
            BufferedReader br = new BufferedReader (new FileReader(filePath));


            while((line=br.readLine()) != null){
                String[] values = line.split(",");

                dataset.add(values); //dataset(0): [values[0], values[1], values[2]....]

                String label = values[41];

                if(labelCounts.containsKey(label)){
                    labelCounts.put(label, labelCounts.get(label)+1);
                }else{
                    labelCounts.put(label,1);
                }//end if-else
            }//End while loop
            br.close();
        }catch(Exception e){
            System.out.println(e.getMessage());
        }
        System.out.println("Rows: " + dataset.size());
        System.out.println("Row 0 protocol: " + dataset.get(0)[1]); //First array of "values" second index

        for(int i =0; i<3; i++){
            System.out.println("Row: " + i +" " + "Label: " + dataset.get(i)[41]);
        }

        System.out.println("\nLabel Distribution: ");

        //enhanced for loop/ for-each loop
        //for (type variable : collection) so for every item in the collection store in the variable ( in this case "normal","neptune"..., store in label)
        for(String label : labelCounts.keySet()){   //keySet() = give all the keys in the hashmap ex [normal, neptune, smurf]
            System.out.println(label +": " + labelCounts.get(label));
        }//end for loop
    }
}

//.keySet(): return the keys
//.values(): return the values
//.entrySet(): return both key and values ex. (neptune,5)