import weka.core.*;
import java.util.*;

public class DataLoader{

    public static Instances buildInstances(ArrayList<double[]>normalized, ArrayList<String> labels, String datasetName){


        ArrayList<Attribute>attributes = new ArrayList<>();

        String[] featureNames = {
                "duration", "protocol_type", "service", "flag",
                "src_bytes", "dst_bytes", "land", "wrong_fragment",
                "urgent", "hot", "num_failed_logins", "logged_in",
                "num_compromised", "root_shell", "su_attempted",
                "num_root", "num_file_creations", "num_shells",
                "num_access_files", "num_outbound_cmds", "is_hot_login",
                "is_guest_login", "count", "srv_count", "serror_rate",
                "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
                "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
                "dst_host_count", "dst_host_srv_count",
                "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
                "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
                "dst_host_serror_rate", "dst_host_srv_serror_rate",
                "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
        };

        for(String name : featureNames)			//uploading the attributes(columns)
            attributes.add(new Attribute(name));

        ArrayList<String> classValues = new ArrayList<>();	//then our model needs a target column (column that holds the answer) -> attack classes (classes are the categories)
        classValues.add("normal");	//0
        classValues.add("DoS");		//1
        classValues.add("Probe");	//2
        classValues.add("R2L");		//3
        classValues.add("U2R");		//4

        Attribute classAttribute = new Attribute("attack_category", classValues); // “This column is called attack_category and it can only contain: normal, DoS, Probe, R2L, U2R”

        attributes.add(classAttribute);	//adds the attack categories as column 42

        Instances instances = new Instances(datasetName, attributes, normalized.size());	//Instances is like the excel sheet, input a name, columns (42 in this case) and how many rows
        instances.setClassIndex(instances.numAttributes()-1); 			//Tell Weka Which Column is the Label. numAttribute=42 here, but because index starts at 0 so -1

        //Now we add each row


        for(int i=0; i<normalized.size(); i++){
            double[] featureRow = normalized.get(i);

            String label = labels.get(i);


            String category=Preprocessor.mapCategory(label); ////Convert Attack Name → Category

            double[] instanceValues = new double[42]; //42 values
            System.arraycopy(featureRow,0,instanceValues,0,41);	 //last row (42) for attack label

									/*
										featureRow (Source): The original array holding your data.
										0 (Source Position): Start reading from the very beginning (index 0) of the source array.
										instanceValues (Destination): The new target array where the data will be pasted.
										0 (Destination Position): Start writing at the very beginning (index 0) of the target array.
										41 (Length): Copy exactly 41 individual elements.
									*/

            instanceValues[41]=classAttribute.indexOfValue(category); //“For this row, the answer is DoS → store 1 in column 42”

            DenseInstance instance = new DenseInstance(1.0, instanceValues); //1.0= weight 100% (standard importance), DenseInstance means an instance (a row) with no missing data

            instance.setDataset(instances);	//Link the row to the dataset so it understands the columns
            instances.add(instance);	//add each row
        }//end loop

        System.out.println("Instances built: " + instances.numInstances());
        System.out.println("Attributes added: " + instances.numAttributes());
        System.out.println("Class Attribute: " + instances.classAttribute().name());

        return instances;
    }//end buildInstances

}//end class