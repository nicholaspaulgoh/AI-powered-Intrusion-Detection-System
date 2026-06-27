//Testing KDDTest+ (Test Set)

import java.util.*;
import java.io.*;
import weka.classifiers.*;
import weka.core.*;



public class TrafficInput {

    static int correctCount=0;
    static Map<String, Integer> mapCategoryStats = new HashMap<>();

    public static void startCSVSimulation(String filePath, AbstractClassifier model, Instances dataStructure ) throws Exception {

        //Reset to avoid accumulation
        correctCount=0;
        mapCategoryStats.clear();

        System.out.println("Starting CSV simulation from: " + filePath);

        ArrayList<double[]> features = new ArrayList<>();
        List<String> attackLabels = new ArrayList<>();
        List<String> predictions = new ArrayList<>();

        int malformed=0;

        //Preprocessing
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;

            while ((line = br.readLine()) != null) {
                String[] values = line.split(",");

                if (values.length < 42){
                    malformed++;
                    continue;
                }

                attackLabels.add(Preprocessor.mapCategory(values[41].trim()));

                features.add(Preprocessor.getFeatures(values));


            }//end while

            //Normalizing
            System.out.println("Normalizing");
            Preprocessor.normalize(features);

            //Predicting
            System.out.println("Predicting");
            for (double[] row : features) {
                predictions.add(ClassifierEngine.classify(model, row, dataStructure));
            }//end for - Predicting

            //Output per row
            for (int i = 0; i < features.size(); i++) {
                String currentAttackLabel = attackLabels.get(i);
                String currentPrediction = predictions.get(i);
                String currentOutcome = isCorrect(currentAttackLabel, currentPrediction);


                System.out.printf("Row %d     actual attack label: %s -> prediction: %s %s %n"
                        , i, currentAttackLabel, currentPrediction, currentOutcome);

                if(currentOutcome.equals("✓ Correct")){
                    correctCount++;
                    mapCategoryStats.merge(currentAttackLabel, 1, Integer::sum);
                }
                Thread.sleep(5);

            }//end for - Output per row

            //Summary
            System.out.println("=====================================================================");
            System.out.println("                      Test Set Result Summary                        ");
            System.out.println("=====================================================================");

            System.out.println("Total rows loaded: " + features.size());
            System.out.println("Total rows skipped: " + malformed);

            double accuracy = (double)(correctCount *100.0/features.size());
            System.out.printf("%nOverall Accuracy: %d / %d (%.2f%%)%n", correctCount, features.size(), accuracy);


            System.out.println("\nDetection rate per category");



            mapCategoryStats.forEach((key,value) ->{
                System.out.printf("%-8s %5d / %5d  (%.2f%%)%n",
                        key,value, Collections.frequency(attackLabels,key), value*100.0/Collections.frequency(attackLabels, key));
            });

            System.out.println("\n\n======================= Test Set Evaluation Complete =============================");


        }catch(Exception ex1){
            System.out.println(ex1.getMessage());
    }//end catch
    }//end startCSV simulation

    public static String isCorrect(String actual, String prediction){

        return actual.equals(prediction)?  "✓ Correct" : "✗ Incorrect";


    }//end isCorrect
}// end TrafficInput
