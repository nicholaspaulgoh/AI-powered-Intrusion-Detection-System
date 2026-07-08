//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
import weka.core.*;
import weka.classifiers.bayes.*;
import weka.classifiers.trees.*;
import weka.classifiers.meta.*;
import java.util.*;

public class Main{

    public static void main(String[] args)throws Exception {

        String trainPath = "C:\\Users\\SAUS\\Documents\\AI-powered-Intrusion-Detection-System\\data\\KDDTrain+.txt";

        String testPath = "C:\\Users\\SAUS\\Documents\\AI-powered-Intrusion-Detection-System\\data\\KDDTest+.txt";

        String binaryModelPath = "C:\\Users\\SAUS\\Documents\\AI-powered-Intrusion-Detection-System\\models\\binary_rf.model";
        String multiModelPath  = "C:\\Users\\SAUS\\Documents\\AI-powered-Intrusion-Detection-System\\models\\multiclass_csc_rf.model";

        System.out.println("====================================================");
        System.out.println("          AI-Powered IDS — Training Pipeline        ");
        System.out.println("====================================================\n");

        System.out.println("[1] Loading and preprocessing training data...");
        ArrayList<String> trainLabel = new ArrayList<>();
        ArrayList<double[]> trainData = Preprocessor.processRow(trainPath, trainLabel);

        Preprocessor.computeMaxMin(trainData);
        Preprocessor.normalize(trainData);  //normalized

        System.out.println("\n[2a] Building Weka dataset...");
        Instances instances = DataLoader.buildInstances(trainData, trainLabel, "NSL-KDDTrain+");

        System.out.println("\n[2b] Balancing Training Data with SMOTE");
        Instances balancedInstances = ClassifierEngine.oversampleMinorityClasses(instances);

        /*
        J48 tree = new J48();
        tree.setConfidenceFactor(0.25f); //this is for prunning -> 0.25 is the default *0.1 is aggressive prunning
        tree.setMinNumObj(2); //Don't create leaves with fewer than 2 training examples.

        ClassifierEngine.evaluate(tree, "J48 Decision Tree", balancedInstances );


         */
        System.out.println("\n[2c] Building binary instances for Stage 1...");
        Instances binaryInstances = ClassifierEngine.buildBinaryInstances(balancedInstances);

        System.out.println("\n[2d] Training Stage 1 — Binary Random Forest...");
        CostSensitiveClassifier binaryCSCRF = ClassifierEngine.buildCostSensitiveBinaryRF(binaryInstances);
        ClassifierEngine.evaluate(binaryCSCRF, "Stage 1 Binary CSC-RF", binaryInstances);
        //before we did 10-fold cross validation to find the best model (90% train 10% test), now that we have identified the best model, we use all the training data
        binaryCSCRF.buildClassifier(binaryInstances);
        ClassifierEngine.saveModel(binaryCSCRF, binaryModelPath);

        System.out.println("\n[2e] Training Stage 2 — Cost-Sensitive Multi-class RF...");
        CostSensitiveClassifier cscRF = ClassifierEngine.buildCostSensitiveClassifier(balancedInstances);
        ClassifierEngine.evaluate(cscRF, "Stage 2 Multi-class CSC-RF", balancedInstances);
        //before we did 10-fold cross validation to find the best model (90% train 10% test), now that we have identified the best model, we use all the training data
        cscRF.buildClassifier(balancedInstances);
        ClassifierEngine.saveModel(cscRF, multiModelPath);

        /*
        NaiveBayes nb = new NaiveBayes();
        ClassifierEngine.evaluate(nb, "Naive Bayes", balancedInstances);
    */

        System.out.println("\n[4] Testing saved models...");
        CostSensitiveClassifier loadedBinary = (CostSensitiveClassifier) ClassifierEngine.loadModel(binaryModelPath);
        CostSensitiveClassifier loadedMulti = (CostSensitiveClassifier) ClassifierEngine.loadModel(multiModelPath);




// Classify the first row of training data as a smoke test ("Does the model load correctly and produce a prediction?" *not measuring accuracy)
        String prediction = ClassifierEngine.classifyTwoStage(
                loadedBinary, loadedMulti,
                trainData.get(0),
                binaryInstances, balancedInstances
        );
        System.out.println("Smoke test prediction on row 0: " + prediction);
        System.out.println("Attack Category: " + Preprocessor.mapCategory(trainLabel.get(0)));



        System.out.println("\n====================Training Pipeline Complete=========================================");

        System.out.println("\n[5] Testing test set evaluation...");
        TrafficInput.startCSVSimulation(
                testPath, loadedBinary, loadedMulti,
                binaryInstances, balancedInstances
        );



    }//end main method
}//end Main class