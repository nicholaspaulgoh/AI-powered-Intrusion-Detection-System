//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
import weka.core.*;
import weka.classifiers.bayes.*;
import weka.classifiers.trees.*;
import java.util.*;

public class Main{

    public static void main(String[] args)throws Exception{

        String trainPath="C:\\Users\\SAUS\\Documents\\AI-powered-Intrusion-Detection-System\\data\\KDDTrain+.txt";
        String modelPath="C:\\Users\\SAUS\\Documents\\AI-powered-Intrusion-Detection-System\\models\\random_forest.model";
        String testPath="C:\\Users\\SAUS\\Documents\\AI-powered-Intrusion-Detection-System\\data\\KDDTest+.txt";

        System.out.println("====================================================");
        System.out.println("          AI-Powered IDS — Training Pipeline        ");
        System.out.println("====================================================\n");

        System.out.println("[1] Loading and preprocessing training data...");
        ArrayList<String> trainLabel = new ArrayList<>();
        ArrayList<double[]> trainData = Preprocessor.processRow(trainPath, trainLabel);

        Preprocessor.computeMaxMin(trainData);
        Preprocessor.normalize(trainData);  //normalized

        System.out.println("\n[2] Building Weka dataset...");
        Instances instances= DataLoader.buildInstances(trainData, trainLabel, "NSL-KDDTrain+");

        J48 tree = new J48();
        tree.setConfidenceFactor(0.25f); //this is for prunning -> 0.25 is the default *0.1 is aggressive prunning
        tree.setMinNumObj(2); //Don't create leaves with fewer than 2 training examples.

        ClassifierEngine.evaluate(tree, "J48 Decision Tree", instances );

        RandomForest rf = new RandomForest();
        rf.setNumIterations(100); //100 trees
        rf.setNumFeatures(0);	//How many features each tree is allowed to consider at every split. so about 6 per tree, 0 means default setting (41^(0.5))
        rf.setSeed(1);

        ClassifierEngine.evaluate(rf, "Random Forest", instances);

        NaiveBayes nb = new NaiveBayes();
        ClassifierEngine.evaluate(nb, "Naive Bayes", instances);

        System.out.println("\n[3] Saving best model...");
//before we did 10-fold cross validation to find the best model (90% train 10% test), now that we have identified the best model, we use all the training data
        rf.buildClassifier(instances);
        ClassifierEngine.saveModel(rf, modelPath);

        System.out.println("\n[4] Testing saved model...");
        RandomForest loadedModel_rf = (RandomForest) ClassifierEngine.loadModel(modelPath); //not every AbstractClassifier is rf

// Classify the first row of training data as a smoke test ("Does the model load correctly and produce a prediction?" *not measuring accuracy)
        String prediction = ClassifierEngine.classify(loadedModel_rf, trainData.get(0), instances);

        System.out.println("Smoke test prediction on row 0: " + prediction);
        System.out.println("Attack Category: " + Preprocessor.mapCategory(trainLabel.get(0)));

        System.out.println("\n====================Training Pipeline Complete=========================================");

        System.out.println("\n[5] Testing test set evaluation...");
        TrafficInput.startCSVSimulation(testPath,loadedModel_rf,instances);



    }//end main method
}//end Main class