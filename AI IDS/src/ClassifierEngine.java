import weka.classifiers.*;
import weka.classifiers.trees.*;
import weka.classifiers.meta.*;
import weka.filters.Filter;
import weka.filters.supervised.instance.SMOTE;
import weka.core.*;
import java.util.*;
import java.io.*;

public class ClassifierEngine{
    public static Evaluation evaluate(AbstractClassifier classifier, String classifierName, Instances instances)throws Exception{

        System.out.println("============================================");
        System.out.println("Classifier: " + classifierName);
        System.out.println("============================================");

        long startTime=System.currentTimeMillis();

        classifier.buildClassifier(instances);		//Looks at all the training data (features + correct labels) and learns patterns to create a trained model. *for classify() later

        long buildTime=System.currentTimeMillis()-startTime;

        System.out.println("Time taken to build: " + buildTime);

        Evaluation eval = new Evaluation(instances);	//constructor tells the eval object the exact structure of the data it will be evaluating

        Evaluation trainEval = new Evaluation(instances);
        trainEval.evaluateModel(classifier, instances);

//crossValidateModel also trains the classifier so classifier.buildClassifier is not needed for crossValidateModel but actually for classify()
        eval.crossValidateModel(classifier, instances, 10, new Random(1)); //new Random()=mix up your dataset rows -> random order before splitting them into 10 groups. Seed 1 means to lock that shuffle, so 2 is a different shuffle

        System.out.println("--------------Cross Validation Result:--------------------\n");
        System.out.printf("CV Accuracy:	%.4f%%%n", eval.pctCorrect());
        System.out.printf("Training Accuracy:	%.4f%%%n", trainEval.pctCorrect());
        System.out.printf("Overfitting Gap:	%.4f%%%n", (trainEval.pctCorrect() - eval.pctCorrect()));
        System.out.printf("Errors:	%d / %d%n", (int)eval.incorrect(), instances.numInstances());
        System.out.printf("Kappa:	%.4f%n",eval.kappa());

        System.out.println("--------------Per-Class F1-Score:--------------------\n");
        for(int i=0; i<instances.numClasses(); i++){
            String className= instances.classAttribute().value(i);
            double f1 = eval.fMeasure(i);
            double precision = eval.precision(i);
            double recall = eval.recall(i);
            System.out.printf("%-8s	P=%.3f	R=%.3f	F1=%.3f%n", className, precision , recall, f1);
        }//end loop

        System.out.println("--------------Confusion Matrix:--------------------\n");
        System.out.println(eval.toMatrixString());

        return eval;

    }//end evaluate

    public static void saveModel(AbstractClassifier classifier, String filepath)throws Exception{

        File file = new File(filepath);
        file.getParentFile().mkdirs();

        SerializationHelper.write(filepath,classifier);	//This stores the trained model on disk. Example saveModel(classifier, "j48.model"); **RAM → File

        long fileSize = file.length();
        System.out.println("Model saved to: "+filepath);
        System.out.printf("%nFile Size:  %.1f KB%n", (fileSize/1024.0));
    }//end saveModel

    public static AbstractClassifier loadModel(String filepath) throws Exception{

        File file = new File(filepath);

        if(!file.exists()) throw new FileNotFoundException("File not found for filepath: " + filepath);


        AbstractClassifier classifier = (AbstractClassifier)SerializationHelper.read(filepath); //Reads the saved model back into memory. **File -> RAM //SerializationHelper.read() returns a generic java.lang.Object so MUST explicitly cast

        System.out.println("Model loaded from: " + file);
        System.out.println("Classifier: " + classifier.getClass().getSimpleName());
        return classifier;


    }//end loadModel

    private static Instances applySmote(Instances instances, String attackCategoryName, double percentage, int kNeighbors) throws Exception{

        SMOTE smote = new SMOTE();
        int attackIndex = instances.classAttribute().indexOfValue(attackCategoryName);

        if(attackIndex == -1){
            throw new IllegalArgumentException("Unknown attack category: " + attackCategoryName);
        }
        smote.setClassValue(Integer.toString(attackIndex+1)); //Weka's SMOTE filter uses one-based indexing for the class value option
        smote.setPercentage(percentage);
        smote.setNearestNeighbors(kNeighbors);
        smote.setInputFormat(instances); //"This is what the dataset looks like."

        return Filter.useFilter(instances,smote); //runs smote

    }

    public static Instances oversampleMinorityClasses(Instances instances) throws Exception{

        System.out.println("\n====== Class Distribution BEFORE SMOTE ======");
        printClassDistribution(instances);

        System.out.println("\nApplying SMOTE to R2L (900%)...");
        instances = applySmote(instances, "R2L",900.0,12);

        System.out.println("\nApplying SMOTE to U2R (1800%)...");
         instances=applySmote(instances, "U2R", 1800.0,9);

        System.out.println("\n====== Class Distribution AFTER SMOTE ======");
        printClassDistribution(instances);

        return instances;
    }

    private static void printClassDistribution(Instances instances) {

        int[] count=instances.attributeStats(instances.classIndex()).nominalCounts;
        Attribute classAttribute = instances.classAttribute();

        for(int i=0; i<classAttribute.numValues();i++){
            System.out.printf("%s -> %d%n", classAttribute.value(i), count[i]);
        }

        System.out.println("Total: " + instances.numInstances());
    }

    public static CostSensitiveClassifier buildCostSensitiveClassifier(Instances instances) throws Exception{
        CostSensitiveClassifier csc = new CostSensitiveClassifier();

       int numClasses =instances.numClasses(); //normal,DoS,Probe,R2L,U2R
        CostMatrix costMatrix = new CostMatrix(numClasses);
        costMatrix.initialize();

        //Increase readability
        int normalIndex =instances.classAttribute().indexOfValue("normal");
        int dosIndex=instances.classAttribute().indexOfValue("DoS");
        int probeIndex=instances.classAttribute().indexOfValue("Probe");
        int r2lIndex =instances.classAttribute().indexOfValue("R2L");
        int u2rIndex=instances.classAttribute().indexOfValue("U2R");

        //Penalties for missing R2L
        costMatrix.setCell(r2lIndex,normalIndex, 30.0);
        costMatrix.setCell(r2lIndex, dosIndex, 5.0);
        costMatrix.setCell(r2lIndex, probeIndex, 5.0);
        costMatrix.setCell(r2lIndex, u2rIndex, 10.0);

        //Penalties for missing U2L
        costMatrix.setCell(u2rIndex,normalIndex, 40.0);
        costMatrix.setCell(u2rIndex, dosIndex, 10.0);
        costMatrix.setCell(u2rIndex, probeIndex, 10.0);
        costMatrix.setCell(u2rIndex, r2lIndex, 10.0);

        //Penalties for missing DoS
        costMatrix.setCell(dosIndex, normalIndex, 2.0);
        costMatrix.setCell(dosIndex,probeIndex,2.0);
        costMatrix.setCell(dosIndex, r2lIndex, 2.0);
        costMatrix.setCell(dosIndex, u2rIndex,2.0);

        //Penalties for missing probe
        costMatrix.setCell(probeIndex, normalIndex, 3.0);
        costMatrix.setCell(probeIndex,dosIndex,3.0);
        costMatrix.setCell(probeIndex, r2lIndex, 3.0);
        costMatrix.setCell(probeIndex, u2rIndex,3.0);

        //Penalties for misclassifying normal traffic
        costMatrix.setCell(normalIndex, r2lIndex, 1.0);
        costMatrix.setCell(normalIndex, u2rIndex,1.0);
        costMatrix.setCell(normalIndex, dosIndex, 1.0);
        costMatrix.setCell(normalIndex, probeIndex,1.0);

        RandomForest rf = new RandomForest();
        rf.setNumIterations(100);
        rf.setNumFeatures(0); //How many features each tree is allowed to consider at every split. so about 6 per tree, 0 means default setting (41^(0.5))
        rf.setSeed(1);

        csc.setCostMatrix(costMatrix);
        csc.setMinimizeExpectedCost(true);
        csc.setClassifier(rf);


        return csc;
    }
//Suppose a new connection arrives:

    public static String classify(AbstractClassifier classifier, double[] featureVector, Instances dataStructure) throws Exception{

        DenseInstance instance = new DenseInstance(1.0, new double[42]); //41 features + 1 class attribute

        instance.setDataset(dataStructure);//Attach this single row (Instance) to the full dataset structure


        for(int i=0; i<41;i++){
            instance.setValue(i,featureVector[i]); //[feature0, feature1, ..., feature40, 0] **setValue() belongs to a Weka Instance
        }//end loop

        instance.setMissing(41);//column 41 -> the attack class is unknown and needs to be predicted, in other words, to prevent 0.0  -> "normal"


//When predicting, Weka only uses the non-class attributes (the first 41 features).
// because we did setClassIndex(instances.numAttribute()-1) so Weka wont use column 42 to make its prediction

        double classIndex = classifier.classifyInstance(instance); //Uses the trained model to predict the label of one new data row whose answer is unknown. so after .buildClassifier now we test it. So it may return 0.0 -> "normal"

        return dataStructure.classAttribute().value((int)classIndex);
    }//end classify
}//end ClassifierEngine