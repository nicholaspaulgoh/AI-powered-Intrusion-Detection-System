import java.util.concurrent.atomic.*;
import java.util.concurrent.*;
import javafx.application.Platform;
import java.io.*;
import java.util.ArrayList;
import weka.classifiers.*;
import weka.core.*;

public class DetectionEngine{

        private ExecutorService executor;
        private volatile boolean running=false;

        public final AtomicInteger dosCount = new AtomicInteger(0);  //0=initial value
        public final AtomicInteger probeCount = new AtomicInteger(0);
        public final AtomicInteger r2lCount = new AtomicInteger(0);
        public final AtomicInteger u2rCount = new AtomicInteger(0);
        public final AtomicInteger totalConnections = new AtomicInteger(0);

        private java.util.function.Consumer<String> onAlert;

        public void setOnAlert(java.util.function.Consumer<String> callback){
            this.onAlert = callback;
        }

        public void start(AbstractClassifier model, Instances dataStructure, String filePath){

            if(Preprocessor.trainMax == null || Preprocessor.trainMin ==null){
                System.out.println("Error: Run training pipeline first!");
                return;
            }

            running=true;

            executor= Executors.newSingleThreadExecutor( r ->{  //to create a custom thread if not there's a built-in Executors.defaultThreadFactory() -> Thread t = new Thread(r);t.setName("pool-1-thread-1");return t;
                Thread t = new Thread(r,"DetectionThread");
                t.setDaemon(true);
                return t;
            });

            executor.submit(()->{

                System.out.println("Detection loop started on: " + Thread.currentThread().getName());


                try(BufferedReader br = new BufferedReader(new FileReader(filePath))){
                    String line;

                    while(running && (line=br.readLine()) != null){


                        String[] values = line.split(",");
                        if (values.length <42) continue;
                        double[] features =Preprocessor.getFeatures(values);
                        ArrayList<double[]> processed = new ArrayList<>();
                        processed.add(features);
                        Preprocessor.normalize(processed);





                        String prediction= ClassifierEngine.classify(model,processed.get(0),dataStructure);

                        totalConnections.incrementAndGet();
                        String actualLabel= values[41].trim();

                        updateCounter(prediction);


                        String alert = String.format("[%s] Connections %d -> %s", java.time.LocalTime.now(), totalConnections.get(), prediction);

                        if(onAlert !=null){
                            Platform.runLater(() -> {onAlert.accept(alert);});

                        }//end if

                        Thread.sleep(50);
                    }//end while

                }catch(InterruptedException ex1){
                    Thread.currentThread().interrupt();
                    System.out.println("Detection loop interrupted cleanly"); //if not Thread.currentThread().isInterrupted() returns false
                }catch(Exception ex1){
                    System.out.println(ex1.getMessage());
                }//end catch

                System.out.println("Detection loop ended");
            });//end executor.submit
        }//end start

        public void stop(){
            running=false;

            if(executor !=null){
                executor.shutdownNow();
            }
        }//end stop

        public void updateCounter(String prediction){

            switch(prediction){
                case "DoS": dosCount.incrementAndGet(); break;
                case "Probe": probeCount.incrementAndGet(); break;
                case "R2L": r2lCount.incrementAndGet(); break;
                case "U2R": u2rCount.incrementAndGet(); break;

            }

        }//end updateCounter
    }//end class


