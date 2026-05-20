import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashMap;

public class DatasetExplorer {

    public static void main(String[] args) {

        String trainPath = "C:\\Users\\SAUS\\Documents\\AI-powered-Intrusion-Detection-System\\data\\KDDTrain+.txt";
        String testPath  = "C:\\Users\\SAUS\\Documents\\AI-powered-Intrusion-Detection-System\\data\\KDDTest+.txt";

        System.out.println("========================================");
        System.out.println("         NSL-KDD DATASET EXPLORER       ");
        System.out.println("========================================");

        exploreFile("TRAINING SET", trainPath);
        exploreFile("TEST SET",     testPath);
    }

    public static void exploreFile(String label, String filepath) {

        int totalRows       = 0;
        int malformedRows   = 0;
        int normalCount     = 0;

        // Count each attack category
        HashMap<String, Integer> categoryCount = new HashMap<>();
        categoryCount.put("normal", 0);
        categoryCount.put("DoS",    0);
        categoryCount.put("Probe",  0);
        categoryCount.put("R2L",    0);
        categoryCount.put("U2R",    0);

        // Track min and max for numeric features (duration, src_bytes, dst_bytes)
        double minDuration = Double.MAX_VALUE, maxDuration = 0;
        double minSrcBytes = Double.MAX_VALUE, maxSrcBytes = 0;
        double minDstBytes = Double.MAX_VALUE, maxDstBytes = 0;

        // Map specific attack names to their category
        HashMap<String, String> attackCategory = new HashMap<>();

        // DoS attacks
        for (String a : new String[]{"neptune","smurf","pod","teardrop","land",
                "back","apache2","udpstorm","processtable","mailbomb"}) {
            attackCategory.put(a, "DoS");
        }
        // Probe attacks
        for (String a : new String[]{"ipsweep","portsweep","nmap","satan","mscan","saint"}) {
            attackCategory.put(a, "Probe");
        }
        // R2L attacks
        for (String a : new String[]{"guess_passwd","ftp_write","imap","phf","multihop",
                "warezmaster","warezclient","spy","xlock","xsnoop",
                "snmpgetattack","named","sendmail","httptunnel",
                "worm","snmpguess"}) {
            attackCategory.put(a, "R2L");
        }
        // U2R attacks
        for (String a : new String[]{"buffer_overflow","rootkit","loadmodule","perl",
                "xterm","ps","sqlattack","httptunnel"}) {
            attackCategory.put(a, "U2R");
        }

        // Count each specific attack name
        HashMap<String, Integer> attackCount = new HashMap<>();

        try (BufferedReader br = new BufferedReader(new FileReader(filepath))) {
            String line;
            while ((line = br.readLine()) != null) {

                String[] values = line.split(",");

                if (values.length < 42) {
                    malformedRows++;
                    continue;
                }

                totalRows++;

                // Get the attack label (column 41)
                String attackLabel = values[41].trim();

                // Count specific attack names
                attackCount.put(attackLabel,
                        attackCount.getOrDefault(attackLabel, 0) + 1);

                // Count by category
                if (attackLabel.equals("normal")) {
                    categoryCount.put("normal", categoryCount.get("normal") + 1);
                } else {
                    String cat = attackCategory.getOrDefault(attackLabel, "Unknown");
                    categoryCount.put(cat, categoryCount.getOrDefault(cat, 0) + 1);
                }

                // Track numeric feature ranges
                double duration = Double.parseDouble(values[0].trim());
                double srcBytes = Double.parseDouble(values[4].trim());
                double dstBytes = Double.parseDouble(values[5].trim());

                if (duration < minDuration) minDuration = duration;
                if (duration > maxDuration) maxDuration = duration;
                if (srcBytes < minSrcBytes) minSrcBytes = srcBytes;
                if (srcBytes > maxSrcBytes) maxSrcBytes = srcBytes;
                if (dstBytes < minDstBytes) minDstBytes = dstBytes;
                if (dstBytes > maxDstBytes) maxDstBytes = dstBytes;
            }

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }

        // ---- Print results ----
        System.out.println("\n--- " + label + " ---");
        System.out.println("Total rows:      " + totalRows);
        System.out.println("Malformed rows:  " + malformedRows);
        System.out.println("Total columns:   42 (41 features + 1 label)");

        System.out.println("\n[ CLASS DISTRIBUTION ]");
        String[] categories = {"normal", "DoS", "Probe", "R2L", "U2R"};
        for (String cat : categories) {
            int count = categoryCount.getOrDefault(cat, 0);
            double pct = (count * 100.0) / totalRows;
            int barLen = (int)(pct / 2); // scale bar to 50 chars max
            String bar = "█".repeat(barLen);
            System.out.printf("  %-8s %6d  (%5.2f%%)  %s%n", cat, count, pct, bar);
        }

        System.out.println("\n[ FEATURE RANGES ]");
        System.out.printf("  duration:   min=%.0f  max=%.0f%n", minDuration, maxDuration);
        System.out.printf("  src_bytes:  min=%.0f  max=%.0f%n", minSrcBytes, maxSrcBytes);
        System.out.printf("  dst_bytes:  min=%.0f  max=%.0f%n", minDstBytes, maxDstBytes);

        System.out.println("\n[ TOP 10 SPECIFIC ATTACKS ]");
        attackCount.entrySet().stream()
                .filter(e -> !e.getKey().equals("normal"))
                .sorted((a, b) -> b.getValue() - a.getValue())
                .limit(10)
                .forEach(e -> System.out.printf("  %-20s %6d%n", e.getKey(), e.getValue()));
    }
}