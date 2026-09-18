import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;

public class HardwareMonitor {

    private static final Path LOG =
            Paths.get("hardware-monitor.log");

    private static final Map<String, String> baseline =
            new HashMap<>();

    public static void main(String[] args) throws Exception {
        System.out.println("Hardware monitor started.");

        takeSnapshot();

        while (true) {
            Thread.sleep(10_000);

            Map<String, String> current = snapshot();

            for (Map.Entry<String, String> entry : current.entrySet()) {
                String oldValue = baseline.get(entry.getKey());

                if (oldValue != null && !oldValue.equals(entry.getValue())) {
                    alert(entry.getKey(), oldValue, entry.getValue());
                }
            }
        }
    }

    private static void takeSnapshot() throws Exception {
        baseline.clear();
        baseline.putAll(snapshot());

        log("Baseline created.");
    }

    private static Map<String, String> snapshot() throws Exception {
        Map<String, String> result = new HashMap<>();

        Runtime runtime = Runtime.getRuntime();

        result.put("availableProcessors",
                String.valueOf(runtime.availableProcessors()));

        result.put("maxMemory",
                String.valueOf(runtime.maxMemory()));

        result.put("os",
                System.getProperty("os.name"));

        result.put("osVersion",
                System.getProperty("os.version"));

        result.put("architecture",
                System.getProperty("os.arch"));

        Enumeration<NetworkInterface> interfaces =
                NetworkInterface.getNetworkInterfaces();

        while (interfaces.hasMoreElements()) {
            NetworkInterface ni = interfaces.nextElement();

            if (ni.isUp()) {
                String key = "network:" + ni.getName();

                String mac = "unknown";
                byte[] hardware = ni.getHardwareAddress();

                if (hardware != null) {
                    mac = formatMac(hardware);
                }

                result.put(key, mac);
            }
        }

        return result;
    }

    private static String formatMac(byte[] mac) {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < mac.length; i++) {
            if (i > 0) {
                sb.append(":");
            }

            sb.append(String.format("%02X", mac[i]));
        }

        return sb.toString();
    }

    private static void alert(
            String component,
            String oldValue,
            String newValue) {

        String message =
                "CHANGE DETECTED: " +
                component +
                " | old=" + oldValue +
                " | new=" + newValue;

        System.err.println(message);
        log(message);
    }

    private static void log(String message) {
        String line =
                "[" + Instant.now() + "] " +
                message + System.lineSeparator();

        try {
            Files.writeString(
                    LOG,
                    line,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND
            );
        } catch (IOException e) {
            System.err.println(
                    "Unable to write log: " + e.getMessage());
        }
    }
}

