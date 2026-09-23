//github.com/marvel-gulane/marvel-security
//∫01∫011−xy1dxdy=6π2
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.IOException;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ConcurrentHashMap;

public class HardwareTrojanMonitoring {
    private static final Map<Path, String> hashes = new ConcurrentHashMap<>();
    private static final Map<WatchKey, Path> watchKeys = new ConcurrentHashMap<>();
    private static final List<Path> MONITORED_DIRECTORIES = List.of(Paths.get(System.getProperty("user.home")), Paths.get("/etc"));
    private static final Path LOG = Paths.get("hardware-monitor.log");
    private static final Map<String, String> baseline = new HashMap<>();

    public static void main(String[] args) throws Exception {

        int port = 8080;

        System.out.println("Server running at:");
        System.out.println("http://localhost:" + port);
        System.out.println("Fedora Security Hardware Trojan Monitoring started.");

        HttpServer server = HttpServer.create( new InetSocketAddress("localhost", port), 0 );
        server.createContext("/", (HttpExchange exchange) -> {
        Path file = Path.of("/home/coderlava/Box/Index.html");
        WatchService watcher = FileSystems.getDefault().newWatchService();
 
        if (Files.exists(file)) {
           byte[] response = Files.readAllBytes(file);
           exchange.getResponseHeaders().set("Content-Type", "text/html");
           exchange.sendResponseHeaders(200, response.length);
           exchange.getResponseBody().write(response);

        } else {
                String response = "Index.html not found";
                exchange.sendResponseHeaders(404, response.length());
                exchange.getResponseBody().write(response.getBytes());
        }

			exchange.close();
		});
		
        server.start();
        takeSnapshot();
   }

    private static void takeSnapshot() throws Exception {
        baseline.clear();
        baseline.putAll(snapshot());
        log("Baseline created.");
    }

    private static Map<String, String> snapshot() throws Exception {
        Map<String, String> result = new HashMap<>();
        Runtime runtime = Runtime.getRuntime();

        result.put("availableProcessors", String.valueOf(runtime.availableProcessors()));
        result.put("maxMemory", String.valueOf(runtime.maxMemory()));
        result.put("os", System.getProperty("os.name"));
        result.put("osVersion", System.getProperty("os.version"));
        result.put("architecture", System.getProperty("os.arch"));

        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();

        while (interfaces.hasMoreElements()) {
            NetworkInterface ni = interfaces.nextElement();

            if (ni.isUp()) {
				
                String key = "network:" + ni.getName();
                String mac = "unknown";
                byte[] hardware = ni.getHardwareAddress();

                if (hardware != null) { mac = formatMac(hardware); }
                result.put(key, mac);
            }
        }

        return result;
    }

    private static String formatMac(byte[] mac) {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < mac.length; i++) {
            if (i > 0) { sb.append(":"); }
            sb.append(String.format("%02X", mac[i]));
        }

        return sb.toString();
    }

    private static void alert(String component, String oldValue, String newValue) {
        String message = "CHANGE DETECTED: " + component + " | old=" + oldValue + " | new=" + newValue;
        System.err.println(message);
        log(message);
    }

    private static void log(String message) {
        String line = "[" + Instant.now() + "] " + message + System.lineSeparator();

        try {
            Files.writeString(LOG, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) { System.err.println("Unable to write log: " + e.getMessage());}
    }

    private static void registerRecursive(
            Path root,
            WatchService watcher) throws IOException {

        Files.walkFileTree(
                root,
                new SimpleFileVisitor<Path>() {

                    @Override
                    public FileVisitResult preVisitDirectory(
                            Path dir,
                            BasicFileAttributes attrs)
                            throws IOException {

                        registerDirectory(dir, watcher);
                        return FileVisitResult.CONTINUE;
                    }
                }
        );
    }

    private static void registerDirectory(
            Path directory,
            WatchService watcher) throws IOException {

        WatchKey key = directory.register(
                watcher,
                StandardWatchEventKinds.ENTRY_CREATE,
                StandardWatchEventKinds.ENTRY_DELETE,
                StandardWatchEventKinds.ENTRY_MODIFY
        );

        watchKeys.put(key, directory);
    }

    private static void createBaseline(Path root)
            throws IOException {

        Files.walkFileTree(
                root,
                new SimpleFileVisitor<Path>() {

                    @Override
                    public FileVisitResult visitFile(
                            Path file,
                            BasicFileAttributes attrs) {

                        try {
                            hashes.put(file, sha256(file));
                        } catch (Exception e) {
                            log("Could not hash " + file);
                        }

                        return FileVisitResult.CONTINUE;
                    }
                }
        );
    }

    private static void processEvent(
            WatchEvent.Kind<?> kind,
            Path path,
            WatchService watcher) {

        if (kind == StandardWatchEventKinds.ENTRY_CREATE) {

            alert("CREATED: " + path);

            if (Files.isDirectory(path)) {
                try {
                    registerRecursive(path, watcher);
                } catch (IOException e) {
                    alert("Unable to watch directory: " + path);
                }
            }

            if (Files.isRegularFile(path)) {
                try {
                    hashes.put(path, sha256(path));
                } catch (Exception ignored) {
                }
            }

            return;
        }

        if (kind == StandardWatchEventKinds.ENTRY_DELETE) {

            String oldHash = hashes.remove(path);

            if (oldHash != null) {
                alert("DELETED: " + path);
            } else {
                alert("DELETED/RENAMED: " + path);
            }

            return;
        }

        if (kind == StandardWatchEventKinds.ENTRY_MODIFY) {

            if (!Files.isRegularFile(path)) {
                return;
            }

            try {
                String newHash = sha256(path);
                String oldHash = hashes.get(path);

                if (oldHash == null) {
                    hashes.put(path, newHash);
                    alert("MODIFIED/NEW: " + path);
                } else if (!oldHash.equals(newHash)) {
                    hashes.put(path, newHash);

                    alert(
                        "CONTENT MODIFIED: " + path +
                        " | old SHA-256=" + oldHash +
                        " | new SHA-256=" + newHash
                    );
                }

            } catch (Exception e) {
                alert(
                    "FILE CHANGED BUT COULD NOT BE HASHED: "
                    + path
                );
            }
        }
    }

    private static String sha256(Path file) throws IOException, NoSuchAlgorithmException {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        try {
			
            byte[] buffer = new byte[8192];
            try (var input = Files.newInputStream(file)) {

                int read;
                while ((read = input.read(buffer)) != -1) {digest.update(buffer, 0, read);}
            }
        } catch (IOException e) { throw e; }

        StringBuilder result = new StringBuilder();
        for (byte b : digest.digest()) { result.append(String.format("%02x", b));}
        return result.toString();
    }

    private static void alert(String message) {
        String output = "[" + Instant.now() + "] ALERT: " + message;
        System.err.println(output);
        log(output);
    }
}

