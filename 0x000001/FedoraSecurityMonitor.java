import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class FedoraSecurityMonitor {
    private static final Map<Path, String> hashes = new ConcurrentHashMap<>();
    private static final Map<WatchKey, Path> watchKeys = new ConcurrentHashMap<>();
    private static final Path LOG = Paths.get("security-monitor.log");
   // Change these to the directories you want to monitor.
    private static final List<Path> MONITORED_DIRECTORIES = List.of(Paths.get(System.getProperty("user.home")), Paths.get("/etc"));

    public static void main(String[] args) throws Exception {
        System.out.println("Fedora security monitor started.");

        WatchService watcher =
                FileSystems.getDefault().newWatchService();

        // Build initial file-integrity baseline.
        for (Path directory : MONITORED_DIRECTORIES) {
            if (Files.isDirectory(directory)) {
                registerRecursive(directory, watcher);
                createBaseline(directory);
            }
        }

        System.out.println("Monitoring filesystem changes...");

        while (true) {
            WatchKey key = watcher.take();

            Path directory = watchKeys.get(key);

            if (directory == null) {
                key.reset();
                continue;
            }

            for (WatchEvent<?> event : key.pollEvents()) {
                WatchEvent.Kind<?> kind = event.kind();

                if (kind == StandardWatchEventKinds.OVERFLOW) {
                    alert("WATCHER OVERFLOW in " + directory);
                    continue;
                }

                Path relative =
                        (Path) event.context();

                Path changed =
                        directory.resolve(relative);

                processEvent(kind, changed, watcher);
            }

            boolean valid = key.reset();

            if (!valid) {
                watchKeys.remove(key);
            }
        }
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

    private static String sha256(Path file)
            throws IOException, NoSuchAlgorithmException {

        MessageDigest digest =
                MessageDigest.getInstance("SHA-256");

        try {
            byte[] buffer = new byte[8192];

            try (var input = Files.newInputStream(file)) {

                int read;

                while ((read = input.read(buffer)) != -1) {
                    digest.update(buffer, 0, read);
                }
            }
        } catch (IOException e) {
            throw e;
        }

        StringBuilder result = new StringBuilder();

        for (byte b : digest.digest()) {
            result.append(
                    String.format("%02x", b)
            );
        }

        return result.toString();
    }

    private static void alert(String message) {
        String output =
                "[" + Instant.now() + "] ALERT: " + message;

        System.err.println(output);
        log(output);
    }

    private static void log(String message) {
        try {
            Files.writeString(
                    LOG,
                    message + System.lineSeparator(),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND
            );
        } catch (IOException e) {
            System.err.println(
                    "Logging failed: " + e.getMessage()
            );
        }
    }
}

