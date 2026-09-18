import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;

public class LocalServer {

    public static void main(String[] args) throws IOException {

        int port = 8080;

        HttpServer server = HttpServer.create(
            new InetSocketAddress("localhost", port), 0
        );

        server.createContext("/", (HttpExchange exchange) -> {

            Path file = Path.of("index.html");

            if (Files.exists(file)) {
                byte[] response = Files.readAllBytes(file);

                exchange.getResponseHeaders()
                        .set("Content-Type", "text/html");

                exchange.sendResponseHeaders(200, response.length);
                exchange.getResponseBody().write(response);
            } else {
                String response = "index.html not found";

                exchange.sendResponseHeaders(404, response.length());
                exchange.getResponseBody().write(response.getBytes());
            }

            exchange.close();
        });

        server.start();

        System.out.println("Server running at:");
        System.out.println("http://localhost:" + port);
    }
}

