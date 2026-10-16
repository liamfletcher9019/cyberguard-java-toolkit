import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class SecurityLogGenerator {

    private static final DateTimeFormatter LOG_TIME_FORMAT = DateTimeFormatter.ofPattern("MMM d HH:mm:ss",
            java.util.Locale.US);

    private static class LogEvent {
        private LocalDateTime timestamp;
        private String hostname;
        private String serviceName;
        private int processId;
        private String message;

        public LogEvent(LocalDateTime timestamp, String hostname, String serviceName, int processId, String message) {
            this.timestamp = timestamp;
            this.hostname = hostname;
            this.serviceName = serviceName;
            this.processId = processId;
            this.message = message;
        }

        public String format() {
            return timestamp.format(LOG_TIME_FORMAT) + " "
                    + hostname + " "
                    + serviceName + "[" + processId + "]: "
                    + message;
        }

    }

    private static List<LogEvent> generateEvents() {
        List<LogEvent> events = new ArrayList<>();

        LocalDateTime startTime = LocalDateTime.of(2026, 10, 15, 14, 0, 0);

        events.add(new LogEvent(
                startTime,
                "web01",
                "sshd",
                1842,
                "Accepted publickey for deploy from 192.0.2.25 port 50122 ssh2"));

        events.add(new LogEvent(
                startTime.plusSeconds(5),
                "web01",
                "sshd",
                1843,
                "Failed password for root from 203.0.113.42 port 52145 ssh2"));

        events.add(new LogEvent(
                startTime.plusSeconds(10),
                "web01",
                "sshd",
                1844,
                "Failed password for root from 203.0.113.42 port 52146 ssh2"));

        events.add(new LogEvent(
                startTime.plusSeconds(15),
                "web01",
                "sshd",
                1845,
                "Failed password for invalid user guest from 203.0.113.42 port 52147 ssh2"));

        return events;
    }

    private static void writeEvents(List<LogEvent> events, String fileName) {
        Path path = Paths.get(fileName);

        try {
            Files.createDirectories(path.getParent());

            try (BufferedWriter writer = Files.newBufferedWriter(path)) {
                for (LogEvent event : events) {
                    writer.write(event.format());
                    writer.newLine();
                }
            }

            System.out.println("Generated log saved to " + path);

        } catch (IOException e) {
            System.out.println("Error writing log file: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        List<LogEvent> events = generateEvents();
        writeEvents(events, "data/generated-auth.log");
    }

}