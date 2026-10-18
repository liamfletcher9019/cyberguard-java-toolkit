import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class SecurityLogGenerator {

    private static final int DEFAULT_EVENT_COUNT = 200;
    private static final String OUTPUT_FILE = "data/generated-auth.log";

    private static final String[] HOSTNAMES = {
            "web01", "db01", "gw01"
    };

    private static final String[] SOURCE_IPS = {
            "192.0.2.25",
            "198.51.100.23",
            "203.0.113.42",
            "203.0.113.77"
    };

    private static final String[] USERNAMES = {
            "admin", "root", "deploy", "ubuntu", "guest", "backup"
    };

    private static final DateTimeFormatter LOG_TIME_FORMAT = DateTimeFormatter.ofPattern("MMM d HH:mm:ss", Locale.US);

    private static class LogEvent {
        private final LocalDateTime timestamp;
        private final String hostname;
        private final String serviceName;
        private final int processId;
        private final String message;

        public LogEvent(
                LocalDateTime timestamp,
                String hostname,
                String serviceName,
                int processId,
                String message) {

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

    private static List<LogEvent> generateEvents(int eventCount) {
        List<LogEvent> events = new ArrayList<>();

        if (eventCount <= 0) {
            return events;
        }

        LocalDateTime startTime = LocalDateTime.of(2026, 10, 15, 14, 0, 0);

        int processId = 1842;

        for (int i = 0; i < eventCount; i++) {
            int scenario = (int) ((long) i * 4 / eventCount);

            long secondsElapsed;

            if (scenario == 0) {
                secondsElapsed = i * 5L;
            } else {
                secondsElapsed = 250L + (i - eventCount / 4);
            }

            LocalDateTime timestamp = startTime.plusSeconds(secondsElapsed);

            String hostname;
            String sourceIp;
            String username;
            String message;

            if (scenario == 0) {
                // Scenario 1: Normal SSH activity
                hostname = HOSTNAMES[0];
                sourceIp = SOURCE_IPS[i % SOURCE_IPS.length];
                username = USERNAMES[i % USERNAMES.length];

                if (i % 2 == 0) {
                    message = "Accepted publickey for " + username
                            + " from " + sourceIp
                            + " port " + (50000 + i) + " ssh2";
                } else {
                    message = "Connection closed by authenticating user "
                            + username + " " + sourceIp
                            + " port " + (50000 + i) + " [preauth]";
                }

            } else if (scenario == 1) {
                // Scenario 2: Repeated failures against one account
                hostname = HOSTNAMES[0];
                sourceIp = "203.0.113.42";
                username = "admin";

                message = "Failed password for " + username
                        + " from " + sourceIp
                        + " port " + (50000 + i) + " ssh2";

            } else if (scenario == 2) {
                // Scenario 3: One IP tries multiple usernames
                hostname = HOSTNAMES[2];
                sourceIp = "198.51.100.23";
                username = USERNAMES[i % USERNAMES.length];

                message = "Failed password for invalid user " + username
                        + " from " + sourceIp
                        + " port " + (50000 + i) + " ssh2";

            } else {
                // Scenario 4: Repeated failures followed by a success
                hostname = HOSTNAMES[1];
                sourceIp = "192.0.2.25";
                username = "deploy";

                if (i == eventCount - 1) {
                    message = "Accepted publickey for " + username
                            + " from " + sourceIp
                            + " port " + (50000 + i) + " ssh2";
                } else {
                    message = "Failed password for " + username
                            + " from " + sourceIp
                            + " port " + (50000 + i) + " ssh2";
                }
            }

            events.add(new LogEvent(
                    timestamp,
                    hostname,
                    "sshd",
                    processId++,
                    message));
        }

        return events;
    }

    private static void writeEvents(
            List<LogEvent> events,
            String fileName) {

        Path path = Path.of(fileName);
        Path parent = path.getParent();

        try {
            if (parent != null) {
                Files.createDirectories(parent);
            }

            try (BufferedWriter writer = Files.newBufferedWriter(path)) {
                for (LogEvent event : events) {
                    writer.write(event.format());
                    writer.newLine();
                }
            }

            System.out.println("Generated " + events.size()
                    + " log events and saved them to " + path);

        } catch (IOException e) {
            System.out.println(
                    "[ERROR] Could not write the log file: "
                            + e.getMessage());
        }
    }

    public static void main(String[] args) {
        List<LogEvent> events = generateEvents(DEFAULT_EVENT_COUNT);
        writeEvents(events, OUTPUT_FILE);
    }
}
