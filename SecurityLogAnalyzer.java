import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoField;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecurityLogAnalyzer {

    private static final int TIME_WINDOW_SECONDS = 60;
    private static final int LOG_YEAR = 2026;
    private static final int BRUTE_FORCE_ALERT_THRESHOLD = 10;
    private static final int SUSPICIOUS_ACTIVITY_THRESHOLD = 5;
    private static final int USERNAME_ENUMERATION_ALERT_THRESHOLD = 10;

    private static final String LOG_FILE_PATH = "data/generated-auth.log";

    private static final Duration TIME_WINDOW = Duration.ofSeconds(TIME_WINDOW_SECONDS);

    private static final DateTimeFormatter LOG_TIME_FORMAT = new DateTimeFormatterBuilder()
            .parseCaseInsensitive()
            .appendPattern("MMM d HH:mm:ss")
            .parseDefaulting(ChronoField.YEAR, LOG_YEAR)
            .toFormatter(Locale.US);

    private static final Pattern TIMESTAMP_PATTERN = Pattern.compile("^(\\w{3} \\d{1,2} \\d{2}:\\d{2}:\\d{2})");

    private static final Pattern IP_PATTERN = Pattern.compile("from (\\S+)");

    private static final Pattern USERNAME_PATTERN = Pattern.compile(
            "(?:Failed password for (?:invalid user )?"
                    + "|Accepted (?:password|publickey) for )(\\S+) from ");

    private static class LogEntry {
        private final String ipAddress;
        private final String username;
        private final LocalDateTime timestamp;
        private final boolean successful;

        private LogEntry(
                String ipAddress,
                String username,
                LocalDateTime timestamp,
                boolean successful) {

            this.ipAddress = ipAddress;
            this.username = username;
            this.timestamp = timestamp;
            this.successful = successful;
        }
    }

    private static class ParseResult {
        private final List<LogEntry> entries;
        private final int ignoredEntries;
        private final int skippedEntries;

        private ParseResult(
                List<LogEntry> entries,
                int ignoredEntries,
                int skippedEntries) {

            this.entries = entries;
            this.ignoredEntries = ignoredEntries;
            this.skippedEntries = skippedEntries;
        }
    }

    private static class LoginAfterFailuresAlert {
        private final String ipAddress;
        private final String username;
        private final long failedAttempts;

        private LoginAfterFailuresAlert(
                String ipAddress,
                String username,
                long failedAttempts) {

            this.ipAddress = ipAddress;
            this.username = username;
            this.failedAttempts = failedAttempts;
        }
    }

    private static List<String> readLogFile(String fileName)
            throws IOException {

        return Files.readAllLines(Path.of(fileName));
    }

    private static ParseResult parseLogEntries(List<String> logLines) {
        List<LogEntry> parsedEntries = new ArrayList<>();
        int ignoredEntries = 0;
        int skippedEntries = 0;

        for (String line : logLines) {
            boolean failed = line.contains("Failed password");

            boolean successful = line.contains("Accepted password")
                    || line.contains("Accepted publickey");

            if (!failed && !successful) {
                ignoredEntries++;
                continue;
            }

            Matcher timeMatcher = TIMESTAMP_PATTERN.matcher(line);
            Matcher ipMatcher = IP_PATTERN.matcher(line);
            Matcher usernameMatcher = USERNAME_PATTERN.matcher(line);

            if (!timeMatcher.find()
                    || !ipMatcher.find()
                    || !usernameMatcher.find()) {

                System.out.println(
                        "[WARNING] Skipping malformed authentication entry: "
                                + line);

                skippedEntries++;
                continue;
            }

            try {
                LocalDateTime timestamp = LocalDateTime.parse(
                        timeMatcher.group(1),
                        LOG_TIME_FORMAT);

                parsedEntries.add(new LogEntry(
                        ipMatcher.group(1),
                        usernameMatcher.group(1),
                        timestamp,
                        successful));

            } catch (DateTimeParseException e) {
                System.out.println(
                        "[WARNING] Skipping entry with invalid timestamp: "
                                + line);

                skippedEntries++;
            }
        }

        return new ParseResult(
                parsedEntries,
                ignoredEntries,
                skippedEntries);
    }

    private static Map<String, List<LocalDateTime>> getFailedLoginTimes(
            List<LogEntry> entries) {

        Map<String, List<LocalDateTime>> failedLoginTimes = new HashMap<>();

        for (LogEntry entry : entries) {
            if (!entry.successful) {
                failedLoginTimes.computeIfAbsent(
                        entry.ipAddress,
                        key -> new ArrayList<>())
                        .add(entry.timestamp);
            }
        }

        return failedLoginTimes;
    }

    private static int getMaxFailedLoginBurst(
            List<LocalDateTime> timestamps) {

        List<LocalDateTime> sortedTimestamps = new ArrayList<>(timestamps);

        Collections.sort(sortedTimestamps);

        int maxAttempts = 0;
        int startIndex = 0;

        for (int endIndex = 0; endIndex < sortedTimestamps.size(); endIndex++) {

            while (Duration.between(
                    sortedTimestamps.get(startIndex),
                    sortedTimestamps.get(endIndex))
                    .compareTo(TIME_WINDOW) > 0) {

                startIndex++;
            }

            int attemptsInWindow = endIndex - startIndex + 1;

            maxAttempts = Math.max(maxAttempts, attemptsInWindow);
        }

        return maxAttempts;
    }

    private static Map<String, Map<String, List<LocalDateTime>>> getFailedUsernamesByIp(List<LogEntry> entries) {

        Map<String, Map<String, List<LocalDateTime>>> attemptsByIp = new HashMap<>();

        for (LogEntry entry : entries) {
            if (!entry.successful) {
                attemptsByIp.computeIfAbsent(
                        entry.ipAddress,
                        key -> new HashMap<>())
                        .computeIfAbsent(
                                entry.username,
                                key -> new ArrayList<>())
                        .add(entry.timestamp);
            }
        }

        return attemptsByIp;
    }

    private static int getMaxUniqueUsernamesInWindow(
            Map<String, List<LocalDateTime>> attemptsByUsername) {

        List<Map.Entry<String, LocalDateTime>> attempts = new ArrayList<>();

        for (Map.Entry<String, List<LocalDateTime>> entry : attemptsByUsername.entrySet()) {

            for (LocalDateTime timestamp : entry.getValue()) {
                attempts.add(Map.entry(entry.getKey(), timestamp));
            }
        }

        attempts.sort(Map.Entry.comparingByValue());

        int maxUniqueUsernames = 0;
        int startIndex = 0;

        Map<String, Integer> usernameCounts = new HashMap<>();

        for (int endIndex = 0; endIndex < attempts.size(); endIndex++) {
            String username = attempts.get(endIndex).getKey();

            usernameCounts.put(
                    username,
                    usernameCounts.getOrDefault(username, 0) + 1);

            while (Duration.between(
                    attempts.get(startIndex).getValue(),
                    attempts.get(endIndex).getValue())
                    .compareTo(TIME_WINDOW) > 0) {

                String oldUsername = attempts.get(startIndex).getKey();

                int count = usernameCounts.get(oldUsername);

                if (count == 1) {
                    usernameCounts.remove(oldUsername);
                } else {
                    usernameCounts.put(oldUsername, count - 1);
                }

                startIndex++;
            }

            maxUniqueUsernames = Math.max(
                    maxUniqueUsernames,
                    usernameCounts.size());
        }

        return maxUniqueUsernames;
    }

    private static List<LoginAfterFailuresAlert> detectSuccessfulLoginAfterFailures(List<LogEntry> entries) {

        Map<String, List<LocalDateTime>> failuresByAccount = new HashMap<>();

        for (LogEntry entry : entries) {
            if (!entry.successful) {
                String accountKey = entry.ipAddress + "\u0000" + entry.username;

                failuresByAccount.computeIfAbsent(
                        accountKey,
                        key -> new ArrayList<>())
                        .add(entry.timestamp);
            }
        }

        for (List<LocalDateTime> timestamps : failuresByAccount.values()) {

            Collections.sort(timestamps);
        }

        List<LoginAfterFailuresAlert> alerts = new ArrayList<>();

        for (LogEntry entry : entries) {
            if (!entry.successful) {
                continue;
            }

            String accountKey = entry.ipAddress + "\u0000" + entry.username;

            List<LocalDateTime> failures = failuresByAccount.get(accountKey);

            if (failures == null) {
                continue;
            }

            LocalDateTime windowStart = entry.timestamp.minus(TIME_WINDOW);

            int firstInWindow = lowerBound(
                    failures,
                    windowStart);

            int firstAfterLogin = upperBound(
                    failures,
                    entry.timestamp);

            long recentFailures = firstAfterLogin - firstInWindow;

            if (recentFailures >= BRUTE_FORCE_ALERT_THRESHOLD) {
                alerts.add(new LoginAfterFailuresAlert(
                        entry.ipAddress,
                        entry.username,
                        recentFailures));
            }
        }

        return alerts;
    }

    private static int lowerBound(
            List<LocalDateTime> timestamps,
            LocalDateTime target) {

        int low = 0;
        int high = timestamps.size();

        while (low < high) {
            int middle = low + (high - low) / 2;

            if (timestamps.get(middle).isBefore(target)) {
                low = middle + 1;
            } else {
                high = middle;
            }
        }

        return low;
    }

    private static int upperBound(
            List<LocalDateTime> timestamps,
            LocalDateTime target) {

        int low = 0;
        int high = timestamps.size();

        while (low < high) {
            int middle = low + (high - low) / 2;

            if (!timestamps.get(middle).isAfter(target)) {
                low = middle + 1;
            } else {
                high = middle;
            }
        }

        return low;
    }

    private static void reportBruteForce(
            Map<String, List<LocalDateTime>> failedLoginTimes) {

        System.out.println("\nBrute-Force Analysis:");

        if (failedLoginTimes.isEmpty()) {
            System.out.println("[INFO] No failed login attempts found.");
            return;
        }

        List<String> sortedIpAddresses = new ArrayList<>(failedLoginTimes.keySet());
        Collections.sort(sortedIpAddresses);

        for (String ipAddress : sortedIpAddresses) {
            List<LocalDateTime> timestamps = failedLoginTimes.get(ipAddress);
            int maxAttempts = getMaxFailedLoginBurst(timestamps);

            if (maxAttempts >= BRUTE_FORCE_ALERT_THRESHOLD) {
                System.out.println(
                        "[ALERT] " + ipAddress + ": "
                                + maxAttempts + " failed attempts within "
                                + TIME_WINDOW_SECONDS
                                + " seconds. Possible brute-force activity.");

            } else if (maxAttempts >= SUSPICIOUS_ACTIVITY_THRESHOLD) {
                System.out.println(
                        "[WARNING] " + ipAddress + ": "
                                + maxAttempts + " failed attempts within "
                                + TIME_WINDOW_SECONDS
                                + " seconds. Suspicious activity.");

            } else {
                System.out.println(
                        "[INFO] " + ipAddress + ": "
                                + maxAttempts + " failed attempts within "
                                + TIME_WINDOW_SECONDS
                                + " seconds. Normal activity.");
            }
        }
    }

    private static void reportUsernameEnumeration(
            Map<String, Map<String, List<LocalDateTime>>> usernamesByIp) {

        System.out.println("\nUsername Enumeration Analysis:");

        if (usernamesByIp.isEmpty()) {
            System.out.println("[INFO] No failed login attempts found.");
            return;
        }

        List<String> sortedIpAddresses = new ArrayList<>(usernamesByIp.keySet());
        Collections.sort(sortedIpAddresses);

        for (String ipAddress : sortedIpAddresses) {
            Map<String, List<LocalDateTime>> usernames = usernamesByIp.get(ipAddress);
            int uniqueUsernames = getMaxUniqueUsernamesInWindow(usernames);

            if (uniqueUsernames >= USERNAME_ENUMERATION_ALERT_THRESHOLD) {
                System.out.println(
                        "[ALERT] " + ipAddress + ": "
                                + uniqueUsernames
                                + " unique usernames within "
                                + TIME_WINDOW_SECONDS
                                + " seconds. Possible username enumeration.");

            } else if (uniqueUsernames >= SUSPICIOUS_ACTIVITY_THRESHOLD) {
                System.out.println(
                        "[WARNING] " + ipAddress + ": "
                                + uniqueUsernames
                                + " unique usernames within "
                                + TIME_WINDOW_SECONDS
                                + " seconds. Suspicious activity.");

            } else {
                System.out.println(
                        "[INFO] " + ipAddress + ": "
                                + uniqueUsernames
                                + " unique usernames within "
                                + TIME_WINDOW_SECONDS
                                + " seconds. Normal activity.");
            }
        }
    }

    private static void reportSuccessfulLoginAfterFailures(
            List<LoginAfterFailuresAlert> alerts) {

        System.out.println(
                "\nSuccessful Login After Failures Analysis:");

        if (alerts.isEmpty()) {
            System.out.println(
                    "[INFO] No successful logins followed by "
                            + BRUTE_FORCE_ALERT_THRESHOLD
                            + " or more failures for the same IP and username "
                            + "within " + TIME_WINDOW_SECONDS + " seconds.");

            return;
        }

        for (LoginAfterFailuresAlert alert : alerts) {
            System.out.println(
                    "[ALERT] " + alert.ipAddress
                            + " successfully logged in as " + alert.username
                            + " after " + alert.failedAttempts
                            + " failed attempts within the preceding "
                            + TIME_WINDOW_SECONDS + " seconds.");
        }
    }

    public static void main(String[] args) {
        try {
            List<String> logLines = readLogFile(LOG_FILE_PATH);

            System.out.println(
                    "Loaded " + logLines.size() + " log lines.");

            if (logLines.isEmpty()) {
                System.out.println(
                        "[INFO] The log file is empty.");
                return;
            }

            ParseResult result = parseLogEntries(logLines);
            List<LogEntry> parsedEntries = result.entries;

            System.out.println(
                    "Parsed " + parsedEntries.size()
                            + " authentication entries.");

            System.out.println(
                    "Ignored " + result.ignoredEntries
                            + " non-authentication lines.");

            System.out.println(
                    "Skipped " + result.skippedEntries
                            + " malformed authentication entries.");

            if (parsedEntries.isEmpty()) {
                System.out.println(
                        "[INFO] No valid authentication entries "
                                + "were found.");
                return;
            }

            Map<String, List<LocalDateTime>> failedLoginTimes = getFailedLoginTimes(parsedEntries);

            Map<String, Map<String, List<LocalDateTime>>> usernamesByIp = getFailedUsernamesByIp(parsedEntries);

            List<LoginAfterFailuresAlert> loginAlerts = detectSuccessfulLoginAfterFailures(parsedEntries);

            reportBruteForce(failedLoginTimes);
            reportUsernameEnumeration(usernamesByIp);
            reportSuccessfulLoginAfterFailures(loginAlerts);

        } catch (InvalidPathException e) {
            System.out.println(
                    "[ERROR] The configured log file path is invalid.");

        } catch (IOException e) {
            System.out.println(
                    "[ERROR] Could not read the log file: "
                            + e.getMessage());

        } catch (SecurityException e) {
            System.out.println(
                    "[ERROR] Permission denied while accessing the log file.");
        }
    }
}