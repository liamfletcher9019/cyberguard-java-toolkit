import java.util.Scanner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

public class CyberGuard {

    public static void main(String[] args) {

        Scanner reader = new Scanner(System.in);

        Set<String> commonPasswords = loadWordList("data/common-passwords.txt");
        Set<String> commonWords = loadWordList("data/common-words.txt");

        if (commonPasswords.isEmpty() || commonWords.isEmpty()) {
            System.out.println("Error: Required word lists could not be loaded");
            System.out.println("Check that both files exist in the data folder");
            reader.close();
            return;
        }

        System.out.println("Loaded " + commonPasswords.size() + " common passwords");
        System.out.println("Loaded " + commonWords.size() + " English words");

        int choice = 0;

        while (choice != 5) {
            System.out.println("========================================");
            System.out.println("           CYBERGUARD TOOLKIT");
            System.out.println("========================================");
            System.out.println("1. Password Strength Assessment");
            System.out.println("2. Security Log Analyzer");
            System.out.println("3. Threat Detection and Risk Analysis");
            System.out.println("4. Security Reports and Evaluation");
            System.out.println("5. Exit");
            System.out.println("========================================");
            System.out.print("Choose an option: ");

            String userInput = reader.nextLine();

            try {
                choice = Integer.parseInt(userInput.trim());

                if (choice == 1) {
                    System.out.println("\nPassword Strength Assessment selected");
                    passwordStrengthAssessment(reader, commonPasswords, commonWords);
                } else if (choice == 2) {
                    System.out.println("\nSecurity Log Analyzer selected");
                } else if (choice == 3) {
                    System.out.println("\nThreat Detection and Risk Analysis selected");
                } else if (choice == 4) {
                    System.out.println("\nSecurity Reports and Evaluation selected");
                } else if (choice == 5) {
                    System.out.println("\nLeaving CyberGuard, Goodbye!");
                } else {
                    System.out.println("\nInvalid option. Please choose 1, 2, 3, 4, or 5");
                }

            } catch (NumberFormatException e) {
                System.out.println("\nInvalid input. Please enter a whole number");
            }

            System.out.println();
        }

        reader.close();
    }

    public static void passwordStrengthAssessment(Scanner reader, Set<String> commonPasswords,
            Set<String> commonWords) {

        System.out.println("\n========================================");
        System.out.println("      PASSWORD STRENGTH ASSESSMENT");
        System.out.println("========================================");
        System.out.print("Enter a test password: ");

        String password = reader.nextLine();

        if (password.isBlank()) {
            System.out.println("\nPassword cannot be empty");
            return;
        }

        String normalizedPassword = password.toLowerCase();

        boolean hasCommonPassword = commonPasswords.contains(normalizedPassword);

        boolean hasCommonWord = false;

        boolean hasWordYearPattern = false;

        for (String word : commonWords) {
            if (word.length() < 4) {
                continue;
            }

            if (normalizedPassword.contains(word)) {
                hasCommonWord = true;
            }

            if (normalizedPassword.startsWith(word)) {
                String remaining = normalizedPassword.substring(word.length());

                if (remaining.matches("\\d{4}.*")) {
                    hasWordYearPattern = true;
                }
            }

            if (hasCommonWord && hasWordYearPattern) {
                break;
            }
        }

        boolean longEnough = password.length() >= 12;
        boolean hasUppercase = false;
        boolean hasLowercase = false;
        boolean hasNumber = false;
        boolean hasSpecial = false;

        for (int i = 0; i < password.length(); i++) {
            char character = password.charAt(i);

            if (Character.isUpperCase(character)) {
                hasUppercase = true;
            } else if (Character.isLowerCase(character)) {
                hasLowercase = true;
            } else if (Character.isDigit(character)) {
                hasNumber = true;
            } else if (!Character.isLetterOrDigit(character) && !Character.isWhitespace(character)) {
                hasSpecial = true;
            }
        }

        int penalty = 0;

        if (hasCommonPassword) {
            penalty += 5;
        }

        if (hasCommonWord) {
            penalty += 2;
        }

        if (hasWordYearPattern) {
            penalty += 2;
        }

        if (password.matches(".*(.)\\1{2,}.*")) {
            penalty += 1;
        }

        if (normalizedPassword.matches(".*(1234|12345|123456|abcd|qwerty|asdf).*")) {
            penalty += 1;
        }

        int score = 0;

        if (longEnough) {
            score++;
        }
        if (hasUppercase) {
            score++;
        }
        if (hasLowercase) {
            score++;
        }
        if (hasNumber) {
            score++;
        }
        if (hasSpecial) {
            score++;
        }

        System.out.println("\n--- Assessment Results ---");
        System.out.println("At least 12 characters: " + longEnough);
        System.out.println("Contains uppercase: " + hasUppercase);
        System.out.println("Contains lowercase: " + hasLowercase);
        System.out.println("Contains a number: " + hasNumber);
        System.out.println("Contains a special character: " + hasSpecial);
        System.out.println("Common Password Match: " + hasCommonPassword);
        System.out.println("Common Word Detected: " + hasCommonWord);
        System.out.println("Word + Number Pattern Detected: " + hasWordYearPattern);

        int adjustedScore = Math.max(0, score - penalty);

        System.out.println("Base Strength Score: " + score + "/5");
        if (penalty > 0) {
            System.out.println("Penalty: -" + penalty);
        } else {
            System.out.println("Penalty: None");
        }
        System.out.println("Adjusted Strength Score: " + adjustedScore + "/5");

        if (hasCommonPassword || adjustedScore <= 2) {
            System.out.println("Assessment: Weak");
        } else if (hasCommonWord || hasWordYearPattern || penalty > 0 || adjustedScore <= 4) {
            System.out.println("Assessment: Moderate");
        } else {
            System.out.println("Assessment: Strong on these checks");
        }

        System.out.println("\n--- Security Recommendations ---");

        boolean hasRecommendation = false;

        if (!longEnough) {
            System.out.println("- Use at least 12 characters");
            hasRecommendation = true;
        }

        if (hasCommonPassword) {
            System.out.println("- Avoid commonly used passwords");
            hasRecommendation = true;
        }

        if (hasWordYearPattern) {
            System.out.println("- Avoid common words followed by a year");
            hasRecommendation = true;
        } else if (hasCommonWord) {
            System.out.println("- Avoid common words that make passwords predictable");
            hasRecommendation = true;
        }

        if (password.matches(".*(.)\\1{2,}.*")) {
            System.out.println("- Avoid repeating the same character three or more times");
            hasRecommendation = true;
        }

        if (normalizedPassword.matches(".*(1234|12345|123456|abcd|qwerty|asdf).*")) {
            System.out.println("- Avoid predictable sequences and keyboard patterns");
            hasRecommendation = true;
        }

        if (!hasRecommendation) {
            System.out.println("No issues detected by these checks");
        }
    }

    public static Set<String> loadWordList(String filePath) {

        Set<String> words = new HashSet<>();

        try {
            for (String line : Files.readAllLines(Path.of(filePath))) {
                String word = line.trim().toLowerCase();

                if (!word.isEmpty() && !word.startsWith("#")) {
                    words.add(word);
                }
            }
        } catch (IOException e) {
            System.out.println("Warning: Could not load " + filePath + ". Related security checks may be incomplete.");
        }

        return words;
    }
} 
