# CyberGuard

CyberGuard is a Java-based cybersecurity toolkit that assesses password strength, analyzes authentication logs, and detects potentially suspicious activity. The project combines practical defensive security concepts with Java programming, log analysis, and security testing.

## Current Features

### Password Strength Assessment
- Evaluates password length and character variety.
- Assigns a password strength score from 1 to 5.
- Checks passwords against common-password and common-word datasets.
- Detects predictable patterns, including common words, year patterns, and repeated characters.
- Validates user input and provides security recommendations.

### Authentication Log Analysis
- Parses SSH authentication log entries.
- Detects potential brute-force login attempts using rolling 60-second windows.
- Identifies suspicious username enumeration activity.
- Flags successful logins following repeated failed attempts from the same IP address and username.
- Tracks authentication events by source IP and username.
- Handles missing files, malformed authentication entries, and unsupported log lines.
- Reports parsed, ignored, and skipped log entries separately.
- Produces consistently ordered detection results.

### Authentication Log Generation
- Generates 200 synthetic authentication events by default.
- Includes normal login activity, repeated login failures, username enumeration, and successful logins following repeated failures.
- Writes generated events to `data/generated-auth.log`.
- Produces logs compatible with the authentication log analyzer.

### Sample Datasets
- Includes sample authentication logs in `data/auth-log-datasets/`.
- Includes password and common-word datasets for password assessment.
- Provides data for testing and developing future log generation features.

## Technologies
- Java
- File I/O and text processing
- Regular expressions
- Collections and data structures
- Git and GitHub

## Running CyberGuard

Run these commands from the project root in a Java environment.

### Start the Main Toolkit
```bash
java CyberGuard.java
```

### Generate Authentication Logs
```bash
java SecurityLogGenerator.java
```

### Analyze Authentication Logs
```bash
java SecurityLogAnalyzer.java
```

The generator creates `data/generated-auth.log`, which is read by the analyzer.

## Project Structure

```text
cyberguard-java-toolkit/
├── CyberGuard.java
├── SecurityLogGenerator.java
├── SecurityLogAnalyzer.java
├── data/
│   ├── common-passwords.txt
│   ├── common-words.txt
│   ├── auth-log-datasets/
│   └── generated-auth.log
└── README.md
```

## Upcoming Features

### Improved Authentication Log Generation
- Use the existing sample authentication logs as reference material for realistic synthetic events.
- Support varied hosts, usernames, timestamps, and authentication patterns.
- Generate configurable numbers of events.
- Support reproducible test scenarios with configurable random seeds.
- Separate realistic log generation from controlled detection test datasets.

### Expanded Threat Detection
- Add more detection rules and event correlation.
- Improve risk assessment and severity classification.
- Evaluate false positives and false negatives.
- Provide explanations for why activity is flagged.

### Security Reports and Evaluation
- Summarize authentication activity and detected threats.
- Generate readable reports with findings, evidence, potential impact, and recommendations.
- Export reports to text or HTML files.
- Integrate local AI through Ollama to explain technical findings in plain English.
- Maintain a non-AI reporting option so reports remain available when a model is not running.

### Dashboard
- Display security findings, risk levels, and suspicious activity.
- Provide visual summaries and filtering options.
- Connect the interface to the existing Java analysis logic.

## Project Goals

CyberGuard is an ongoing project focused on defensive cybersecurity, Java development, authentication monitoring, and security reporting.

The long-term goal is to build a practical cybersecurity toolkit that combines reliable rule-based detection, realistic synthetic log generation, readable security reports, and optional local AI assistance without requiring paid AI services.

