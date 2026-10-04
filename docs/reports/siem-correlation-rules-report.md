# Custom SIEM Correlation Rules for Credential Stuffing, DNS Tunnelling, and PowerShell Exploitation

## 1. Overview

The goal of this report is to show how to design, implement, and test custom correlation rules in a SIEM, using an ELK-based stack as the working example. The focus is on three attack techniques that are common, high-signal when telemetry exists, and often noisy if rules are tuned poorly:

- Credential stuffing
- DNS tunnelling
- PowerShell exploitation

A correlation rule is not just a single keyword search. In a SIEM context, it usually means a query or pipeline that watches for related events over time and raises an alert when the pattern suggests an attack, not just a routine operation. The best rules combine:

- good log sources
- enough context to distinguish legitimate use from abuse
- thresholds or sequencing that reduce false positives
- validation with realistic test data before production use

This report is structured as a practical internship deliverable: it explains the methodology first, then walks through each attack technique with rule intent, data requirements, example detection logic, tuning considerations, and testing guidance.

---

## 2. General Rule Development Process

### 2.1 Start with the technique, not the query

For each technique, define:

- What is the attacker trying to achieve?
- Which systems see the activity?
- What does normal behavior look like?
- What does abusive behavior look like?
- Which logs are required to see it?
- What could create false positives?

This keeps the rule tied to the actual attack rather than to a convenient log field.

### 2.2 Confirm the required telemetry

Correlation rules only work if the SIEM can see the activity. For the three techniques in this report, useful telemetry typically includes:

- Authentication logs, application login logs, SSO/IdP logs
- DNS query logs
- Network proxy or firewall logs
- Endpoint process telemetry, especially command-line and script execution events
- EDR or shell-monitoring data where available
- Application or API request logs for login endpoints and rate-limit events

If a required source is missing, the first deliverable should be a telemetry gap note, not a rule that cannot be validated.

### 2.3 Choose the rule type

In an ELK-style environment, detection can be implemented in several ways:

- Simple event-based rules for obvious patterns
- Correlation or sequence rules for multi-event behaviors
- Aggregation rules for volume-based detection, such as repeated failed logins
- Anomaly or threshold-based rules for behavior that deviates from baseline

The right type depends on the technique. For example, credential stuffing is often a volume and pattern problem, while PowerShell exploitation may require sequencing of execution, command-line context, and follow-on actions.

### 2.4 Write the rule logic

A good rule definition should state:

- Name and technique it addresses
- Log sources used
- Event criteria
- Time window
- Threshold or sequence conditions
- Expected alert context
- Tuning notes

If possible, map the rule to a known technique taxonomy, such as MITRE ATT&CK, so the detection has a clear security meaning.

### 2.5 Test before deployment

Testing should cover:

- Positive cases: simulated or sample events that should trigger the rule
- Negative cases: normal activity that should not trigger the rule
- Edge cases: bursts, retries, legitimate automation, and known benign tools
- Sensitivity checks: how the rule behaves at different thresholds or windows

Testing is not complete until you know both how the rule fires and how often it might fire incorrectly.

### 2.6 Tune and document

After testing, adjust:

- Thresholds
- Lookback windows
- Scope of source IPs, users, or destinations
- Exclusion logic for known-good activity

Document the expected false-positive profile and the kind of investigation each alert should trigger.

---

## 3. Credential Stuffing

### 3.1 What the technique looks like

Credential stuffing is the use of large numbers of stolen username and password pairs against login interfaces. The hallmark is not a single failed login, but many authentication attempts across many accounts, often from a small number of sources or with shared tooling characteristics.

Typical indicators include:

- High rates of failed logins
- Many distinct accounts targeted from the same source or in the same time window
- Logins using credentials that appear in known breached datasets, if that data is available to the system
- Unusual geographic or device patterns compared with the user's normal access
- Successful logins following many failures, especially from new locations or devices

### 3.2 Required log sources

Strong detection usually needs:

- Authentication failure and success events
- Source IP, user agent, and timestamp
- Account or username identity
- Session or device context where available
- Rate-limiting or abuse-mitigation logs from the application or SSO layer

If only failed-login counts are available, detection is still possible but weaker and noisier.

### 3.3 Rule intent

The rule should surface sequences that look like automated reuse of credentials rather than a user who simply forgot a password.

A strong rule should distinguish:

- One user with several failures: usually not stuffing
- Many users targeted from the same source in a short period: higher concern
- High failure volume followed by a success: higher concern
- Login attempts with randomised or suspicious client behavior: higher concern

### 3.4 Example detection logic

A practical correlation approach can combine several signals:

- Failure rate per source IP or per subnet over a short window
- Number of distinct accounts attempted from the same source
- Presence of rapid, repeated attempts with minimal delay between them
- Optional: successful login shortly after many failures from the same source
- Optional: known malicious user-agent patterns or missing/ anomalous client headers

Example rule concept:

- Over a 5-to-15-minute window, if a source IP generates failed login attempts against many distinct accounts above a defined threshold, raise an alert.
- If a source IP shows many failures and then a success for one of those accounts, raise a higher-severity alert.
- If both failure volume and account diversity exceed threshold, include that combination in the alert context.

A complementary anomaly rule can watch for spikes in failed login volume beyond the normal baseline for an application or region.

### 3.5 Tuning considerations

Credential stuffing rules can be noisy if they are too broad. Common tuning levers include:

- Thresholds for failed attempts and distinct accounts
- Time windows
- Whether to alert on a single IP or also on aggregated source groups
- Whether to require a success event for higher severity
- Exclusion of known authentication health checks or internal scanning where appropriate

Be careful not to tune away real attacks by requiring an unrealistically high threshold. The rule should be sensitive enough to catch automated campaigns, but specific enough to avoid alerting on a single confused user.

### 3.6 False-positive risks

Likely false-positive sources include:

- Users repeatedly entering the wrong password
- Automated synchronisation or API clients with stale credentials
- Password reset or account unlock activity
- Load testing or internal QA activity
- Misconfigured applications retrying authentication

These should be identified during testing so they can be excluded or deprioritised.

### 3.7 How to test it

Test the rule against sample data that represents both benign and malicious behavior.

Positive test cases:

- A source IP attempting logins against many different accounts in a short period
- A burst of failures followed by one success
- A pattern of attempts with consistent timing suggestive of automation

Negative test cases:

- A single user failing several times and then succeeding
- A small number of failures spread over a long period
- Legitimate password reset activity

Validation checklist:

- Does the rule fire for the simulated stuffing pattern?
- Does it stay silent for ordinary individual failures?
- Does the alert include the source IP, targeted accounts, time window, and failure count?
- Does severity change appropriately when a success follows many failures?
- Does the rule behave acceptably when volume is high but account diversity is low?

If possible, reproduce test events in a non-production environment and verify both the alert and the accompanying context.

---

## 4. DNS Tunnelling

### 4.1 What the technique looks like

DNS tunnelling uses DNS queries and responses to carry data or commands outside the intended channel. It is attractive to attackers because DNS is usually allowed and often less closely monitored than HTTP or other traffic.

Common signs include:

- Unusually large DNS queries or responses
- High volume of DNS queries from a single host
- Many queries with long or unusually encoded hostnames
- Repeated queries to the same uncommon domain or subdomain pattern
- Query patterns that look like encoded data rather than normal human-readable names
- Use of low-reputation or newly observed domains in an unusual way

DNS tunnelling is not always obvious from a single event. It often emerges from patterns over time.

### 4.2 Required log sources

Good detection depends on DNS logging that captures enough detail:

- Query timestamp
- Source host or IP
- Query name
- Query type
- Response details where available
- Domain or subdomain structure
- Optional: response size, flags, or resolution result

Network security logs can add context, such as which internal hosts are generating abnormal DNS traffic.

### 4.3 Rule intent

The rule should identify DNS usage that does not match normal host behavior and is consistent with covert data movement or command-and-control via DNS.

Rather than relying on one magic pattern, the strongest approaches use a mix of:

- volume anomalies
- query length orentropy anomalies
- unusual query name structure
- repeated contact with suspicious domains
- deviation from a host's normal DNS behavior

### 4.4 Example detection logic

One approach is an aggregation and anomaly rule:

- For each host, measure DNS query volume over a window.
- Flag hosts whose query volume is much higher than expected.
- Within that set, look for high proportions of long, oddly structured, or highly varying subdomain names.
- Flag repeated queries to rare or suspicious domains.

Another approach is pattern-based:

- Alert on DNS queries where the query name is unusually long or contains high-entropy strings.
- Alert when a single host generates many such queries in a short period.
- Combine with reputation signals where available.

A practical rule concept:

- If a host generates an unusually high count of DNS queries with long or randomly appearing subdomains over a short window, raise an alert.
- If those queries concentrate on one domain that is rare in the environment, increase severity.
- If the host also shows other suspicious behavior, correlate that into a broader investigation alert.

### 4.5 Tuning considerations

DNS rules must be tuned carefully because legitimate services can sometimes look unusual.

Useful tuning factors:

- Baseline DNS behavior per host or per subnet
- Normal domains used by the organization
- Known internal or vendor domains that generate many queries
- Time window and volume thresholds
- Minimum query name length or entropy threshold, if used
- Whether to alert on first occurrence or require repetition

A rule that fires on any long DNS name will likely create too many false positives. It is usually better to require both unusual structure and unusual volume or repetition.

### 4.6 False-positive risks

Common sources of noise include:

- Software updates and package registries
- Telemetry or analytics services
- CDNs and dynamic resource lookups
- VPN or productivity tools that use many subdomains
- Legitimate internal services with automated name generation

During testing, identify which normal services create the busiest or longest query patterns so they can be baselined or excluded where appropriate.

### 4.7 How to test it

Positive test cases:

- A host generating many high-entropy or long DNS queries in a short period
- Repeated queries to a single uncommon domain with randomised subdomains
- A spike in DNS traffic from a host that normally has low DNS volume

Negative test cases:

- Normal browsing and application activity with ordinary DNS patterns
- Periodic but expected lookups to known services
- A single unusual DNS query without repetition or volume

Validation checklist:

- Does the rule fire only when both anomaly and repetition signals are present?
- Does it avoid flagging a single odd-looking query?
- Does the alert include source host, domain, query count, and time window?
- Can you distinguish suspicious tunneling-like patterns from a legitimate high-volume DNS client?
- Does the rule hold up when tested against realistic internal traffic patterns?

If DNS logs are available in a non-production environment, replay or construct representative events to check both detection and noise levels.

---

## 5. PowerShell Exploitation

### 5.1 What the technique looks like

PowerShell is a powerful administration tool, which also makes it useful to attackers for execution, discovery, downloading payloads, and lateral movement. The risk is not PowerShell itself, but how it is used.

Suspicious use often includes:

- PowerShell invoked from unexpected parent processes
- Command lines that download or decode content
- Use of obfuscated or encoded commands
- Attempts to bypass constraints or hide activity
- PowerShell used to launch or inject into other processes
- Unusual scripting activity on workstations or servers that do not normally use PowerShell in that way

Because PowerShell is also used legitimately, the detection goal is to identify risky usage patterns rather than every PowerShell invocation.

### 5.2 Required log sources

Better detection usually needs:

- Process creation events
- Parent process information
- Full or meaningful command-line capture
- User context
- Host and timestamp
- Script block logging or module logging where available
- EDR telemetry for follow-on behavior such as network connections, file writes, or injection

If command-line logging is limited, detection becomes harder and more reliant on process ancestry and outcomes.

### 5.3 Rule intent

The rule should highlight PowerShell usage that is either intrinsically risky or inconsistent with the host's normal administration patterns.

Detection can be built around:

- High-risk command-line features or arguments
- Suspicious parent-child relationships
- Execution of downloaded or encoded content
- Scripting behavior on systems that rarely use PowerShell
- Sequences where PowerShell execution is followed by further suspicious actions

### 5.4 Example detection logic

A strong approach uses layered rules rather than one giant pattern.

Layer 1: high-risk command-line indicators

- Alert on PowerShell commands that include download or request features, decoding features, execution features, or other behaviors associated with payload handling.
- Alert on heavily obfuscated command lines, especially when combined with encoded commands.

Layer 2: context-based correlation

- Alert when PowerShell is spawned by an unexpected parent process, such as a browser, office application, or other user-facing process where scripting is not normally expected.
- Alert when PowerShell use occurs on a host or by a user outside normal patterns.

Layer 3: sequence-based correlation

- If PowerShell execution is followed by suspicious network connections, file writes to unusual locations, or process creation patterns of concern, raise a higher-severity alert.

A practical rule concept:

- If PowerShell is executed with encoded or obfuscated arguments, or with features commonly used to download or run additional content, create a signal.
- If that execution comes from a suspicious parent or an unusual host context, escalate.
- If additional suspicious actions follow within a short window, correlate them into a possible exploitation event.

### 5.5 Tuning considerations

PowerShell rules can easily become too noisy if they rely on presence alone.

Tuning guidance:

- Focus on the most suspicious command-line features first
- Use parent-process and host context to reduce benign administrative noise
- Use allowlists carefully and only for well-understood, verifiable use cases
- Prefer correlation over single-event alerting where possible
- Keep the rule tied to behaviors that are hard to explain as normal administration

Also consider that tuning should not just reduce alerts, but preserve visibility into real misuse. If in doubt, lower severity rather than silently disabling detection.

### 5.6 False-positive risks

Typical false positives include:

- Legitimate administrative scripts
- Software installation or management tools that use PowerShell
- Automated configuration management
- Helpdesk or support activity
- Developers or power users running scripts locally

These should be mapped during testing so the rule can distinguish everyday use from abuse.

### 5.7 How to test it

Positive test cases:

- PowerShell launched from an unexpected parent process with suspicious command-line features
- Encoded or obfuscated command execution
- PowerShell activity followed by a suspicious network connection or file operation in the same window

Negative test cases:

- Normal admin script execution in an expected context
- Routine software deployment or configuration activity
- Low-risk PowerShell commands without suspicious features

Validation checklist:

- Does the rule fire for risky PowerShell usage but not for routine admin scripts?
- Does parent-process and host context change the alert correctly?
- Does the alert provide enough detail to justify investigation, including command line, parent process, user, and host?
- Does sequence correlation improve confidence without hiding suspicious activity?
- Does the rule avoid flagging every PowerShell execution in the environment?

Because PowerShell detection depends heavily on logging quality, testing should also confirm that the necessary fields are actually being captured and searchable.

---

## 6. Testing and Validation Strategy

### 6.1 Define test objectives

For each rule, decide what a successful test means:

- The rule detects the intended technique
- The rule does not drown analysts in false alerts
- The alert provides actionable context
- The rule behaves predictably when conditions change

### 6.2 Build representative test data

Use a mix of:

- Simulated attack events
- Normal activity events
- Edge cases such as retries, bursts, and partial patterns

If possible, create test events that are as close as possible to the real log schema used in the SIEM. Testing with the wrong field names or formats can hide problems until deployment.

### 6.3 Use a structured validation approach

For each rule, validate:

- Detection: does it fire for the intended pattern?
- Specificity: does it avoid firing for obvious benign cases?
- Context: does the alert contain the fields needed to triage it?
- Threshold behavior: does severity or alert frequency change in sensible ways?
- Robustness: does the rule still make sense under higher event volumes?

### 6.4 Review false positives and missed detections

After testing, classify outcomes:

- True positive: correct detection
- False positive: alert on benign activity
- False negative: missed detection of the simulated pattern
- Low-confidence case: fires, but needs extra context

Use these results to adjust thresholds, add context, or improve log coverage.

### 6.5 Operationalize carefully

Before production use:

- Document the rule's purpose, data dependencies, and known limitations
- Set alert severity and routing
- Define initial response steps
- Identify who owns tuning and who reviews alerts
- Plan for periodic review so rules stay relevant as systems and attackers change

---

## 7. Suggested Rule Summary

### 7.1 Credential stuffing

- Detect high volumes of authentication failures across many accounts from shared sources
- Escalate when failures are followed by a success
- Tune by threshold, window, account diversity, and client behavior
- Validate against both individual user mistakes and automated retry patterns

### 7.2 DNS tunnelling

- Detect abnormal DNS volume and unusual query name structure
- Combine anomaly signals with repetition or rare-domain usage
- Baseline normal host and service behavior before raising alerts
- Validate against legitimate high-volume DNS clients and single odd queries

### 7.3 PowerShell exploitation

- Detect high-risk PowerShell command-line patterns and suspicious process ancestry
- Correlate with host context and follow-on suspicious actions
- Use layered rules to reduce noise while preserving visibility
- Validate against both malicious usage and legitimate administrative scripts

---

## 8. Conclusion

Custom correlation rules work best when they are built around the attack technique, supported by the right logs, and tested against realistic behavior before deployment. Credential stuffing, DNS tunnelling, and PowerShell exploitation each require different detection strategies: volume and pattern analysis for credential stuffing, anomaly and structure analysis for DNS tunnelling, and command-line, parent-process, and sequence analysis for PowerShell exploitation.

The most common failure mode is not a lack of rule ideas, but weak telemetry, poor thresholds, or insufficient testing. A repeatable process of requirements, log coverage, rule logic, test data, tuning, and validation will produce rules that are far more useful in practice than one-off queries alone.

For an internship deliverable, the strongest submission pairs the rule concept with proof that it was tested, explains what the rule catches, what it misses, and what would be needed to improve it. That shows both detection thinking and operational maturity.
