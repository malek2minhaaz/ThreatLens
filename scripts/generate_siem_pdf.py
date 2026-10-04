#!/usr/bin/env python3
"""
Generate the SIEM Custom Correlation Rules report as a formatted PDF.
"""

from fpdf import FPDF
from datetime import datetime


class SIEMReportPDF(FPDF):
    def __init__(self):
        super().__init__("P", "mm", "A4")
        self.set_auto_page_break(True, 20)
        try:
            self.add_font("Arial", "", r"C:\\Windows\\Fonts\\arial.ttf", uni=True)
            self.add_font("Arial", "B", r"C:\\Windows\\Fonts\\arialbd.ttf", uni=True)
            self.add_font("Consolas", "", r"C:\\Windows\\Fonts\\consola.ttf", uni=True)
            self.add_font("Consolas", "B", r"C:\\Windows\\Fonts\\consolab.ttf", uni=True)
        except Exception:
            self.add_font("Arial", "", "", uni=True)
            self.add_font("Arial", "B", "", uni=True)
            self.add_font("Consolas", "", "", uni=True)
            self.add_font("Consolas", "B", "", uni=True)

    def header(self):
        if self.page_no() > 1:
            self.set_font("Arial", "", 8)
            self.set_text_color(100, 100, 100)
            self.cell(0, 5, "SIEM Custom Correlation Rules Report", align="L")
            self.cell(0, 5, f"Page {self.page_no()}", align="R", new_x="LMARGIN", new_y="NEXT")
            self.line(10, 12, 200, 12)
            self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "", 7)
        self.set_text_color(128, 128, 128)
        self.cell(
            0,
            10,
            f"Elevanceskills Internship Submission | Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            align="C",
        )

    def chapter_title(self, title):
        self.set_font("Arial", "B", 15)
        self.set_text_color(26, 109, 181)
        self.cell(0, 9, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)
        self.set_draw_color(34, 211, 238)
        self.set_line_width(0.5)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)

    def section_title(self, title):
        self.set_font("Arial", "B", 11)
        self.set_text_color(34, 34, 34)
        self.cell(0, 7, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def subsection_title(self, title):
        self.set_font("Arial", "B", 10)
        self.set_text_color(60, 60, 60)
        self.cell(0, 6, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def body_text(self, text):
        self.set_font("Arial", "", 10)
        self.set_text_color(40, 40, 40)
        self.multi_cell(0, 5.5, text, align="L")
        self.ln(2)

    def bullet(self, text, indent=8):
        self.set_font("Arial", "", 10)
        self.set_text_color(40, 40, 40)
        x = self.get_x()
        self.set_x(x + indent)
        self.cell(4, 5.5, "\u2022")
        self.multi_cell(180 - indent, 5.5, text)
        self.ln(1)

    def code_block(self, text):
        self.set_font("Consolas", "", 8)
        self.set_text_color(50, 50, 50)
        self.set_fill_color(245, 245, 245)
        lines = text.count("\n") + 1
        if self.get_y() + lines * 4.3 > 270:
            self.add_page()
        self.set_x(14)
        self.multi_cell(182, 4.2, text, fill=True)
        self.ln(3)

    def rule_box(self, lines):
        self.set_font("Consolas", "", 8)
        self.set_text_color(40, 40, 40)
        self.set_fill_color(235, 241, 250)
        self.set_draw_color(26, 109, 181)
        lines_count = lines.count("\n") + 1
        if self.get_y() + lines_count * 4.3 > 270:
            self.add_page()
        self.set_x(12)
        self.multi_cell(186, 4.2, lines, fill=True, border=1)
        self.ln(3)


def build_pdf(output_path):
    pdf = SIEMReportPDF()
    pdf.add_page()

    pdf.chapter_title("Custom SIEM Correlation Rules for Credential Stuffing, DNS Tunnelling, and PowerShell Exploitation")

    pdf.section_title("1. Overview")
    pdf.body_text(
        "This report shows how to design, implement, and test custom correlation rules in a SIEM, "
        "using an ELK-based stack as the working example. The focus is on three attack techniques that are "
        "common, high-signal when telemetry exists, and often noisy if rules are tuned poorly:"
    )
    pdf.bullet("Credential stuffing")
    pdf.bullet("DNS tunnelling")
    pdf.bullet("PowerShell exploitation")
    pdf.body_text(
        "A correlation rule is not just a single keyword search. In a SIEM context, it usually means a query "
        "or pipeline that watches for related events over time and raises an alert when the pattern suggests an "
        "attack, not just a routine operation. The best rules combine good log sources, enough context to "
        "distinguish legitimate use from abuse, thresholds or sequencing that reduce false positives, and "
        "validation with realistic test data before production use."
    )
    pdf.body_text(
        "This report is structured as a practical internship deliverable. It explains the methodology first, "
        "then walks through each attack technique with rule intent, data requirements, example detection logic, "
        "tuning considerations, and testing guidance."
    )

    pdf.chapter_title("2. General Rule Development Process")

    pdf.section_title("2.1 Start with the technique, not the query")
    pdf.body_text(
        "For each technique, define what the attacker is trying to achieve, which systems see the activity, what "
        "normal behavior looks like, what abusive behavior looks like, which logs are required to see it, and what "
        "could create false positives. This keeps the rule tied to the actual attack rather than to a convenient log field."
    )

    pdf.section_title("2.2 Confirm the required telemetry")
    pdf.body_text(
        "Correlation rules only work if the SIEM can see the activity. For the three techniques in this report, useful "
        "telemetry typically includes:"
    )
    pdf.bullet("Authentication logs, application login logs, SSO/IdP logs")
    pdf.bullet("DNS query logs")
    pdf.bullet("Network proxy or firewall logs")
    pdf.bullet("Endpoint process telemetry, especially command-line and script execution events")
    pdf.bullet("EDR or shell-monitoring data where available")
    pdf.bullet("Application or API request logs for login endpoints and rate-limit events")
    pdf.body_text(
        "If a required source is missing, the first deliverable should be a telemetry gap note, not a rule that cannot "
        "be validated."
    )

    pdf.section_title("2.3 Choose the rule type")
    pdf.body_text(
        "In an ELK-style environment, detection can be implemented in several ways:"
    )
    pdf.bullet("Simple event-based rules for obvious patterns")
    pdf.bullet("Correlation or sequence rules for multi-event behaviors")
    pdf.bullet("Aggregation rules for volume-based detection, such as repeated failed logins")
    pdf.bullet("Anomaly or threshold-based rules for behavior that deviates from baseline")
    pdf.body_text(
        "The right type depends on the technique. Credential stuffing is often a volume and pattern problem, while "
        "PowerShell exploitation may require sequencing of execution, command-line context, and follow-on actions."
    )

    pdf.section_title("2.4 Write the rule logic")
    pdf.body_text(
        "A good rule definition should state the name and technique it addresses, the log sources used, the event criteria, "
        "the time window, the threshold or sequence conditions, the expected alert context, and tuning notes. If possible, "
        "map the rule to a known technique taxonomy such as MITRE ATT&CK so the detection has a clear security meaning."
    )

    pdf.section_title("2.5 Test before deployment")
    pdf.body_text(
        "Testing should cover positive cases that should trigger the rule, negative cases that should not, edge cases such "
        "as bursts, retries, legitimate automation, and known benign tools, and sensitivity checks at different thresholds or "
        "windows. Testing is not complete until you know both how the rule fires and how often it might fire incorrectly."
    )

    pdf.section_title("2.6 Tune and document")
    pdf.body_text(
        "After testing, adjust thresholds, lookback windows, the scope of source IPs, users, or destinations, and exclusion "
        "logic for known-good activity. Document the expected false-positive profile and the kind of investigation each alert "
        "should trigger."
    )

    pdf.chapter_title("3. Credential Stuffing")

    pdf.section_title("3.1 What the technique looks like")
    pdf.body_text(
        "Credential stuffing is the use of large numbers of stolen username and password pairs against login interfaces. "
        "The hallmark is not a single failed login, but many authentication attempts across many accounts, often from a small "
        "number of sources or with shared tooling characteristics."
    )
    pdf.body_text("Typical indicators include:")
    pdf.bullet("High rates of failed logins")
    pdf.bullet("Many distinct accounts targeted from the same source or in the same time window")
    pdf.bullet("Logins using credentials that appear in known breached datasets, if that data is available")
    pdf.bullet("Unusual geographic or device patterns compared with the user's normal access")
    pdf.bullet("Successful logins following many failures, especially from new locations or devices")

    pdf.section_title("3.2 Required log sources")
    pdf.body_text("Strong detection usually needs:")
    pdf.bullet("Authentication failure and success events")
    pdf.bullet("Source IP, user agent, and timestamp")
    pdf.bullet("Account or username identity")
    pdf.bullet("Session or device context where available")
    pdf.bullet("Rate-limiting or abuse-mitigation logs from the application or SSO layer")
    pdf.body_text(
        "If only failed-login counts are available, detection is still possible but weaker and noisier."
    )

    pdf.section_title("3.3 Rule intent")
    pdf.body_text(
        "The rule should surface sequences that look like automated reuse of credentials rather than a user who simply forgot "
        "a password. A strong rule should distinguish one user with several failures, which is usually not stuffing, from many "
        "users targeted from the same source in a short period, which is higher concern. High failure volume followed by a success "
        "is also higher concern, as is login attempts with randomised or suspicious client behavior."
    )

    pdf.section_title("3.4 Example detection logic")
    pdf.body_text(
        "A practical correlation approach can combine several signals: failure rate per source IP or subnet over a short window, "
        "the number of distinct accounts attempted from the same source, rapid repeated attempts with minimal delay between them, "
        "optional success shortly after many failures from the same source, and optional known malicious user-agent patterns."
    )
    pdf.rule_box(
        "RULE CONCEPT — CREDENTIAL STUFFING\n"
        "WINDOW: 5 to 15 minutes\n"
        "IF source_ip generates failed login attempts against many distinct accounts above a defined threshold\n"
        "THEN raise alert\n"
        "IF source_ip shows many failures and then a success for one of those accounts\n"
        "THEN raise higher-severity alert\n"
        "IF failure volume AND account diversity both exceed threshold\n"
        "THEN include the combination in alert context"
    )

    pdf.section_title("3.5 Tuning considerations")
    pdf.body_text("Credential stuffing rules can be noisy if they are too broad. Common tuning levers include:")
    pdf.bullet("Thresholds for failed attempts and distinct accounts")
    pdf.bullet("Time windows")
    pdf.bullet("Whether to alert on a single IP or also on aggregated source groups")
    pdf.bullet("Whether to require a success event for higher severity")
    pdf.bullet("Exclusion of known authentication health checks or internal scanning where appropriate")
    pdf.body_text(
        "Be careful not to tune away real attacks by requiring an unrealistically high threshold. The rule should be sensitive "
        "enough to catch automated campaigns, but specific enough to avoid alerting on a single confused user."
    )

    pdf.section_title("3.6 False-positive risks")
    pdf.body_text("Likely false-positive sources include:")
    pdf.bullet("Users repeatedly entering the wrong password")
    pdf.bullet("Automated synchronisation or API clients with stale credentials")
    pdf.bullet("Password reset or account unlock activity")
    pdf.bullet("Load testing or internal QA activity")
    pdf.bullet("Misconfigured applications retrying authentication")
    pdf.body_text(
        "These should be identified during testing so they can be excluded or deprioritised."
    )

    pdf.section_title("3.7 How to test it")
    pdf.body_text("Test the rule against sample data that represents both benign and malicious behavior.")
    pdf.body_text("Positive test cases:")
    pdf.bullet("A source IP attempting logins against many different accounts in a short period")
    pdf.bullet("A burst of failures followed by one success")
    pdf.bullet("A pattern of attempts with consistent timing suggestive of automation")
    pdf.body_text("Negative test cases:")
    pdf.bullet("A single user failing several times and then succeeding")
    pdf.bullet("A small number of failures spread over a long period")
    pdf.bullet("Legitimate password reset activity")
    pdf.body_text("Validation checklist:")
    pdf.bullet("Does the rule fire for the simulated stuffing pattern?")
    pdf.bullet("Does it stay silent for ordinary individual failures?")
    pdf.bullet("Does the alert include the source IP, targeted accounts, time window, and failure count?")
    pdf.bullet("Does severity change appropriately when a success follows many failures?")
    pdf.bullet("Does the rule behave acceptably when volume is high but account diversity is low?")
    pdf.body_text(
        "If possible, reproduce test events in a non-production environment and verify both the alert and the accompanying context."
    )

    pdf.chapter_title("4. DNS Tunnelling")

    pdf.section_title("4.1 What the technique looks like")
    pdf.body_text(
        "DNS tunnelling uses DNS queries and responses to carry data or commands outside the intended channel. It is attractive "
        "to attackers because DNS is usually allowed and often less closely monitored than HTTP or other traffic."
    )
    pdf.body_text("Common signs include:")
    pdf.bullet("Unusually large DNS queries or responses")
    pdf.bullet("High volume of DNS queries from a single host")
    pdf.bullet("Many queries with long or unusually encoded hostnames")
    pdf.bullet("Repeated queries to the same uncommon domain or subdomain pattern")
    pdf.bullet("Query patterns that look like encoded data rather than normal human-readable names")
    pdf.bullet("Use of low-reputation or newly observed domains in an unusual way")

    pdf.section_title("4.2 Required log sources")
    pdf.body_text("Good detection depends on DNS logging that captures enough detail:")
    pdf.bullet("Query timestamp")
    pdf.bullet("Source host or IP")
    pdf.bullet("Query name")
    pdf.bullet("Query type")
    pdf.bullet("Response details where available")
    pdf.bullet("Domain or subdomain structure")
    pdf.bullet("Optional: response size, flags, or resolution result")
    pdf.body_text(
        "Network security logs can add context, such as which internal hosts are generating abnormal DNS traffic."
    )

    pdf.section_title("4.3 Rule intent")
    pdf.body_text(
        "The rule should identify DNS usage that does not match normal host behavior and is consistent with covert data movement "
        "or command-and-control via DNS. Rather than relying on one magic pattern, the strongest approaches use a mix of volume "
        "anomalies, query length or entropy anomalies, unusual query name structure, repeated contact with suspicious domains, and "
        "deviation from a host's normal DNS behavior."
    )

    pdf.section_title("4.4 Example detection logic")
    pdf.body_text(
        "One approach is an aggregation and anomaly rule. For each host, measure DNS query volume over a window, flag hosts whose "
        "query volume is much higher than expected, look for a high proportion of long, oddly structured, or highly varying subdomain "
        "names, and flag repeated queries to rare or suspicious domains."
    )
    pdf.body_text("Another approach is pattern-based:")
    pdf.bullet("Alert on DNS queries where the query name is unusually long or contains high-entropy strings")
    pdf.bullet("Alert when a single host generates many such queries in a short period")
    pdf.bullet("Combine with reputation signals where available")
    pdf.rule_box(
        "RULE CONCEPT — DNS TUNNELLING\n"
        "WINDOW: short-term host-level aggregation\n"
        "IF a host generates an unusually high count of DNS queries with long or randomly appearing subdomains\n"
        "THEN raise an alert\n"
        "IF those queries concentrate on one domain that is rare in the environment\n"
        "THEN increase severity\n"
        "IF the host also shows other suspicious behavior\n"
        "THEN correlate that into a broader investigation alert"
    )

    pdf.section_title("4.5 Tuning considerations")
    pdf.body_text("DNS rules must be tuned carefully because legitimate services can sometimes look unusual.")
    pdf.body_text("Useful tuning factors:")
    pdf.bullet("Baseline DNS behavior per host or per subnet")
    pdf.bullet("Normal domains used by the organization")
    pdf.bullet("Known internal or vendor domains that generate many queries")
    pdf.bullet("Time window and volume thresholds")
    pdf.bullet("Minimum query name length or entropy threshold, if used")
    pdf.bullet("Whether to alert on first occurrence or require repetition")
    pdf.body_text(
        "A rule that fires on any long DNS name will likely create too many false positives. It is usually better to require both "
        "unusual structure and unusual volume or repetition."
    )

    pdf.section_title("4.6 False-positive risks")
    pdf.body_text("Common sources of noise include:")
    pdf.bullet("Software updates and package registries")
    pdf.bullet("Telemetry or analytics services")
    pdf.bullet("CDNs and dynamic resource lookups")
    pdf.bullet("VPN or productivity tools that use many subdomains")
    pdf.bullet("Legitimate internal services with automated name generation")
    pdf.body_text(
        "During testing, identify which normal services create the busiest or longest query patterns so they can be baselined or "
        "excluded where appropriate."
    )

    pdf.section_title("4.7 How to test it")
    pdf.body_text("Positive test cases:")
    pdf.bullet("A host generating many high-entropy or long DNS queries in a short period")
    pdf.bullet("Repeated queries to a single uncommon domain with randomised subdomains")
    pdf.bullet("A spike in DNS traffic from a host that normally has low DNS volume")
    pdf.body_text("Negative test cases:")
    pdf.bullet("Normal browsing and application activity with ordinary DNS patterns")
    pdf.bullet("Periodic but expected lookups to known services")
    pdf.bullet("A single unusual DNS query without repetition or volume")
    pdf.body_text("Validation checklist:")
    pdf.bullet("Does the rule fire only when both anomaly and repetition signals are present?")
    pdf.bullet("Does it avoid flagging a single odd-looking query?")
    pdf.bullet("Does the alert include source host, domain, query count, and time window?")
    pdf.bullet("Can you distinguish suspicious tunneling-like patterns from a legitimate high-volume DNS client?")
    pdf.bullet("Does the rule hold up when tested against realistic internal traffic patterns?")
    pdf.body_text(
        "If DNS logs are available in a non-production environment, replay or construct representative events to check both detection "
        "and noise levels."
    )

    pdf.chapter_title("5. PowerShell Exploitation")

    pdf.section_title("5.1 What the technique looks like")
    pdf.body_text(
        "PowerShell is a powerful administration tool, which also makes it useful to attackers for execution, discovery, downloading "
        "payloads, and lateral movement. The risk is not PowerShell itself, but how it is used."
    )
    pdf.body_text("Suspicious use often includes:")
    pdf.bullet("PowerShell invoked from unexpected parent processes")
    pdf.bullet("Command lines that download or decode content")
    pdf.bullet("Use of obfuscated or encoded commands")
    pdf.bullet("Attempts to bypass constraints or hide activity")
    pdf.bullet("PowerShell used to launch or inject into other processes")
    pdf.bullet("Unusual scripting activity on workstations or servers that do not normally use PowerShell in that way")

    pdf.section_title("5.2 Required log sources")
    pdf.body_text("Better detection usually needs:")
    pdf.bullet("Process creation events")
    pdf.bullet("Parent process information")
    pdf.bullet("Full or meaningful command-line capture")
    pdf.bullet("User context")
    pdf.bullet("Host and timestamp")
    pdf.bullet("Script block logging or module logging where available")
    pdf.bullet("EDR telemetry for follow-on behavior such as network connections, file writes, or injection")
    pdf.body_text(
        "If command-line logging is limited, detection becomes harder and more reliant on process ancestry and outcomes."
    )

    pdf.section_title("5.3 Rule intent")
    pdf.body_text(
        "The rule should highlight PowerShell usage that is either intrinsically risky or inconsistent with the host's normal "
        "administration patterns. Detection can be built around high-risk command-line features or arguments, suspicious "
        "parent-child relationships, execution of downloaded or encoded content, scripting behavior on systems that rarely use "
        "PowerShell, and sequences where PowerShell execution is followed by further suspicious actions."
    )

    pdf.section_title("5.4 Example detection logic")
    pdf.body_text(
        "A strong approach uses layered rules rather than one giant pattern."
    )
    pdf.body_text("Layer 1: high-risk command-line indicators")
    pdf.bullet("Alert on PowerShell commands that include download or request features, decoding features, execution features, or other behaviors associated with payload handling")
    pdf.bullet("Alert on heavily obfuscated command lines, especially when combined with encoded commands")
    pdf.body_text("Layer 2: context-based correlation")
    pdf.bullet("Alert when PowerShell is spawned by an unexpected parent process, such as a browser, office application, or other user-facing process where scripting is not normally expected")
    pdf.bullet("Alert when PowerShell use occurs on a host or by a user outside normal patterns")
    pdf.body_text("Layer 3: sequence-based correlation")
    pdf.bullet("If PowerShell execution is followed by suspicious network connections, file writes to unusual locations, or process creation patterns of concern, raise a higher-severity alert")
    pdf.rule_box(
        "RULE CONCEPT — POWERSHELL EXPLOITATION\n"
        "LAYER 1: Flag PowerShell with encoded/obfuscated arguments or features commonly used to download or run additional content\n"
        "LAYER 2: If that execution comes from a suspicious parent or an unusual host context, escalate\n"
        "LAYER 3: If additional suspicious actions follow within a short window, correlate them into a possible exploitation event"
    )

    pdf.section_title("5.5 Tuning considerations")
    pdf.body_text(
        "PowerShell rules can easily become too noisy if they rely on presence alone. Focus on the most suspicious command-line "
        "features first, use parent-process and host context to reduce benign administrative noise, use allowlists carefully and only "
        "for well-understood verifiable use cases, prefer correlation over single-event alerting where possible, and keep the rule "
        "tied to behaviors that are hard to explain as normal administration. If in doubt, lower severity rather than silently "
        "disabling detection."
    )

    pdf.section_title("5.6 False-positive risks")
    pdf.body_text("Typical false positives include:")
    pdf.bullet("Legitimate administrative scripts")
    pdf.bullet("Software installation or management tools that use PowerShell")
    pdf.bullet("Automated configuration management")
    pdf.bullet("Helpdesk or support activity")
    pdf.bullet("Developers or power users running scripts locally")
    pdf.body_text(
        "These should be mapped during testing so the rule can distinguish everyday use from abuse."
    )

    pdf.section_title("5.7 How to test it")
    pdf.body_text("Positive test cases:")
    pdf.bullet("PowerShell launched from an unexpected parent process with suspicious command-line features")
    pdf.bullet("Encoded or obfuscated command execution")
    pdf.bullet("PowerShell activity followed by a suspicious network connection or file operation in the same window")
    pdf.body_text("Negative test cases:")
    pdf.bullet("Normal admin script execution in an expected context")
    pdf.bullet("Routine software deployment or configuration activity")
    pdf.bullet("Low-risk PowerShell commands without suspicious features")
    pdf.body_text("Validation checklist:")
    pdf.bullet("Does the rule fire for risky PowerShell usage but not for routine admin scripts?")
    pdf.bullet("Does parent-process and host context change the alert correctly?")
    pdf.bullet("Does the alert provide enough detail to justify investigation, including command line, parent process, user, and host?")
    pdf.bullet("Does sequence correlation improve confidence without hiding suspicious activity?")
    pdf.bullet("Does the rule avoid flagging every PowerShell execution in the environment?")
    pdf.body_text(
        "Because PowerShell detection depends heavily on logging quality, testing should also confirm that the necessary fields are "
        "actually being captured and searchable."
    )

    pdf.chapter_title("6. Testing and Validation Strategy")

    pdf.section_title("6.1 Define test objectives")
    pdf.body_text(
        "For each rule, decide what a successful test means. The rule should detect the intended technique, should not drown "
        "analysts in false alerts, should provide actionable context, and should behave predictably when conditions change."
    )

    pdf.section_title("6.2 Build representative test data")
    pdf.body_text(
        "Use a mix of simulated attack events, normal activity events, and edge cases such as retries, bursts, and partial patterns. "
        "If possible, create test events that are as close as possible to the real log schema used in the SIEM. Testing with the wrong "
        "field names or formats can hide problems until deployment."
    )

    pdf.section_title("6.3 Use a structured validation approach")
    pdf.body_text("For each rule, validate:")
    pdf.bullet("Detection: does it fire for the intended pattern?")
    pdf.bullet("Specificity: does it avoid firing for obvious benign cases?")
    pdf.bullet("Context: does the alert contain the fields needed to triage it?")
    pdf.bullet("Threshold behavior: does severity or alert frequency change in sensible ways?")
    pdf.bullet("Robustness: does the rule still make sense under higher event volumes?")

    pdf.section_title("6.4 Review false positives and missed detections")
    pdf.body_text(
        "After testing, classify outcomes as true positive, false positive, false negative, or low-confidence case. Use these results "
        "to adjust thresholds, add context, or improve log coverage."
    )

    pdf.section_title("6.5 Operationalize carefully")
    pdf.body_text(
        "Before production use, document the rule's purpose, data dependencies, and known limitations, set alert severity and routing, "
        "define initial response steps, identify who owns tuning and who reviews alerts, and plan for periodic review so rules stay "
        "relevant as systems and attackers change."
    )

    pdf.chapter_title("7. Suggested Rule Summary")

    pdf.section_title("7.1 Credential stuffing")
    pdf.bullet("Detect high volumes of authentication failures across many accounts from shared sources")
    pdf.bullet("Escalate when failures are followed by a success")
    pdf.bullet("Tune by threshold, window, account diversity, and client behavior")
    pdf.bullet("Validate against both individual user mistakes and automated retry patterns")

    pdf.section_title("7.2 DNS tunnelling")
    pdf.bullet("Detect abnormal DNS volume and unusual query name structure")
    pdf.bullet("Combine anomaly signals with repetition or rare-domain usage")
    pdf.bullet("Baseline normal host and service behavior before raising alerts")
    pdf.bullet("Validate against legitimate high-volume DNS clients and single odd queries")

    pdf.section_title("7.3 PowerShell exploitation")
    pdf.bullet("Detect high-risk PowerShell command-line patterns and suspicious process ancestry")
    pdf.bullet("Correlate with host context and follow-on suspicious actions")
    pdf.bullet("Use layered rules to reduce noise while preserving visibility")
    pdf.bullet("Validate against both malicious usage and legitimate administrative scripts")

    pdf.chapter_title("8. Conclusion")
    pdf.body_text(
        "Custom correlation rules work best when they are built around the attack technique, supported by the right logs, and tested "
        "against realistic behavior before deployment. Credential stuffing, DNS tunnelling, and PowerShell exploitation each require "
        "different detection strategies: volume and pattern analysis for credential stuffing, anomaly and structure analysis for DNS "
        "tunnelling, and command-line, parent-process, and sequence analysis for PowerShell exploitation."
    )
    pdf.body_text(
        "The most common failure mode is not a lack of rule ideas, but weak telemetry, poor thresholds, or insufficient testing. A "
        "repeatable process of requirements, log coverage, rule logic, test data, tuning, and validation will produce rules that are "
        "far more useful in practice than one-off queries alone."
    )
    pdf.body_text(
        "For an internship deliverable, the strongest submission pairs the rule concept with proof that it was tested, explains what "
        "the rule catches, what it misses, and what would be needed to improve it. That shows both detection thinking and operational "
        "maturity."
    )

    pdf.output(output_path)
    return output_path


if __name__ == "__main__":
    from pathlib import Path
    output_dir = Path(__file__).resolve().parent.parent / "docs" / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    out = build_pdf(str(output_dir / "siem-correlation-rules-report.pdf"))
    print("PDF generated:", out)
