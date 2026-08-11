/* ============================================================
   ThreatLens — Learn page (learn.html)
   Example library + Spot-the-Phish quiz
   ============================================================ */
"use strict";

(function () {
  if (!App.isAuthed()) return;
  const { $ } = App;

  /* ---------------- Tabs ---------------- */

  const tabs = Array.from(document.querySelectorAll(".tool-tab"));
  tabs.forEach((tab) =>
    tab.addEventListener("click", () => {
      tabs.forEach((t) => {
        const active = t === tab;
        t.classList.toggle("is-active", active);
        t.setAttribute("aria-selected", String(active));
      });
      document.querySelectorAll(".tool-panel").forEach((p) => {
        p.hidden = p.id !== "panel-" + tab.dataset.tab;
      });
    })
  );

  /* ---------------- Example library ---------------- */

  const EXAMPLES = [
    {
      title: "Account suspension scare",
      verdict: "PHISHING",
      content: `From: "PayPal Security" <security@paypal-verify-account.tk>
Reply-To: scammer1337@gmail.com
Subject: URGENT: account suspended

Dear valued customer, we detected unusual activity. Your account will be
CLOSED within 24 hours. Click here to verify: https://paypal-login-verify.tk/confirm`,
      signs: [
        "Generic greeting ('valued customer') — a real company uses your name",
        "Sender domain 'paypal-verify-account.tk' is a .tk lookalike of paypal.com",
        "Reply-To points to a free Gmail account",
        "Urgency + threat of closure pressures you to act without thinking",
        "The link's domain doesn't match the claimed sender",
      ],
    },
    {
      title: "The fake invoice",
      verdict: "PHISHING",
      content: `From: "Invoice" <invoice@dropbox-shared.link>
Subject: Your receipt #84721 — action needed

Dear customer, your invoice is attached. If you didn't order this, please
review and dispute it within 24 hours: https://dropbox-shared.link/invoice`,
      signs: [
        "Unfamiliar sender claiming to be a well-known brand",
        "'Invoice' attachments/links are a classic malware delivery trick",
        "Shortener-style domain hides the real destination",
        "Creates urgency to make you click before checking",
      ],
    },
    {
      title: "The prize scam SMS",
      verdict: "PHISHING",
      content: `Congratulations! Your phone number has won a $500 Walmart gift card.
Claim it now at https://walmart-gift-today.top/claim before it expires.
Text STOP to opt out.`,
      signs: [
        "You can't win a prize you never entered",
        "Suspicious TLD '.top' and brand lookalike domain",
        "Urgency ('before it expires')",
        "SMS prizes are a near-universal scam pattern",
      ],
    },
    {
      title: "A legitimate email (for contrast)",
      verdict: "SAFE",
      content: `From: "Netflix" <info@mailer.netflix.com>
Subject: We've updated our terms of service

Hi Alex,

You can read the updated terms here: https://help.netflix.com/legal/termsofuse.
No action needed — just letting you know.`,
      signs: [
        "Addressed by name",
        "Sender domain is a real subdomain of netflix.com",
        "No urgency, threats or requests for credentials",
        "The link goes to the official help domain",
      ],
    },
  ];

  function renderExamples() {
    $("learnExamples").innerHTML = EXAMPLES.map(
      (ex) => `
      <div class="panel example-card">
        <div class="example-card__head">
          <h3 class="panel-title" style="margin:0">${App.escapeHtml(ex.title)}</h3>
          <span class="verdict-badge ${App.verdictClass(ex.verdict)}">${ex.verdict}</span>
        </div>
        <pre class="example-card__content mono">${App.escapeHtml(ex.content)}</pre>
        <div class="example-card__signs">
          ${ex.signs.map((s) => `<div class="sign-row">${App.escapeHtml(s)}</div>`).join("")}
        </div>
      </div>`
    ).join("");
  }

  /* ---------------- Quiz ---------------- */

  const QUIZ = [
    {
      prompt: "Phish or legit?",
      content: `From: "Microsoft Account Team" <alerts@microsoft-security-alert.info>
Subject: Your password expires in 24 hours

Dear customer, your password is about to expire. Sign in now to keep your
account active: https://microsoft-account-alert.info/verify`,
      options: [
        { text: "Phishing", phish: true },
        { text: "Legitimate", phish: false },
      ],
      explanation: "Phishing. 'microsoft-security-alert.info' is not a Microsoft domain, and real companies never email a bare 'expires in 24 hours' password ultimatum.",
    },
    {
      prompt: "Phish or legit?",
      content: `From: "Alex's bank" <notifications@alexbank.com>
Subject: Your monthly statement is ready

Hi Alex, your March statement is ready to view. Download it from our secure
portal: https://alexbank.com/statements`,
      options: [
        { text: "Phishing", phish: false },
        { text: "Legitimate", phish: true },
      ],
      explanation: "Legitimate-looking: personal greeting, correct official domain (alexbank.com), no pressure, no credential requests. (Still verify the domain carefully in real life.)",
    },
    {
      prompt: "Which single clue is the STRONGEST phishing signal?",
      content: `From: "Apple" <support@apple.com>
Reply-To: refunds2026@gmail.com
Subject: Your refund is waiting — reply within 24 hours or lose it!`,
      options: [
        { text: "From claims to be 'Apple'", phish: false },
        { text: "Reply-To is a free Gmail address", phish: true },
        { text: "The subject is all lowercase", phish: false },
      ],
      explanation: "A Reply-To address that differs from the claimed sender is a classic spoofing red flag — replies go straight to the attacker.",
    },
    {
      prompt: "Phish or legit?",
      content: `SMS: "Your package is on hold! Confirm your delivery address now or it will be returned: http://usp-delivery.xyz/track"`,
      options: [
        { text: "Phishing", phish: true },
        { text: "Legitimate", phish: false },
      ],
      explanation: "Phishing. 'usp-delivery.xyz' mimics USPS, uses the sketchy .xyz TLD, and shipping companies don't text you a random link to confirm a hold.",
    },
    {
      prompt: "A colleague forwards you this email. Safe to click?",
      content: `From: "Shared Document" <documents@we-transfer-downloads.cc>
Subject: Invoice_pdf_FINAL_2026

Hi, I've shared a document with you. Click to download: https://we-transfer-downloads.cc/invoice`,
      options: [
        { text: "Yes — it's from a colleague", phish: false },
        { text: "No — verify the sender and domain first", phish: true },
      ],
      explanation: "No. 'WeTransfer' would send from wetransfer.com. Lookalike domains + unexpected file downloads are how malware spreads.",
    },
  ];

  let quizIndex = 0;
  let quizScore = 0;
  let quizAnswered = false;

  function renderQuizQuestion() {
    quizAnswered = false;
    const q = QUIZ[quizIndex];
    $("quizCounter").textContent = `Question ${quizIndex + 1} / ${QUIZ.length}`;
    $("quizProgressFill").style.width = `${(quizIndex / QUIZ.length) * 100}%`;
    $("quizMessage").innerHTML = `<p class="quiz-prompt">${App.escapeHtml(q.prompt)}</p><pre class="quiz-message__content mono">${App.escapeHtml(q.content)}</pre>`;
    $("quizOptions").innerHTML = q.options
      .map(
        (opt, i) =>
          `<button class="btn btn--ghost quiz-option" data-i="${i}">${App.escapeHtml(opt.text)}</button>`
      )
      .join("");
    $("quizExplanation").hidden = true;
    $("quizNextBtn").hidden = true;

    $("quizOptions").querySelectorAll("[data-i]").forEach((btn) =>
      btn.addEventListener("click", () => answerQuiz(Number(btn.dataset.i), btn))
    );
  }

  function answerQuiz(choiceIdx, btn) {
    if (quizAnswered) return;
    quizAnswered = true;
    const q = QUIZ[quizIndex];
    const correct = q.options.findIndex((o) => o.phish === true);
    const isCorrect = choiceIdx === correct;

    if (isCorrect) quizScore += 1;
    const chosen = q.options[choiceIdx];
    if (chosen.phish) btn.classList.add("is-correct");
    else btn.classList.add("is-wrong");
    $("quizOptions").querySelectorAll("[data-i]").forEach((b) => (b.disabled = true));
    if (correct !== choiceIdx) $("quizOptions").querySelector(`[data-i="${correct}"]`).classList.add("is-correct");

    const exp = $("quizExplanation");
    exp.hidden = false;
    exp.innerHTML = `<b>${isCorrect ? "✅ Correct" : "❌ Not quite"}.</b> ${App.escapeHtml(q.explanation)}`;
    $("quizNextBtn").hidden = false;
  }

  function renderQuizResult() {
    const pct = Math.round((quizScore / QUIZ.length) * 100);
    $("quizResultScore").textContent = `${quizScore} / ${QUIZ.length} (${pct}%)`;
    $("quizResultText").textContent =
      pct === 100 ? "Perfect score — you're phish-proof. 🛡️"
      : pct >= 60 ? "Good instincts — review the library and try again to sharpen up."
      : "Keep studying the example library — those red flags matter.";
    $("quizIntro").hidden = true;
    $("quizQuestion").hidden = true;
    $("quizResult").hidden = false;
  }

  $("quizStartBtn").addEventListener("click", () => {
    quizIndex = 0;
    quizScore = 0;
    $("quizIntro").hidden = true;
    $("quizResult").hidden = true;
    $("quizQuestion").hidden = false;
    renderQuizQuestion();
  });

  $("quizNextBtn").addEventListener("click", () => {
    quizIndex += 1;
    if (quizIndex >= QUIZ.length) renderQuizResult();
    else renderQuizQuestion();
  });

  $("quizRetryBtn").addEventListener("click", () => $("quizStartBtn").click());

  renderExamples();
})();
