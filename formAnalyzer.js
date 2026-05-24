// // Event listeners for forms
// document.getElementById("testForm1").addEventListener("submit", function(e) {
//     e.preventDefault();
//     analyzeForm("testForm1");
// });
// document.getElementById("testForm2").addEventListener("submit", function(e) {
//     e.preventDefault();
//     analyzeForm("testForm2");
// });

// // Analyze form inputs
// function analyzeForm(formId) {
//     const form = document.getElementById(formId);
//     const inputs = form.querySelectorAll("input");
//     const alertsContainer = document.getElementById("alertsContainer");
//     alertsContainer.innerHTML = ""; // clear previous alerts

//     inputs.forEach(input => {
//         const value = input.value.trim();

//         if (value === "") {
//             createAlert(`${input.id} is empty`, "low");
//         } 
//         else if (input.type === "password") {
//             if (value.length < 8) createAlert(`${input.id} is too short`, "high");
//             if (value.match(/123|password|abc/i)) createAlert(`${input.id} is weak`, "medium");
//         } 
//         else if (value.match(/<script>|<\/script>/i)) {
//             createAlert(`${input.id} contains unsafe characters`, "high");
//         } 
//         else {
//             // Generic demo alerts
//             if (value.length < 5) createAlert(`${input.id} is very short`, "medium");
//             if (value.match(/test|demo/i)) createAlert(`${input.id} contains generic text`, "low");
//             if (value.length >=5 && value.length <=10) createAlert(`${input.id} is okay but could be stronger`, "low");
//             if (value.length > 10) createAlert(`${input.id} looks strong`, "medium");
//         }
//     });

//     // Animate form fade out temporarily
//     form.classList.add("submitted");
//     setTimeout(()=> form.classList.remove("submitted"), 800);

//     // Save results to localStorage
//     const results = { form: formId, timestamp: new Date().toLocaleString(), inputs: Array.from(inputs).map(i => i.value) };
//     localStorage.setItem(formId + "_lastResult", JSON.stringify(results));
// }

// // Create alerts dynamically
// function createAlert(message, severity) {
//     const alertsContainer = document.getElementById("alertsContainer");
//     const div = document.createElement("div");
//     div.classList.add("alert");
//     if (severity === "low") div.classList.add("severity-low");
//     if (severity === "medium") div.classList.add("severity-medium");
//     if (severity === "high") div.classList.add("severity-high");
//     div.innerText = message;
//     alertsContainer.appendChild(div);

//     // Animate alert slide in
//     setTimeout(()=>{
//         div.style.transition = "all 0.5s ease";
//         div.style.opacity = 1;
//         div.style.transform = "translateY(0)";
//     },50);
// }



// ---- Enhanced formAnalyzer.js (client-side, safe) ----

// Attach listeners
["testForm1","testForm2"].forEach(id => {
  const el = document.getElementById(id);
  if (el) el.addEventListener("submit", function(e){
    e.preventDefault();
    analyzeForm(id);
  });
});

// Heuristics: safe, high-level indicators only
const HEURISTICS = [
  {
    type: "XSS",
    severity: "high",
    indicator: /<\s*script\b|on\w+\s*=|javascript:/i,
    summary: "Contains HTML/script-like markup that could execute in a browser.",
    remediation: [
      "Escape or encode user output before inserting into HTML (context-aware encoding).",
      "Adopt a strict Content Security Policy (CSP) and avoid unsafe-inline.",
      "Sanitize untrusted HTML on server using a library (e.g., DOMPurify) and prefer not to render raw HTML."
    ]
  },
  {
    type: "SQL Injection (pattern)",
    severity: "high",
    // note: simple keyword heuristic — for detection only
    indicator: /\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP)\b/i,
    summary: "Contains SQL keywords — may indicate attempted injection when used in query strings.",
    remediation: [
      "Use parameterized queries / prepared statements on server side (never concat SQL with user input).",
      "Validate and whitelist expected input formats (e.g., numeric IDs).",
      "Use least-privilege DB accounts and proper error handling."
    ]
  },
  {
    type: "Command Injection (pattern)",
    severity: "high",
    indicator: /[`|;>\$&<>]\s*/i,
    summary: "Contains characters often used to chain or execute shell commands.",
    remediation: [
      "Never pass user input directly to shell commands. Use safe APIs.",
      "Validate and strictly whitelist allowed values.",
      "Run services with minimal privileges and avoid shell invocation."
    ]
  },
  {
    type: "Path Traversal",
    severity: "medium",
    indicator: /(\.\.\/|\/etc\/|\\\.\.\\)/i,
    summary: "Looks like attempts to access parent directories or sensitive paths.",
    remediation: [
      "Normalize and validate paths on server; whitelist allowed directories.",
      "Avoid exposing raw filesystem paths to users."
    ]
  },
  {
    type: "Weak Password (policy)",
    severity: "medium",
    indicator: /.{0,7}$/, // length < 8
    appliesTo: "password",
    summary: "Password too short or simple.",
    remediation: [
      "Enforce minimum length (≥ 8-12) and complexity policies where appropriate.",
      "Encourage passphrases and use password managers.",
      "Apply rate limiting and multifactor authentication."
    ]
  },
  {
    type: "Credential Reuse Indicator",
    severity: "medium",
    indicator: /password|12345|qwerty|letmein/i,
    appliesTo: "password",
    summary: "Common password phrases detected (likely reused/easy).",
    remediation: [
      "Block commonly used passwords using a denylist.",
      "Force password reset if reuse detected, and educate users."
    ]
  },
  {
    type: "Generic Suspicious (low)",
    severity: "low",
    indicator: /test|demo|sample/i,
    summary: "Generic/demo text — useful to flag for quality or test purposes.",
    remediation: [
      "Ensure test/demo placeholders are not stored in production.",
      "Validate inputs against expected patterns."
    ]
  }
];

// Analyze form and build structured alerts
function analyzeForm(formId) {
  const form = document.getElementById(formId);
  const inputs = Array.from(form.querySelectorAll("input"));
  const alertsContainer = document.getElementById("alertsContainer");
  alertsContainer.innerHTML = "";

  const results = { form: formId, timestamp: new Date().toISOString(), findings: [] };

  inputs.forEach(input => {
    const value = input.value || "";
    const inputType = input.type || "text";
    const inputMeta = { name: input.id, value: value, findings: [] };

    // Run heuristics
    HEURISTICS.forEach(h => {
      // skip password heuristics for non-password inputs
      if (h.appliesTo && h.appliesTo !== inputType) return;

      if (h.indicator.test(value)) {
        // Add finding (no exploit details)
        const finding = {
          attack_type: h.type,
          severity: h.severity,
          summary: h.summary,
          matched: h.indicator.toString() // show which heuristic matched
        };
        inputMeta.findings.push(finding);
      }
    });

    // If nothing matched, add a benign note (optional)
    if (inputMeta.findings.length === 0) {
      inputMeta.findings.push({ attack_type: "None", severity: "low", summary: "No obvious suspicious pattern detected." });
    }

    // Render alerts for this input
    inputMeta.findings.forEach(f => {
      // Build UI card with attack type, severity, short summary, and "More" that shows remediation
      createDetailedAlert({
        field: input.id,
        attack_type: f.attack_type,
        severity: f.severity,
        summary: f.summary,
        remediation: getRemediationForType(f.attack_type),
        matched: f.matched
      });
    });

    results.findings.push(inputMeta);
  });

  // temporary form animation
  form.classList.add("submitted");
  setTimeout(()=> form.classList.remove("submitted"), 800);

  // store structured results for dashboard/export (safe)
  localStorage.setItem(formId + "_lastResult", JSON.stringify(results));
}

// Return remediation list given attack type (centralized to avoid duplicating text)
function getRemediationForType(type){
  const h = HEURISTICS.find(x => x.type === type);
  return h ? h.remediation : [
    "Validate inputs on server side.",
    "Log and monitor unusual inputs.",
    "Follow secure coding practices and least privilege."
  ];
}

// Create a detailed, expandable alert card (safe, non-actionable)
function createDetailedAlert({ field, attack_type, severity, summary, remediation, matched }) {
  const container = document.getElementById("alertsContainer");

  const card = document.createElement("div");
  card.className = "alert-card";
  card.dataset.severity = severity;

  // header row
  const header = document.createElement("div");
  header.className = "alert-header";
  header.innerHTML = `<strong>${severity.toUpperCase()}</strong> — ${attack_type} detected in <em>${field}</em>`;
  card.appendChild(header);

  // summary
  const desc = document.createElement("div");
  desc.className = "alert-summary";
  desc.innerText = summary;
  card.appendChild(desc);

  // "more" toggle
  const more = document.createElement("button");
  more.className = "alert-more";
  more.innerText = "More";
  card.appendChild(more);

  // details (hidden by default)
  const details = document.createElement("div");
  details.className = "alert-details";
  details.style.display = "none";

  // matched heuristic — for transparency (not exploit)
  const matchedP = document.createElement("p");
  matchedP.innerText = `Detection rule: ${matched}`;
  details.appendChild(matchedP);

  // remediation list
  const remTitle = document.createElement("strong");
  remTitle.innerText = "Remediation:";
  details.appendChild(remTitle);

  const remList = document.createElement("ul");
  remediation.forEach(r => {
    const li = document.createElement("li"); li.innerText = r; remList.appendChild(li);
  });
  details.appendChild(remList);

  card.appendChild(details);

  more.addEventListener("click", () => {
    details.style.display = (details.style.display === "none") ? "block" : "none";
    more.innerText = (details.style.display === "none") ? "More" : "Less";
  });

  // style + animation
  card.style.opacity = 0;
  card.style.transform = "translateY(-12px)";
  container.appendChild(card);
  setTimeout(()=> { card.style.transition = "all .35s ease"; card.style.opacity = 1; card.style.transform = "translateY(0)"; }, 40);

  // auto-remove for low severity (optional)
  if (severity.toLowerCase() === "low") {
    setTimeout(()=> {
      card.style.opacity = 0; card.style.transform = "translateY(-12px)";
      setTimeout(()=> card.remove(), 900);
    }, 10000);
  }
}