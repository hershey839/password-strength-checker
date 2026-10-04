"use strict";

/* =====================================================
   PART 1 — THE LOGIC (no DOM here, so it is easy to test)
   ===================================================== */

// A small list of very common passwords. Real attackers try these first.
const COMMON_PASSWORDS = [
  "password", "password1", "password123", "passw0rd", "123456", "1234567", "12345678",
  "123456789", "1234567890", "qwerty", "qwerty123", "qwertyuiop", "abc123", "letmein",
  "welcome", "admin", "administrator", "iloveyou", "monkey", "dragon", "football",
  "baseball", "master", "sunshine", "princess", "login", "starwars", "whatever",
  "trustno1", "shadow", "superman", "batman", "hello", "freedom", "secret", "default",
  "guest", "root", "test", "changeme", "000000", "111111", "121212", "654321",
  "666666", "123123", "123321", "zaq12wsx", "asdfgh", "asdfghjkl", "zxcvbn",
  "zxcvbnm", "1q2w3e4r", "1qaz2wsx", "pass", "mypassword", "welcome1", "google",
  "india", "cricket", "krishna", "ganesh", "lovely", "computer", "internet"
];

// Rows of a keyboard — typing along a row is a very predictable pattern.
const KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"];

// Common "leet speak" swaps, e.g. p@ssw0rd -> password
const LEET = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i" };

const GUESSES_PER_SECOND = 1e10; // a fast offline attack on a weak hash

const SETS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  number: "0123456789",
  special: "!@#$%^&*()-_=+[]{};:,.?"
};

/* ---- Character-type checks ---- */
function getChecks(pw) {
  return {
    length: pw.length >= 8,
    upper: /[A-Z]/.test(pw),
    lower: /[a-z]/.test(pw),
    number: /[0-9]/.test(pw),
    special: /[^A-Za-z0-9]/.test(pw)
  };
}

/* ---- Is it (or is it based on) a common password? ---- */
function isCommon(pw) {
  const lower = pw.toLowerCase();
  const variants = [lower, lower.split("").map(c => LEET[c] || c).join("")];
  return variants.some(v => {
    if (COMMON_PASSWORDS.includes(v)) return true;
    // "Password1!" -> remove numbers/symbols stuck on the end or start
    const trimmed = v.replace(/^[^a-z]+|[^a-z]+$/g, "");
    return trimmed.length >= 4 && COMMON_PASSWORDS.includes(trimmed);
  });
}

/* ---- Find repeated / sequential / keyboard patterns ----
   Returns which kinds were found, plus a list of positions that are
   "predictable" (they add almost no extra difficulty for an attacker). */
function findPatterns(pw) {
  const lower = pw.toLowerCase();
  const free = new Array(pw.length).fill(false);
  const found = { repeat: false, sequence: false, keyboard: false };

  // Repeats: 3 or more of the same character in a row (aaa, 1111)
  for (let i = 0; i < pw.length; ) {
    let j = i;
    while (j + 1 < pw.length && pw[j + 1] === pw[i]) j++;
    if (j - i + 1 >= 3) {
      found.repeat = true;
      for (let k = i + 1; k <= j; k++) free[k] = true;
    }
    i = j + 1;
  }

  // Sequences: 3 or more letters/digits going up or down by one (abc, 1234, 987)
  const isAlnum = c => /[a-z0-9]/.test(c);
  for (let i = 0; i < lower.length - 2; i++) {
    for (const step of [1, -1]) {
      let j = i;
      while (
        j + 1 < lower.length &&
        isAlnum(lower[j]) && isAlnum(lower[j + 1]) &&
        lower.charCodeAt(j + 1) - lower.charCodeAt(j) === step
      ) j++;
      if (j - i + 1 >= 3) {
        found.sequence = true;
        for (let k = i + 1; k <= j; k++) free[k] = true;
      }
    }
  }

  // Keyboard runs: 4 keys side by side (qwer, asdf), forwards or backwards
  for (let i = 0; i + 4 <= lower.length; i++) {
    const chunk = lower.slice(i, i + 4);
    const reversed = chunk.split("").reverse().join("");
    if (KEYBOARD_ROWS.some(row => row.includes(chunk) || row.includes(reversed))) {
      found.keyboard = true;
      for (let k = i + 1; k < i + 4; k++) free[k] = true;
    }
  }

  return { found, effectiveLength: Math.max(1, free.filter(f => !f).length) };
}

/* ---- Entropy = how many "bits of randomness" the password has ----
   Each extra bit doubles the number of guesses an attacker needs. */
function charsetSize(checks) {
  let size = 0;
  if (checks.lower) size += 26;
  if (checks.upper) size += 26;
  if (checks.number) size += 10;
  if (checks.special) size += 33;
  return size;
}

/* ---- Turn seconds into a friendly sentence ---- */
function formatTime(seconds) {
  const MIN = 60, HOUR = 3600, DAY = 86400, MONTH = DAY * 30, YEAR = DAY * 365;
  if (seconds < 1) return "Instantly";
  if (seconds < MIN) return `${Math.round(seconds)} seconds`;
  if (seconds < HOUR) return `${Math.round(seconds / MIN)} minutes`;
  if (seconds < DAY) return `${Math.round(seconds / HOUR)} hours`;
  if (seconds < MONTH) return `${Math.round(seconds / DAY)} days`;
  if (seconds < YEAR) return `${Math.round(seconds / MONTH)} months`;
  const years = seconds / YEAR;
  if (years < 1000) return `${Math.round(years).toLocaleString("en-US")} years`;
  if (years < 1e6) return `${Math.round(years / 1e3).toLocaleString("en-US")} thousand years`;
  if (years < 1e9) return `${Math.round(years / 1e6).toLocaleString("en-US")} million years`;
  if (years < 1e12) return `${Math.round(years / 1e9).toLocaleString("en-US")} billion years`;
  return "Over a trillion years";
}

const LEVELS = ["Weak", "Medium", "Strong", "Very Strong"];

/* ---- The main function: password in, full report out ---- */
function evaluate(pw) {
  const checks = getChecks(pw);
  const common = isCommon(pw);
  const { found, effectiveLength } = findPatterns(pw);

  let entropy = effectiveLength * Math.log2(charsetSize(checks) || 1);
  if (common) entropy = Math.min(entropy, 12); // attackers guess these almost immediately

  // Strength level from entropy; short passwords can never be better than Weak
  let level = entropy < 40 ? 0 : entropy < 60 ? 1 : entropy < 80 ? 2 : 3;
  if (pw.length < 8) level = 0;

  // On average an attacker finds it after trying half of all possibilities
  const seconds = Math.pow(2, entropy - 1) / GUESSES_PER_SECOND;

  // Build the improvement tips
  const tips = [];
  if (common) tips.push({ type: "warn", text: "This is (or is based on) a very common password. Attackers try these first — pick something unique." });
  if (found.repeat) tips.push({ type: "warn", text: "Avoid repeated characters like “aaa” or “111”." });
  if (found.sequence) tips.push({ type: "warn", text: "Avoid sequences like “abc” or “1234”." });
  if (found.keyboard) tips.push({ type: "warn", text: "Avoid keyboard patterns like “qwer” or “asdf”." });
  if (pw.length < 8) tips.push({ type: "info", text: `Use at least 8 characters (you have ${pw.length}).` });
  else if (pw.length < 12) tips.push({ type: "info", text: "Aim for 12 or more characters — length helps the most." });
  if (!checks.upper) tips.push({ type: "info", text: "Add an uppercase letter." });
  if (!checks.lower) tips.push({ type: "info", text: "Add a lowercase letter." });
  if (!checks.number) tips.push({ type: "info", text: "Add a number." });
  if (!checks.special) tips.push({ type: "info", text: "Add a special character such as ! @ # $ %." });
  if (tips.length === 0) tips.push({ type: "good", text: "Looks great! Use a different password for every account, ideally with a password manager." });

  return {
    checks, level, label: LEVELS[level], entropy, tips,
    percent: Math.min(100, Math.max(6, entropy)),
    crackTime: formatTime(seconds)
  };
}

/* ---- Secure random password generator ----
   Uses crypto.getRandomValues (unpredictable), NOT Math.random (guessable). */
function secureRandomInt(max) {
  const limit = Math.floor(0x100000000 / max) * max; // avoids "modulo bias"
  const buf = new Uint32Array(1);
  do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
  return buf[0] % max;
}

function generatePassword(length = 16) {
  const pools = Object.values(SETS);
  const all = pools.join("");
  // Start with one character from each group so every requirement is met...
  const chars = pools.map(p => p[secureRandomInt(p.length)]);
  // ...fill the rest from all groups...
  while (chars.length < length) chars.push(all[secureRandomInt(all.length)]);
  // ...then shuffle (Fisher–Yates) so the guaranteed ones aren't always first.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}

/* =====================================================
   PART 2 — THE PAGE (connects the logic to the HTML)
   ===================================================== */
function initApp() {
  const $ = id => document.getElementById(id);
  const input = $("password");
  const meter = $("meter");
  const fill = $("meterFill");
  const label = $("strengthLabel");
  const strengthBlock = label.closest("section");
  const crackTime = $("crackTime");
  const suggestions = $("suggestions");
  const copyBtn = $("copyBtn");
  const toast = $("toast");
  const visToggle = $("visibilityToggle");
  const themeToggle = $("themeToggle");
  const root = document.documentElement;
  let toastTimer;

  // Redraw everything every time the password changes
  function render() {
    const pw = input.value;
    const checklistItems = document.querySelectorAll("#checklist li");
    copyBtn.disabled = pw.length === 0;

    // Empty input: reset to the starting state
    if (!pw) {
      meter.className = "meter";
      strengthBlock.className = "block";
      fill.style.width = "0%";
      meter.setAttribute("aria-valuenow", "0");
      label.textContent = "Not entered yet";
      crackTime.textContent = "—";
      checklistItems.forEach(li => li.classList.remove("met"));
      suggestions.innerHTML = "<li>Start typing and your tips will show up here.</li>";
      return;
    }

    const r = evaluate(pw);

    // Meter: width + colour class (level-0 ... level-3)
    meter.className = `meter level-${r.level}`;
    strengthBlock.className = `block level-${r.level}`;
    fill.style.width = `${r.percent}%`;
    meter.setAttribute("aria-valuenow", String(Math.round(r.percent)));
    label.textContent = r.label;
    crackTime.textContent = r.crackTime;

    // Checklist ticks
    checklistItems.forEach(li => li.classList.toggle("met", r.checks[li.dataset.check]));

    // Tips (built with textContent, so nothing typed can ever run as HTML)
    suggestions.replaceChildren(...r.tips.map(t => {
      const li = document.createElement("li");
      li.textContent = t.text;
      if (t.type !== "info") li.className = t.type;
      return li;
    }));
  }

  function showToast(message) {
    toast.textContent = message;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (toast.textContent = ""), 2500);
  }

  function setVisible(visible) {
    input.type = visible ? "text" : "password";
    visToggle.setAttribute("aria-pressed", String(visible));
    visToggle.setAttribute("aria-label", visible ? "Hide password" : "Show password");
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (e) {
      // Fallback for older browsers / non-secure pages
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      let ok = false;
      try { ok = document.execCommand("copy"); } catch (err) { ok = false; }
      ta.remove();
      return ok;
    }
  }

  // ---- Events ----
  input.addEventListener("input", render);
  visToggle.addEventListener("click", () => setVisible(input.type === "password"));

  $("generateBtn").addEventListener("click", () => {
    input.value = generatePassword(16);
    setVisible(true); // show it so the user can see what was made
    render();
    showToast("New password generated. Copy it before you leave!");
  });

  copyBtn.addEventListener("click", async () => {
    const ok = await copyText(input.value);
    showToast(ok ? "Copied to clipboard!" : "Couldn’t copy — select the text and copy it manually.");
  });

  themeToggle.addEventListener("click", () => {
    const next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    themeToggle.setAttribute("aria-label", next === "dark" ? "Switch to light mode" : "Switch to dark mode");
    try { localStorage.setItem("theme", next); } catch (e) { /* storage blocked: ignore */ }
  });
  themeToggle.setAttribute("aria-label", root.getAttribute("data-theme") === "dark" ? "Switch to light mode" : "Switch to dark mode");

  render();
}

// Run in the browser; export for Node tests otherwise.
if (typeof document !== "undefined") {
  initApp();
} else if (typeof module !== "undefined") {
  module.exports = { evaluate, isCommon, findPatterns, formatTime, generatePassword };
}
