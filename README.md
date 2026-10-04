# 🔐 Password Strength Checker

A fast, private, and beginner-friendly web app that tells you how strong your password really is, how long it would take to crack, and exactly how to make it better. Built with plain HTML, CSS, and JavaScript — no frameworks, no dependencies.

**🔗 Live demo:** [https://hershey839.github.io/password-strength-checker](https://hershey839.github.io/password-strength-checker)

## Features

- **Real-time strength meter** — Weak, Medium, Strong, or Very Strong, with a colour-coded progress bar
- **Live checklist** — 8+ characters, uppercase, lowercase, number, special character
- **Weak-pattern detection** — common passwords (`password123`, `qwerty`), leet-speak variants (`P@ssw0rd`), repeated characters (`aaaa`), sequences (`1234`, `abcd`) and keyboard runs (`asdf`)
- **Time-to-crack estimate** — based on entropy and a fast offline attack (10 billion guesses/second)
- **Specific suggestions** — tells you what to fix, not just that it's weak
- **Secure password generator** — one-click 16-character password using the browser's cryptographic random generator, plus copy to clipboard
- **Show / hide toggle** for the password field
- **Dark and light mode** — remembers your choice and respects your system setting
- **Responsive and accessible** — works on phones, keyboard-friendly, screen-reader labels, respects reduced-motion settings
- **Private by design** — your password never leaves your browser

## Tech Stack

| Technology | Used for |
| --- | --- |
| HTML5 | Page structure and accessibility attributes |
| CSS3 | Layout (Flexbox/Grid), CSS variables for theming, responsive design |
| JavaScript (ES6+) | Strength logic, DOM updates, Web Crypto API for generation |
| GitHub Pages | Free hosting |

## How It Works

1. **Checks** — regular expressions test for each character type and the minimum length.
2. **Common-password check** — the lowercased password (and a "de-leeted" version, with `@`→`a`, `0`→`o`, etc.) is compared against a list of well-known passwords, after trimming numbers/symbols from the ends.
3. **Pattern detection** — the code scans for repeated characters, ascending/descending sequences, and keyboard rows. Characters inside a pattern are treated as "predictable" and don't count towards strength.
4. **Entropy** — `entropy = (effective length) × log2(size of character pool)`. Each extra bit doubles the number of guesses needed. The pool grows when you use lowercase (26), uppercase (26), digits (10), and symbols (33).
5. **Rating** — under 40 bits is Weak, 40–59 Medium, 60–79 Strong, 80+ Very Strong. Anything under 8 characters is always Weak, and common passwords are capped at a very low entropy.
6. **Time to crack** — on average an attacker needs half of all possibilities: `2^(entropy − 1) ÷ 10,000,000,000` seconds, converted to a readable unit.
7. **Generator** — uses `crypto.getRandomValues()` (not `Math.random()`), guarantees one character of each type, and shuffles with the Fisher–Yates algorithm.

> **Note:** time-to-crack is an estimate for learning purposes. Real-world results depend on how the website stores passwords and on the attacker's hardware.

## Run Locally

No installation needed.

```bash
git clone https://github.com/hershey839/password-strength-checker.git
cd password-strength-checker
```

Then double-click `index.html` to open it in your browser. (Optional: in VS Code, install the *Live Server* extension and click "Go Live" for auto-reload.)

## Project Structure

```
password-strength-checker/
├── index.html    # Page structure
├── style.css     # Styling, themes, responsive layout
├── script.js     # Logic (Part 1) and page interaction (Part 2)
├── README.md
├── LICENSE
└── .gitignore
```

## Future Improvements

- Check against a much larger breached-password list using the Have I Been Pwned *k-anonymity* API (only a hash prefix is sent, never the password)
- Add passphrase generation (e.g. four random words)
- Let users choose the generated password's length and character types
- Add unit tests for the scoring functions
- Support multiple languages
- Turn it into an installable Progressive Web App (PWA)

## License

Released under the [MIT License](LICENSE).
