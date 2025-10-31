import argparse
import math
import re
from typing import Iterable, List, Optional, Dict

# Small built-in common password list for offline checks
DEFAULT_COMMON = {
    "123456",
    "password",
    "123456789",
    "12345678",
    "12345",
    "qwerty",
    "abc123",
    "111111",
    "letmein",
    "iloveyou",
}

KEYBOARD_SEQS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]


def calculate_entropy(password: str) -> float:
    """Estimate entropy in bits using pool size approach."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32

    if pool == 0 or len(password) == 0:
        return 0.0

    entropy = len(password) * math.log2(pool)
    return entropy


def has_repeated_sequence(password: str) -> bool:
    """Detect repeated substrings like abcabc, 1212, xxxx."""
    n = len(password)
    for size in range(1, n // 2 + 1):
        for i in range(n - 2 * size + 1):
            if password[i : i + size] == password[i + size : i + 2 * size]:
                return True
    return False


def has_keyboard_sequence(password: str) -> bool:
    s = password.lower()
    for seq in KEYBOARD_SEQS:
        for l in range(4, len(seq) + 1):
            for i in range(len(seq) - l + 1):
                sub = seq[i : i + l]
                if sub in s or sub[::-1] in s:
                    return True
    return False


def contains_common_password(password: str, common_passwords: Optional[Iterable[str]]) -> Optional[str]:
    if not common_passwords:
        common_passwords = DEFAULT_COMMON
    pw_lower = password.lower()
    for cp in common_passwords:
        if cp in pw_lower:
            return cp
    return None


def contains_dictionary_word(password: str, min_len: int = 4) -> Optional[str]:
    SAMPLE_WORDS = {"password", "admin", "user", "login", "welcome", "hello", "secret", "love"}
    s = password.lower()
    n = len(s)
    for l in range(min_len, n + 1):
        for i in range(0, n - l + 1):
            sub = s[i : i + l]
            if sub in SAMPLE_WORDS:
                return sub
    return None


def score_password(password: str, entropy: float, issues: List[str]) -> int:
    base = min(entropy, 60) / 60 * 80
    length_bonus = 0
    if len(password) >= 12:
        length_bonus = min(10, (len(password) - 11) * 2)

    score = base + length_bonus

    penalty = 0
    for issue in issues:
        if issue == "common":
            penalty += 40
        elif issue == "dictionary":
            penalty += 20
        elif issue == "repeat":
            penalty += 15
        elif issue == "keyboard":
            penalty += 15
        elif issue == "short_length":
            penalty += 20

    score -= penalty
    score = max(0, min(100, int(round(score))))
    return score


def suggest_improvements(password: str, issues: List[str]) -> List[str]:
    suggestions: List[str] = []
    if "short_length" in issues:
        suggestions.append("Use at least 12 characters — longer passwords are stronger.")
    if "common" in issues:
        suggestions.append("Avoid common passwords or well-known sequences (e.g., '123456', 'password').")
    if "dictionary" in issues:
        suggestions.append("Avoid complete dictionary words; mix unrelated words or use passphrases.")
    if "repeat" in issues:
        suggestions.append("Avoid repeated sequences like 'abcabc' or '121212'.")
    if "keyboard" in issues:
        suggestions.append("Avoid keyboard paths like 'qwerty' or '12345'.")

    suggestions.append("Add length and variety: uppercase, lowercase, digits, and symbols.")
    suggestions.append("Consider using a reputable password manager to generate and store strong passwords.")
    return suggestions


def assess_password(password: str, common_passwords: Optional[Iterable[str]] = None) -> Dict[str, object]:
    issues: List[str] = []

    if len(password) < 8:
        issues.append("short_length")

    cp = contains_common_password(password, common_passwords)
    if cp:
        issues.append("common")

    dw = contains_dictionary_word(password)
    if dw:
        issues.append("dictionary")

    if has_repeated_sequence(password):
        issues.append("repeat")

    if has_keyboard_sequence(password):
        issues.append("keyboard")

    entropy = calculate_entropy(password)
    score = score_password(password, entropy, issues)
    suggestions = suggest_improvements(password, issues)

    return {
        "password": password,
        "length": len(password),
        "entropy_bits": round(entropy, 2),
        "score": score,
        "issues": issues,
        "suggestions": suggestions,
    }


def _cli_main():
    parser = argparse.ArgumentParser(description="Assess password strength")
    parser.add_argument("--password", "-p", required=True, help="Password to evaluate")
    parser.add_argument("--show-json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    report = assess_password(args.password)

    if args.show_json:
        import json
        print(json.dumps(report, indent=2))
    else:
        print(f"Password: {'*' * min(10, len(args.password))} (length={report['length']})")
        print(f"Entropy: {report['entropy_bits']} bits")
        print(f"Score: {report['score']}/100")
        if report["issues"]:
            print("Issues detected:")
            for it in report["issues"]:
                print(f" - {it}")
        print("Suggestions:")
        for s in report["suggestions"]:
            print(f" - {s}")


if __name__ == "__main__":
    _cli_main()
