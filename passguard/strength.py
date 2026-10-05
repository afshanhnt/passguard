"""Password strength analysis based on entropy estimates and common weaknesses."""
import math
import string
from dataclasses import dataclass, field

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123",
    "password1", "iloveyou", "admin", "welcome", "letmein", "monkey",
    "dragon", "football", "baseball", "master", "login", "princess",
    "sunshine", "shadow", "superman", "qwerty123", "passw0rd", "111111",
    "000000", "trustno1", "1234567890", "654321", "starwars", "whatever",
    "987654321", "abc@123", "abcd@1234", "Admin"
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


@dataclass
class StrengthResult:
    score: int            # 0 (very weak) to 4 (very strong)
    label: str
    entropy_bits: float
    feedback: list = field(default_factory=list)


def _pool_size(password: str) -> int:
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    if any(c not in string.printable for c in password):
        pool += 100  # rough allowance for unicode characters
    return max(pool, 1)


def _has_sequence(password: str, length: int = 4) -> bool:
    """Detect runs like 'abcd', '4321' or keyboard rows like 'qwer'."""
    p = password.lower()
    for i in range(len(p) - length + 1):
        chunk = p[i:i + length]
        for row in KEYBOARD_ROWS:
            if chunk in row or chunk in row[::-1]:
                return True
        codes = [ord(c) for c in chunk]
        diffs = {codes[j + 1] - codes[j] for j in range(length - 1)}
        if diffs in ({1}, {-1}):
            return True
    return False


def _has_repeats(password: str, length: int = 3) -> bool:
    return any(len(set(password[i:i + length])) == 1
               for i in range(len(password) - length + 1))


def analyze(password: str) -> StrengthResult:
    feedback = []
    if not password:
        return StrengthResult(0, "Very weak", 0.0, ["Password is empty."])

    entropy = len(password) * math.log2(_pool_size(password))

    if password.lower() in COMMON_PASSWORDS:
        return StrengthResult(0, "Very weak", min(entropy, 10.0),
                              ["This is one of the most commonly used passwords."])

    if len(password) < 12:
        feedback.append("Use at least 12 characters.")
    if password.lower() == password or password.upper() == password:
        feedback.append("Mix uppercase and lowercase letters.")
    if not any(c.isdigit() for c in password):
        feedback.append("Add some digits.")
    if not any(c in string.punctuation for c in password):
        feedback.append("Add some symbols.")
    if _has_sequence(password):
        feedback.append("Avoid sequences like 'abcd', '1234' or 'qwer'.")
        entropy *= 0.7
    if _has_repeats(password):
        feedback.append("Avoid repeated characters like 'aaa'.")
        entropy *= 0.8

    if entropy < 28:
        score, label = 0, "Very weak"
    elif entropy < 36:
        score, label = 1, "Weak"
    elif entropy < 60:
        score, label = 2, "Fair"
    elif entropy < 80:
        score, label = 3, "Strong"
    else:
        score, label = 4, "Very strong"

    if not feedback:
        feedback.append("Looks good. A password manager is the best way to store it.")
    return StrengthResult(score, label, round(entropy, 1), feedback)
