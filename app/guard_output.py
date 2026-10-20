"""Parse complete classifier fields without matching category substrings."""
import re

CATEGORIES = (
    "Violent", "Non-violent Illegal Acts", "Sexual Content or Sexual Acts", "PII",
    "Suicide & Self-Harm", "Unethical Acts", "Politically Sensitive Topics",
    "Copyright Violation", "Jailbreak", "Cyberattack",
)


def parse_guard_output(raw):
    safety = re.search(r"^Safety:\s*(Safe|Unsafe|Controversial)\s*$", raw, re.I | re.M)
    if not safety:
        raise RuntimeError("Guard model returned no valid safety classification")
    categories = []
    field = re.search(r"^Categories:\s*([^\r\n]*)", raw, re.I | re.M)
    if field:
        canonical = {c.lower(): c for c in CATEGORIES}
        for item in field.group(1).split(","):
            value = canonical.get(item.strip().lower())
            if value and value not in categories:
                categories.append(value)
    refusal = re.search(r"^Refusal:\s*(Yes|No)\s*$", raw, re.I | re.M)
    return safety.group(1).capitalize(), categories, refusal.group(1).capitalize() if refusal else None
