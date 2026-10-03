"""Detect when the model refuses instead of helping."""

REFUSAL_PHRASES = (
    "can't assist",
    "cannot assist",
    "can't help",
    "cannot help",
    "i'm sorry, but i can't",
    "i am sorry, but i can't",
    "not able to assist",
    "unable to assist",
    "against my",
    "as an ai",
)


def is_refusal(text: str) -> bool:
    lower = text.lower()
    return any(phrase in lower for phrase in REFUSAL_PHRASES)
