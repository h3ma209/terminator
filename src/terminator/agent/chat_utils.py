"""Simple chat helpers — no model needed."""

GREETINGS = frozenset({
    "hi", "hello", "hey", "yo", "sup", "hiya", "howdy",
    "good morning", "good evening", "good night", "gm", "gn",
})


def is_greeting(text: str) -> bool:
    lower = text.lower().strip().rstrip("!.?")
    if lower in GREETINGS:
        return True
    return lower.startswith(("hi ", "hello ", "hey ")) and len(lower.split()) <= 3


def greeting_reply() -> str:
    return "Hello. I'm the terminator agent. Say /help or ask me to profile http://127.0.0.1:3000"
