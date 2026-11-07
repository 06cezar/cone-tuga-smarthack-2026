"""The chat behind the Întreabă page (specs/contracts.md, section reply): the one place a future model plugs in
(NFR-06), so the page never changes.

It answers the last message as answer_question does: from the scan's findings and our fixed texts, with no network
and no key. Only when CONETUGA_LLM_MODEL names a local model (off by default) may an answer that cites findings come
back rephrased by it, checked against the scan (conetuga/explain/llm.py). Earlier messages are only checked for their
form, never read for meaning, repeated or sent anywhere: they are the user's own (untrusted, NFR-03) or ours.
"""
from conetuga.explain import llm
from conetuga.explain.narrate import MODES
from conetuga.explain.qa import MAX_QUESTION_CHARS, Answer, answer_question, read_question
from conetuga.explain.template import LANGUAGES

# A conversation longer than this is refused: the page keeps only the latest messages, and the limit keeps a pasted
# or scripted flood out of the checks below (NFR-03).
MAX_MESSAGES = 40
USER, ASSISTANT = "user", "assistant"  # the only roles a message may have


def reply(messages: list[dict], result, lang: str, mode: str) -> Answer:
    """The answer to the conversation's last message, which must be the user's, in Romanian or English.

    `mode` ("simple" or "advanced") doesn't change the retrieval answer; it sets the tone of the optional local model.
    Raises KeyError for an unknown language or mode, and ValueError for a malformed conversation and for every case
    where answer_question raises it (an empty or too long question, a scan in error).
    """
    if lang not in LANGUAGES:
        raise KeyError(lang)
    if mode not in MODES:
        raise KeyError(mode)
    check_conversation(messages)
    question = messages[-1]["text"]
    answer = answer_question(question, result, lang)
    # Only an answer about something the question names, with the findings it cites, may be rephrased; the fixed
    # sentences and the "most dangerous" answer stay word for word (the UI's headline says the same).
    if llm.model_name() and answer.citations and read_question(question, result).names_something():
        return llm.rephrase(answer, result, lang, mode)
    return answer


def check_conversation(messages: list[dict]) -> None:
    """Raise ValueError unless the conversation has 1 to MAX_MESSAGES well-formed messages and ends with the user's."""
    if not messages:
        raise ValueError("there is no message to answer")
    if len(messages) > MAX_MESSAGES:
        raise ValueError(f"the conversation has more than {MAX_MESSAGES} messages")
    for message in messages:
        if not isinstance(message, dict) or message.get("role") not in (USER, ASSISTANT):
            raise ValueError("every message is a dict whose role is 'user' or 'assistant'")
        if not isinstance(message.get("text"), str):
            raise ValueError("every message has a text")
        # Our own answers may be long; a user's message has answer_question's limit, even an earlier one.
        if message["role"] == USER and len(message["text"].strip()) > MAX_QUESTION_CHARS:
            raise ValueError(f"a question is longer than {MAX_QUESTION_CHARS} characters")
    if messages[-1]["role"] != USER:
        raise ValueError("the last message must be the user's")
