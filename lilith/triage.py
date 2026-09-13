"""
Triage loop — pipeline orchestrator.

Runs the rule-based analysis pipeline over unanalyzed connections in a
background loop. Stages: whitelist → heuristics → blocklist (Feodo /
Spamhaus ZEN) → reputation (DShield) → behavior → DNS/DGA → long-lived
connection check.

There is NO LLM stage. Lilith is a pure rule + reputation + behavior
monitor, in the spirit of classic pre-AI network analysis tools. Every
connection ends up with one of:
  - a verdict from whitelist / heuristics / blocklist / reputation /
    behavior / dns / longlived, or
  - a "clean" marker when no rule-based signal is found.
"""

import time

from .pipeline import run_pipeline

# How many connections the pipeline processes per cycle.
BATCH_SIZE = 20


def triage_once() -> int:
    """
    One cycle of the triage loop: run the pipeline over unanalyzed
    connections (whitelist → heuristics → blocklist → reputation → behavior
    → dns → long-lived).

    Returns the number of connections handled this cycle.
    """
    return run_pipeline(max_batch=BATCH_SIZE)


def triage_loop(interval_seconds=1):
    """
    Polling loop. Runs the pipeline every *interval_seconds* seconds.
    """
    print(
        f"[triage] pipeline (whitelist + heuristics + reputation + behavior) "
        f"polling every {interval_seconds}s ... Ctrl+C to stop"
    )
    while True:
        try:
            n = triage_once()
            if n:
                print(f"[triage] analyzed {n} connection(s)")
        except Exception as e:
            print(f"[triage] error: {e}")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    triage_loop()
