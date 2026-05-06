"""
Continuous Dojo — adversarial training loop.

Modules:
  fuzzer   — generate novel attack payloads
  sandbox  — test defences against each payload in isolation
  trainer  — retrain the ML model when enough new samples accumulate
"""
