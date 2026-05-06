"""
Entropy package — Layer 7 DDoS / bot detection.

Modules:
  behavioral  — extract 47 feature dimensions from raw HTTP request data
  detector    — compute entropy score and decide block/pass
  classifier  — ML ensemble intent classifier (human vs bot vs attack)
"""
