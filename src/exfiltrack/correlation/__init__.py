"""USB session reconstruction, risk scoring, and confidence evaluation.

Owner: Maheesha (Dabarera G. D. M.)

The correlation engine combines multiple individually weak signals into an
explainable, rule-based score. It is deliberately not a black box: every
score contribution is traceable to a named rule and a source artifact.
"""

__all__ = ["confidence", "scoring", "sessions"]
