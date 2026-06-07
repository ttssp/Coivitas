"""Python conformance test package (the full cross-language alignment set).

Design principles
-----------------
- 1:1 naming mapping with ``tests/conformance/*.test.ts``
- Shares fixtures with ``tests/fixtures/conformance/`` (the single authoritative source)
- Every ``assert`` hits a production-code contract (to prevent self-equal false positives)
"""
