# Prompt 00 — Repository Comprehension Check

Use this before any implementation task.

---

Read `AGENTS.md` and `README_START_HERE.md`, then follow their links to the relevant repository docs.

Do not modify files.

Summarize:

1. the v0.1 research goal,
2. the exact in-scope and out-of-scope features,
3. the difference between Page, Endpoint, InputPoint, and VulnerabilityCandidate,
4. why FeatureVector belongs to InputPoint,
5. why ranking unit is InputPoint x VulnerabilityType,
6. why RankScore is not vulnerability probability,
7. the one-at-a-time probe invariant,
8. the role of the legacy WHSPIDER code,
9. the required implementation/test/review loop,
10. any contradiction, ambiguity, or stale-looking rule across the docs.

For every contradiction, cite the exact file sections involved.

Do not propose code yet. The purpose is to prove that repository guidance is internally legible before implementation starts.
