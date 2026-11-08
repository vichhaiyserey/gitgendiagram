## Summary

<!-- What does this change, and why? -->

Closes #

## Task tracking

- [ ] Linked issue is referenced above (`Closes #N` or `Refs #N`)
- [ ] Linked issue has `type:*` and `priority:*` labels
- [ ] Issue status is `In Review`
- [ ] `python scripts/taskctl.py sync` was run after status changes
- [ ] Local task cache was not committed (`.secdiagram/tasks/` is gitignored)

## Verification

- [ ] `python -m unittest discover -s tests -v`
- [ ] `ruff check .`
- [ ] `mypy`
- [ ] `python -m bandit -r secdiagram_core -lll`
- [ ] `python scripts/taskctl.py validate --offline`
- [ ] Container build and smoke test (if applicable)
- [ ] Trivy image scan (if applicable)

## Notes for reviewers

<!-- Risks, follow-ups, migration notes, or screenshots. -->
