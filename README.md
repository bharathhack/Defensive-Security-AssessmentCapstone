# Defensive Security Assessment Capstone: Student Portal (Lab)

An authorized assessment of a **fictional student portal that I built and run on localhost**. I tested it,
fixed the highest risks, and retested to prove the fixes.

**Read first:** [REPORT.md](REPORT.md) (scope, authorization, rules of engagement, threat model, findings, retest)

## Result
| | Before (v1) | After (v2) |
|---|---|---|
| Checks passed | 0 / 10 | 10 / 10 |

## Contents
| Path | What it is |
|---|---|
| `REPORT.md` | Full assessment report |
| `app_v1_vulnerable/` | The lab app before fixes (deliberate weaknesses) |
| `app_v2_fixed/` | The same app after remediation |
| `assess.py` | Repeatable checks; refuses any non-localhost target |
| `run_assessment.sh` | Starts both versions on localhost and writes the evidence |
| `evidence/before.txt`, `evidence/after.txt` | Retest output |
| `CHECKLIST.md` | Mapping to the task's passing checklist |

## Reproduce
```bash
pip install flask==3.1.3
./run_assessment.sh
```

## Safety
- Everything binds to `127.0.0.1`. `assess.py` exits if pointed at any other host.
- All users, students and passwords are synthetic lab values. No real credentials or personal data.
- v1 is intentionally weak. Do not deploy it.
