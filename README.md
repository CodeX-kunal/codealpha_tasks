# Data Redundancy Removal System

Identifies and classifies incoming data as **redundant** or **false positive**, validates it, and appends
**only unique, verified** records to the database.

## How it works

```
incoming record
   |
   v
[1] Normalise  (case, spaces, punctuation, phone digits)
   |
   v
[2] Validate   (name, email format, phone length, address)  --> INVALID  (rejected)
   |
   v
[3] Exact check  (SHA-256 fingerprint, O(1) lookup)         --> REDUNDANT (rejected)
   |
   v
[4] Fuzzy check  (only against indexed candidates: same email / phone / name prefix)
   |        same person re-entered ...................... --> REDUNDANT      (rejected)
   |        looks similar but identity data conflicts ... --> FALSE_POSITIVE (verified different entity, appended)
   v
[5] Append to DB  (UNIQUE index on fingerprint = final safety net) --> UNIQUE (appended)
```

| Status | Meaning | Inserted? |
|---|---|---|
| UNIQUE | No similar record exists | Yes |
| FALSE_POSITIVE | Flagged as similar, but email/phone/address prove it is a different entity | Yes (audited) |
| REDUNDANT | Real duplicate (exact or fuzzy) | No |
| INVALID | Failed validation | No |

Every decision is written to the `audit_log` table.

## Requirement mapping

| Task requirement | Where |
|---|---|
| Classify redundant / false positive | `dedup/classifier.py` |
| Validation mechanism vs existing data | `dedup/validator.py`, `dedup/pipeline.py` |
| Prevent duplicates entering the DB | fingerprint + `UNIQUE` constraint in `dedup/repository.py` |
| Append only unique & verified data | `DedupPipeline.process()` |
| Accuracy & efficiency | indexed lookups + blocking (no full-table scan), audit log |

## Run

```bash
python main.py --input sample_data/incoming.csv --db records.db
python -m unittest discover -s tests -v
```

Input CSV columns: `name,email,phone,address`. Output: console summary + `decisions.csv`.

## Moving to the cloud (AWS)

`Repository` is the only class that touches the database. To use Amazon RDS (PostgreSQL/MySQL), reimplement
its 5 methods with `psycopg2`/`pymysql` and keep the same `UNIQUE(fingerprint)` constraint. For DynamoDB,
use `fingerprint` as the partition key with a conditional put (`attribute_not_exists(fingerprint)`).
