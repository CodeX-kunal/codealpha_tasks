"""CLI:  python main.py --input sample_data/incoming.csv --db records.db"""
import argparse
import csv
from collections import Counter

from dedup import DedupPipeline
from dedup.repository import Repository


def main():
    ap = argparse.ArgumentParser(description="Data Redundancy Removal System")
    ap.add_argument("--input", required=True, help="CSV with columns: name,email,phone,address")
    ap.add_argument("--db", default="records.db")
    ap.add_argument("--report", default="decisions.csv")
    args = ap.parse_args()

    repo = Repository(args.db)
    pipeline = DedupPipeline(repo)

    with open(args.input, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    decisions = pipeline.process_batch(rows)

    with open(args.report, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["row", "name", "email", "status", "inserted", "reason"])
        for i, (r, d) in enumerate(zip(rows, decisions), start=2):
            w.writerow([i, r.get("name"), r.get("email"), d.status.value, d.inserted, d.reason])
            print(f"row {i:>2}  {d.status.value:<15} {r.get('name')!s:<18} -> {d.reason}")

    counts = Counter(d.status.value for d in decisions)
    print("\nSummary:", dict(counts))
    print(f"Rows in database now: {repo.count()}  |  report: {args.report}")
    repo.close()


if __name__ == "__main__":
    main()
