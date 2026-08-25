#!/usr/bin/env python3
"""Cypture eval skorlama: bulunan bulguları beklenen sınıflarla eşler.

Kullanım:
    python3 score.py expected/juice-shop.json findings.json

findings.json: bir bulgu nesnesi DİZİSİ (engine /cyp/findings.json formatı ya da
DB /api/scans/<id>/findings -> {"findings":[...]}). Her bulgu: title, severity,
vuln_type, endpoint, verified, confidence alanları (eksikler tolere edilir).
"""
import json
import re
import sys


def load_findings(path):
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, dict):
        data = data.get("findings", data.get("expected_classes", []))
    return data if isinstance(data, list) else []


def finding_text(fnd):
    parts = [str(fnd.get(k, "")) for k in ("title", "vuln_type", "type", "name", "endpoint", "evidence", "description")]
    return " ".join(parts).lower()


def main():
    if len(sys.argv) != 3:
        print("kullanım: score.py <expected.json> <findings.json>", file=sys.stderr)
        sys.exit(2)
    with open(sys.argv[1]) as f:
        spec = json.load(f)
    findings = load_findings(sys.argv[2])
    classes = spec.get("expected_classes", [])

    texts = [finding_text(f) for f in findings]
    found, missing = [], []
    matched_finding_idx = set()

    for c in classes:
        pats = [re.compile(p, re.I) for p in c.get("match", [])]
        hit = False
        for i, t in enumerate(texts):
            if any(p.search(t) for p in pats):
                hit = True
                matched_finding_idx.add(i)
        (found if hit else missing).append(c["class"])

    total_expected = len(classes) or 1
    recall = len(found) / total_expected
    precision = (len(matched_finding_idx) / len(findings)) if findings else 0.0
    verified = sum(1 for f in findings if f.get("verified") is True)
    verified_rate = (verified / len(findings)) if findings else 0.0

    print("=" * 56)
    print(f"  Hedef            : {spec.get('target', '?')}")
    print(f"  Toplam bulgu     : {len(findings)}")
    print(f"  Beklenen sınıf   : {len(classes)}")
    print("-" * 56)
    print(f"  RECALL (kapsam)  : {recall:.0%}   ({len(found)}/{len(classes)} sınıf bulundu)")
    print(f"  PRECISION (kaba) : {precision:.0%}   (beklenenle eşleşen / toplam bulgu)")
    print(f"  VERIFIED oranı   : {verified_rate:.0%}   ({verified}/{len(findings)} doğrulanmış)")
    print("-" * 56)
    print(f"  Bulunan sınıflar : {', '.join(found) or '—'}")
    print(f"  EKSİK sınıflar   : {', '.join(missing) or '— (hepsi bulundu)'}")
    print("=" * 56)
    # Makine-okunur özet (CI / trend takibi için son satır JSON).
    print(json.dumps({
        "recall": round(recall, 3), "precision": round(precision, 3),
        "verified_rate": round(verified_rate, 3),
        "found": found, "missing": missing,
        "total_findings": len(findings), "expected": len(classes),
    }))


if __name__ == "__main__":
    main()
