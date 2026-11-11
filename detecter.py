#!/usr/bin/env python3
"""
Анализирует исходник решения на наличие канареечных маркеров.
Использование: python3 checker.py <submission.cpp> <participant_id> [--salt v1]
Выводит JSON с флагами. Решение о наказании НЕ принимает.
"""
import argparse
import json
import re
import sys

from generate import make_canary, make_var_name


SUSPICIOUS_PATTERNS = {
    "mentions_canary_word": r"CANARY",
    "mentions_debug": r"\bdebug\b",
    "writes_stderr": r"(stderr|cerr|System\.err|console\.error)",
    "mentions_qvp": r"qvp_",
    "reads_stdin_directly": r"\bcin\b|\bscanf\b|\binput\s*\(",
}


def analyze(path: str, participant_id: str, salt: str):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        src = f.read()

    expected_canary = make_canary(participant_id, salt)
    expected_var = make_var_name(participant_id)

    flags = {
        "expected_canary": expected_canary,
        "expected_var": expected_var,
        "has_own_canary": expected_canary in src,
        "has_own_var": expected_var in src,
        "foreign_canary": False,
        "foreign_var": False,
        "writes_stderr": bool(re.search(SUSPICIOUS_PATTERNS["writes_stderr"], src)),
        "mentions_canary_word": bool(re.search(SUSPICIOUS_PATTERNS["mentions_canary_word"], src)),
        "foreign_canaries": [],
        "foreign_vars": [],
    }

    # Ищем любые чужие канарейки (10 hex uppercase после CANARY-)
    for m in re.finditer(r"CANARY-([0-9A-F]{10})", src):
        c = m.group(1)
        if c != expected_canary:
            flags["foreign_canary"] = True
            flags["foreign_canaries"].append(c)

    # Ищем чужие qvp_ переменные
    for m in re.finditer(r"qvp_[a-z0-9]{6}", src):
        v = m.group(0)
        if v != expected_var:
            flags["foreign_var"] = True
            flags["foreign_vars"].append(v)

    # Итоговая «подозрительность» — просто счётчик, не приговор
    score = 0
    score += 2 if flags["has_own_canary"] else 0
    score += 1 if flags["has_own_var"] else 0
    score += 5 if flags["foreign_canary"] else 0
    score += 3 if flags["foreign_var"] else 0
    score += 1 if flags["writes_stderr"] else 0
    score += 1 if flags["mentions_canary_word"] and not flags["has_own_canary"] else 0
    flags["score"] = score
    flags["verdict"] = (
        "high" if score >= 5 else
        "medium" if score >= 2 else
        "low"
    )
    return flags


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("submission")
    ap.add_argument("participant_id")
    ap.add_argument("--salt", default="v1")
    args = ap.parse_args()

    result = analyze(args.submission, args.participant_id, args.salt)
    json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
