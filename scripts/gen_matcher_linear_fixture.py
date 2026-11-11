"""Record the matcher answers tests/test_matcher_linear.py compares against.

The fixture holds one CRC-32 per input (prompt, kit text, kit list reply); the inputs
themselves are generated at run time from a fixed seed by the test module, so nothing
from git history is stored. Run once, from a checkout WITH git history, under the same
environment the tests use (the Hermes SDK on PYTHONPATH):

    python scripts/gen_matcher_linear_fixture.py [--spec <commit>:matcher.py]

``--spec`` defaults to the test's ``BASE_SPEC`` (the matcher before the linear rewrite).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    sys.path.insert(0, str(REPO))
    import tests.test_matcher_linear as t  # noqa: PLC0415  (needs sys.path first)

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--spec", default=t.BASE_SPEC)
    args = parser.parse_args(argv)
    t.BASE_SPEC = args.spec
    base = t.load_base()
    data = {"schema": "defuzz.matcher_linear_expected/1", "base": args.spec, "seed": t.SEED}
    data.update(t.recorded_answers(base))
    t.FIXTURE_PATH.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"wrote {t.FIXTURE_PATH.relative_to(REPO)}: "
          + ", ".join(f"{k}={len(v)}" for k, v in data.items() if isinstance(v, list)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
