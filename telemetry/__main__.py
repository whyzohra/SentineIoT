"""Run the local synthetic OT telemetry generator with ``python -m telemetry``."""

import argparse
import json
import time

from telemetry.generator import NormalTelemetryGenerator


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic, local OT baseline events as JSONL.")
    parser.add_argument("--count", type=int, default=None, help="stop after this many events (default: continuous)")
    parser.add_argument("--interval", type=float, default=1.0, help="seconds between events (default: 1)")
    parser.add_argument("--seed", type=int, default=None, help="seed simulated process readings for repeatability")
    args = parser.parse_args()
    if args.interval < 0:
        parser.error("--interval must be non-negative")
    generator = NormalTelemetryGenerator(seed=args.seed)
    for event in generator.events(args.count):
        print(json.dumps(event.to_dict(), separators=(",", ":")), flush=True)
        if args.interval:
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
