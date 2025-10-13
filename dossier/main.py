import argparse
import datetime
import logging
import sys

import httpx
from dateutil import parser as datetime_parser

from dossier import revocation, ccadb_client, processor, report, statistics

_CCADB_IR_GUIDELINES_CONFORMANCE_LEVEL = "3.1"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate certificate reports conformant with CCADB Incident Reporting Guidelines v"
        + _CCADB_IR_GUIDELINES_CONFORMANCE_LEVEL
    )
    parser.add_argument(
        "--full-report-threshold",
        type=int,
        default=10000,
        help="Certificate count threshold for generating the full report (default: 10000)",
    )
    parser.add_argument(
        "--hide-progress", action="store_true", help="Hide progress bars"
    )
    parser.add_argument(
        "--output-file",
        type=lambda p: open(p, "w", encoding="utf-8", newline=""),
        help="Output file (default: stdout)",
        default=sys.stdout,
    )
    parser.add_argument(
        "--log-file",
        type=argparse.FileType("w"),
        help="Log file (default: stderr)",
        default=sys.stderr,
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        type=str.upper,
        help="Set the logging level (default: INFO)",
    )
    parser.add_argument(
        "incident_discovery_datetime",
        type=datetime_parser.isoparse,
        help="Date and time when the incident was discovered in ISO 8601 format (e.g. 20250729T150000Z)",
    )
    parser.add_argument(
        "revocation_window",
        choices=["24H", "5D", "7D"],
        type=str.upper,
        help="Time allowed for revocation after incident discovery",
    )
    parser.add_argument(
        "input_files",
        help="Paths to PEM or DER certificate files, .csv files, or .zip files containing PEM or DER certificate files",
        nargs="+",
        type=argparse.FileType("rb"),
    )

    args = parser.parse_args()

    # Set the logging level and output stream based on user arguments
    logging.basicConfig(stream=args.log_file, level=getattr(logging, args.log_level))

    revocation_window = revocation.RevocationWindow.from_string(args.revocation_window)

    http_client = httpx.Client(timeout=60.0, headers={"User-Agent": "dossier/1.0"})

    now = datetime.datetime.now(tz=datetime.timezone.utc)

    ccadb = ccadb_client.CcadbClient(http_client, now, args.hide_progress)
    classifier = revocation.RevocationClassifier(
        revocation_window, args.incident_discovery_datetime, now
    )

    revocation_manager = revocation.RevocationManager(
        http_client, ccadb, classifier, now
    )

    proc = processor.Processor(revocation_manager, args.hide_progress)
    entries = proc.process_files(args.input_files)

    if len(entries) >= args.full_report_threshold:
        report.write_link_report(entries, args.output_file)
    else:
        report.write_full_report(entries, args.output_file)

    return int(statistics.INSTANCE.error_count > 0)


if __name__ == "__main__":
    main()
