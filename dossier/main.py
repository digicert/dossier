import argparse
import datetime
import logging
import sys

import httpx
from dateutil import parser as datetime_parser

from dossier import revocation, ccadb_client, processor, report

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--full-report-threshold",
        type=int,
        default=10000,
        help="Certificate count threshold where the full report is generated (default: 10000)",
    )
    parser.add_argument(
        "--show-progress", action="store_true", help="Show progress bars"
    )
    parser.add_argument(
        "--output-file",
        type=argparse.FileType("w"),
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
        "incident_discovery_datetime",
        type=datetime_parser.isoparse,
        help="Date and time when the incident was discovered in ISO 8601 format (e.g. 2025-07-29T15:00:00Z)",
    )
    parser.add_argument(
        "revocation_window",
        choices=["24h", "5d", "7d"],
        help="Time allowed for revocation after incident discovery. Options: 24h, 5d, 7d.",
    )
    parser.add_argument(
        "input_files",
        help="Paths to .pem files, .csv files, or .zip files containing .pem files",
        nargs="+",
        type=argparse.FileType("rb"),
    )

    args = parser.parse_args()

    revocation_window = revocation.RevocationWindow.from_string(args.revocation_window)

    http_client = httpx.Client(timeout=30.0, headers={"User-Agent": "dossier/1.0"})

    now = datetime.datetime.now(tz=datetime.timezone.utc)

    ccadb = ccadb_client.CcadbClient(http_client, now)
    classifier = revocation.RevocationClassifier(
        revocation_window, args.incident_discovery_datetime, now
    )

    revocation_manager = revocation.RevocationManager(
        http_client, ccadb, classifier, now
    )

    proc = processor.Processor(revocation_manager, args.show_progress)
    entries = proc.process_files(args.input_files)

    if len(entries) >= args.full_report_threshold:
        report.write_link_report(entries, args.output_file)
    else:
        report.write_full_report(entries, args.output_file)


if __name__ == "__main__":
    main()
