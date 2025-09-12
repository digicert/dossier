import argparse
import collections
import csv
import datetime
import itertools
import json
import logging
import os
import sys

from dateutil import parser as datetime_parser
import tqdm
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import oid

from dossier import revocation, cert_loader
from dossier.report import LinkReportEntry

logging.basicConfig(stream=sys.stderr, level=logging.INFO)

logger = logging.getLogger(__name__)


def _get_dnsnames(cert):
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            x509.OID_SUBJECT_ALTERNATIVE_NAME
        )
        return ",".join(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        return ""


def _is_precert(cert):
    try:
        cert.extensions.get_extension_for_oid(oid.ExtensionOID.PRECERT_POISON)

        return True
    except x509.ExtensionNotFound:
        return False


def process_files(
    input_files,
    revocation_window,
    incident_discovery_datetime,
    output_format,
    summary_report_threshold,
    show_progress=True
):
    serial_numbers = set()

    full_report_entries = []
    summary_report_entries = []
    summary_mode = False

    for input_file in input_files:
        logging.info("Processing %s", input_file.name)

        reader = cert_loader.get_certificate_reader(input_file)
        if reader is None:
            continue

        for cert in tqdm.tqdm(reader.read(), desc=input_file.name, disable=not show_progress):
            if summary_mode:
                summary_report_entries.append(LinkReportEntry(cert.fingerprint(hashes.SHA256())))
            else:


                serial_numbers.add(cert.serial_number)

            if not summary_mode and len(serial_numbers) == summary_report_threshold:
                logging.info("Switching to summary report mode")

                # convert full report entries to summary report entries
                summary_report_entries.extend(itertools.chain(f.to_link_report_entries() for f in full_report_entries))
                full_report_entries = []

                summary_mode = True












def
def process_pem_csv(
    pem_csvs,
    output_format,
    incident_discovered,
    revocation_window,
    crtsh_flag,
    fast_threshold,
):

    if not fast_mode:
        # Normal mode variables
        year_bucket = collections.Counter()
        revoked_count = 0
        expired_without_revocation_count = 0
        valid_not_revoked_count = 0
        final_without_precert = 0
        precert_without_final = 0

    for pem_csv in pem_csv_list:
        logger.info(
            "Fast processing %s" if fast_mode else "Parsing %s",
            pem_csv.name if hasattr(pem_csv, "name") else "certificates",
        )

        for line_idx, row in tqdm.tqdm(enumerate(csv.DictReader(pem_csv))):
            pem = row.get("pem")
            if not pem:
                logger.error("No PEM found in row #%d: %s", line_idx, row)
                continue

            try:
                cert = x509.load_pem_x509_certificate(pem.encode())
            except ValueError as e:
                logger.error("Failed to parse PEM in row %s: %s", row, e)
                continue

            serial_number = hex(cert.serial_number)[2:]
            total_certs += 1

            cert_entry = all_certs.get(serial_number)
            if cert_entry is None:
                if fast_mode:
                    # Minimal data extraction for fast mode - only need serial for tracking
                    cert_entry = {}
                else:
                    # Full data extraction for normal mode
                    cert_entry = {
                        "subject": cert.subject.rfc4514_string(),
                        "issuer": cert.issuer.rfc4514_string(),
                        "not_before": cert.not_valid_before_utc.isoformat(),
                        "not_after": cert.not_valid_after_utc.isoformat(),
                        "dns_names": _get_dnsnames(cert),
                    }

                    issued_year = cert.not_valid_before_utc.year

                all_certs[serial_number] = cert_entry

            # Extract fingerprints for both modes
            fingerprint_key = (
                "precert_fingerprint_sha256"
                if _is_precert(cert)
                else "final_cert_fingerprint_sha256"
            )
            if not fast_mode and fingerprint_key in cert_entry:
                logger.error(
                    'Duplicate key "%s" for serial number %s found, overwriting',
                    fingerprint_key,
                    cert.serial_number,
                )

            cert_entry[fingerprint_key] = cert.fingerprint(hashes.SHA256()).hex()

            # Only count revocation status in normal mode
            if not fast_mode:
                if revocation_status == "Yes":
                    revoked_count += 1
                elif cert.not_valid_after_utc < now:
                    expired_without_revocation_count += 1
                else:
                    valid_not_revoked_count += 1

    # Write crt.sh links if in fast mode OR if crtsh_flag is set OR if over threshold
    if fast_mode or crtsh_flag or len(all_certs) >= fast_threshold:
        logger.info(
            f"Writing crt.sh links for {len(all_certs)} unique certificates to crtsh_links.txt"
        )

        with open("crtsh_links.txt", "w") as f:
            for cert_entry in all_certs.values():
                final_fingerprint = cert_entry.get("final_cert_fingerprint_sha256")
                precert_fingerprint = cert_entry.get("precert_fingerprint_sha256")
                if final_fingerprint:
                    f.write(f"https://crt.sh/?sha256={final_fingerprint}\n")
                if precert_fingerprint:
                    f.write(f"https://crt.sh/?sha256={precert_fingerprint}\n")

    # Count final/precert relationships (only in normal mode)
    if not fast_mode:
        for entry in all_certs.values():
            has_final = "final_cert_fingerprint_sha256" in entry
            has_precert = "precert_fingerprint_sha256" in entry

            if has_final and not has_precert:
                final_without_precert += 1
            elif has_precert and not has_final:
                precert_without_final += 1

    # Output results
    if fast_mode:
        # Fast mode: Only output the crt.sh links file - no CSV/JSON output needed
        sys.stderr.write("\n🚀 Fast Mode Summary:\n")
        sys.stderr.write(f"Total Certs Processed: {total_certs}\n")
        sys.stderr.write(f"Unique Certificates: {len(all_certs)}\n")
        sys.stderr.write(f"crt.sh links written to: crtsh_links.txt\n")
        sys.stderr.write(
            "Note: For CA incidents >10k certs, only crt.sh URLs are required\n"
        )
        return

    # Normal mode output
    if output_format == "csv":
        c = csv.writer(sys.stdout, lineterminator="\n")

        # Normal mode CSV header
        c.writerow(
            [
                "Precertificate SHA-256 Hash",
                "Certificate SHA-256 Hash",
                "Subject",
                "Issuer",
                "Not before",
                "Not after",
                "Serial #",
                "dNSNames",
                "Is Revoked?",
                "Revocation Date",
                "Revocation Reason",
            ]
        )

        for serial_number, cert_entry in sorted(
            list(all_certs.items()), key=lambda x: x[1]["not_before"], reverse=True
        ):
            if not cert_entry.get("precert_fingerprint_sha256"):
                logger.error(
                    "Missing precert_fingerprint_sha256 for serial number %s",
                    serial_number,
                )

            if not cert_entry.get("final_cert_fingerprint_sha256"):
                logger.error(
                    "Missing final_cert_fingerprint_sha256 for serial number %s",
                    serial_number,
                )

            c.writerow(
                [
                    cert_entry.get("precert_fingerprint_sha256", "N/A"),
                    cert_entry.get("final_cert_fingerprint_sha256", "N/A"),
                    cert_entry["subject"],
                    cert_entry["issuer"],
                    cert_entry["not_before"],
                    cert_entry["not_after"],
                    serial_number,
                    cert_entry["dns_names"],
                    cert_entry["revocation_status"],
                    cert_entry["revocation_date"],
                    cert_entry["revocation_reason"],
                ]
            )
    else:
        # JSON output
        output_list = []
        for serial_number, cert_entry in sorted(
            all_certs.items(), key=lambda x: x[1]["not_before"], reverse=True
        ):
            cert_entry_with_serial = {"serial_number": serial_number, **cert_entry}
            output_list.append(cert_entry_with_serial)

        json.dump(output_list, sys.stdout, indent=2)
        sys.stdout.write("\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--full-report-format",
        choices=["csv", "json"],
        default="csv",
        help="Full report output format (csv or json)",
    )
    parser.add_argument(
        "--full-report-threshold",
        type=int,
        default=10000,
        help="Certificate count threshold where the full report is generated (default: 10000)",
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





if __name__ == "__main__":
    main()
