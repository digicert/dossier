import csv
import datetime
import io
from typing import List, Optional, NamedTuple, Sequence

from dossier import revocation


class ReportEntry(NamedTuple):
    serial_number: int
    subject: str
    issuer: str
    not_before: datetime.datetime
    not_after: datetime.datetime
    dns_names: str
    revocation_info: Optional[revocation.RevocationInfo]
    precert_sha256_hashes: List[bytes]
    final_cert_sha256_hashes: List[bytes]


def write_link_report(report_entries: Sequence[ReportEntry], output_io: io.TextIOBase):
    for entry in report_entries:
        for h in entry.precert_sha256_hashes + entry.final_cert_sha256_hashes:
            print(f"https://crt.sh/?sha256={h.hex()}", file=output_io)


def write_full_report(report_entries: Sequence[ReportEntry], output_io: io.TextIOBase):
    c = csv.writer(output_io)

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

    for entry in report_entries:
        c.writerow(
            [
                ",".join(h.hex() for h in entry.precert_sha256_hashes),
                ",".join(h.hex() for h in entry.final_cert_sha256_hashes),
                entry.subject,
                entry.issuer,
                entry.not_before.isoformat(),
                entry.not_after.isoformat(),
                hex(entry.serial_number)[2:],
                entry.dns_names,
                entry.revocation_info.status,
                entry.revocation_info.date,
                entry.revocation_info.reason,
            ]
        )
