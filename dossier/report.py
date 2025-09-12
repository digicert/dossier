import csv
import datetime
import io
from typing import List, Optional, NamedTuple, Iterator

from dossier import revocation


class LinkReportEntry(NamedTuple):
    sha256_hash: bytes


def write_link_report(report_entries: List[LinkReportEntry], output_io: io.TextIOBase):
    for entry in report_entries:
        print(f"https://crt.sh/?sha256={entry.sha256_hash.hex()}", file=output_io)


class FullReportEntry(NamedTuple):
    serial_number: int
    subject: str
    issuer: str
    not_before: datetime.datetime
    not_after: datetime.datetime
    dns_names: str
    precert_sha256_hash: Optional[bytes] = None
    final_cert_sha256_hash: Optional[bytes] = None
    revocation_info: Optional[revocation.RevocationInfo] = None

    def to_link_report_entries(self) -> Iterator[LinkReportEntry]:
        if self.precert_sha256_hash:
            yield LinkReportEntry(self.precert_sha256_hash)
        if self.final_cert_sha256_hash:
            yield LinkReportEntry(self.final_cert_sha256_hash)


def write_full_report(report_entries: List[FullReportEntry], output_io: io.TextIOBase):
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
                entry.precert_sha256_hash,
                entry.final_cert_sha256_hash,
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
