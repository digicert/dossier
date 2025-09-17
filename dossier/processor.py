import enum
import io
import logging
from typing import List, Optional

import tqdm
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import oid

from dossier import statistics, cert_loader
from dossier.report import LinkReportEntry, ReportEntry
from dossier.revocation import RevocationManager

logger = logging.getLogger(__name__)


class CertificateType(enum.Enum):
    TLS_EE = enum.auto()
    SMIME_EE = enum.auto()
    CA = enum.auto()


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


def _get_certificate_type(cert) -> Optional[CertificateType]:
    try:
        bc_ext = cert.extensions.get_extension_for_oid(
            oid.ExtensionOID.BASIC_CONSTRAINTS
        )

        if bc_ext.value.ca:
            return CertificateType.CA
    except x509.ExtensionNotFound:
        pass

    try:
        eku_ext = cert.extensions.get_extension_for_oid(
            oid.ExtensionOID.EXTENDED_KEY_USAGE
        )

        if oid.ExtendedKeyUsageOID.SERVER_AUTH in eku_ext.value:
            return CertificateType.TLS_EE
        elif oid.ExtendedKeyUsageOID.EMAIL_PROTECTION in eku_ext.value:
            return CertificateType.SMIME_EE
        else:
            logger.warning("Unknown EKU: %s", eku_ext.value)

            return None

    except x509.ExtensionNotFound:
        logger.warning("No EKU extension found")

        return None


class Processor:
    def __init__(
        self,
        revocation_manager: RevocationManager,
        show_progress: bool = True,
    ):
        self._revocation_manager = revocation_manager
        self._show_progress = show_progress

    def process_files(self, input_files: List[io.FileIO]):
        entries_by_issuer_and_serial_number = {}

        fingerprints_seen = set()

        statistics.INSTANCE.reset()

        for input_file in input_files:
            logger.info("Processing %s", input_file.name)

            reader = cert_loader.get_certificate_reader(input_file)
            if reader is None:
                continue

            for cert in tqdm.tqdm(
                reader.read(), desc=input_file.name, disable=not self._show_progress
            ):
                fingerprint = cert.fingerprint(hashes.SHA256())

                if fingerprint in fingerprints_seen:
                    logger.error(
                        "Duplicate certificate with fingerprint %s encountered",
                        fingerprint.hex(),
                    )
                    statistics.INSTANCE.duplicate_cert_count += 1

                    continue

                fingerprints_seen.add(fingerprint)

                entry = entries_by_issuer_and_serial_number.get(cert.serial_number)
                if entry is None:
                    cert_type = _get_certificate_type(cert)
                    if cert_type is None:
                        statistics.INSTANCE.unknown_certificate_types += 1

                    subject = (
                        "REDACTED"
                        if cert_type == CertificateType.SMIME_EE
                        else cert.subject.rfc4514_string()
                    )

                    revocation_info = self._revocation_manager.get_revocation_info(cert)

                    entry = ReportEntry(
                        cert.serial_number,
                        subject,
                        cert.issuer.rfc4514_string(),
                        cert.not_valid_before_utc,
                        cert.not_valid_after_utc,
                        _get_dnsnames(cert),
                        revocation_info,
                    )

                    entries_by_issuer_and_serial_number[cert.serial_number] = entry

                if _is_precert(cert):
                    if entry.precert_sha256_hash:
                        logger.error(
                            "Multiple pre-certificates with SHA-256 fingerprint %s found",
                            fingerprint.hex(),
                        )

                    entry.precert_sha256_hash.append(fingerprint)
                else:
                    if entry.final_cert_sha256_hash:
                        logger.error(
                            "Multiple final certificates with SHA-256 fingerprint %s found",
                            fingerprint.hex(),
                        )
                    entry.final_cert_sha256_hash.append(fingerprint)

            statistics.INSTANCE.output()

            return list(entries_by_issuer_and_serial_number.values())
