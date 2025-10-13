import io
import logging
from typing import List, Optional

import tqdm
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import oid

from dossier import statistics, cert_loader
from dossier.report import ReportEntry, CertificateType
from dossier.revocation import RevocationManager

logger = logging.getLogger(__name__)


def _get_dnsnames(cert):
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            x509.OID_SUBJECT_ALTERNATIVE_NAME
        )
        return " ".join(san_ext.value.get_values_for_type(x509.DNSName))
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
        hide_progress: bool,
    ):
        self._revocation_manager = revocation_manager
        self._hide_progress = hide_progress

    def process_files(self, input_files: List[io.FileIO]) -> List[ReportEntry]:
        entries_by_issuer_and_serial_number = {}

        fingerprints_seen = set()

        statistics.INSTANCE.reset()

        for input_file in input_files:
            logger.info("Processing %s", input_file.name)

            reader = cert_loader.get_certificate_reader(input_file.name)
            if reader is None:
                continue

            for cert in tqdm.tqdm(
                reader(input_file, input_file.name),
                desc=input_file.name,
                disable=self._hide_progress,
                initial=statistics.INSTANCE.total_cert_count,
            ):
                fingerprint = cert.fingerprint(hashes.SHA256())

                if fingerprint in fingerprints_seen:
                    logger.error(
                        "Duplicate certificate with fingerprint %s encountered",
                        fingerprint.hex(),
                    )
                    statistics.INSTANCE.duplicate_cert_count += 1

                    continue

                statistics.INSTANCE.total_cert_count += 1

                fingerprints_seen.add(fingerprint)

                key = (cert.issuer.public_bytes(), cert.serial_number)

                entry = entries_by_issuer_and_serial_number.get(key)
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
                        cert_type,
                        cert.serial_number,
                        subject,
                        cert.issuer.rfc4514_string(),
                        cert.not_valid_before_utc,
                        cert.not_valid_after_utc,
                        _get_dnsnames(cert),
                        revocation_info,
                        [],
                        [],
                    )

                    entries_by_issuer_and_serial_number[key] = entry

                if _is_precert(cert):
                    if entry.precert_sha256_hashes:
                        statistics.INSTANCE.error_count += 1

                        logger.error(
                            "Multiple pre-certificates with serial number %d and issuer %s found",
                            cert.serial_number,
                            cert.issuer.rfc4514_string(),
                        )

                    entry.precert_sha256_hashes.append(fingerprint)
                else:
                    if entry.final_cert_sha256_hashes:
                        statistics.INSTANCE.error_count += 1

                        logger.error(
                            "Multiple final certificates with serial number %d and issuer %s found",
                            cert.serial_number,
                            cert.issuer.rfc4514_string(),
                        )

                    entry.final_cert_sha256_hashes.append(fingerprint)

        statistics.INSTANCE.final_without_precert = sum(
            1
            for entry in entries_by_issuer_and_serial_number.values()
            if entry.cert_type == CertificateType.TLS_EE
            and entry.final_cert_sha256_hashes
            and not entry.precert_sha256_hashes
        )
        statistics.INSTANCE.precert_without_final = sum(
            1
            for entry in entries_by_issuer_and_serial_number.values()
            if entry.cert_type == CertificateType.TLS_EE
            and entry.precert_sha256_hashes
            and not entry.final_cert_sha256_hashes
        )

        statistics.INSTANCE.output()

        return list(entries_by_issuer_and_serial_number.values())
