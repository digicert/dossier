import datetime
import enum
import functools
import logging
import typing
from typing import Optional

import httpx
from cryptography import x509

from dossier import statistics
from dossier.ccadb_client import CcadbClient, CcadbEntry
from dossier.crl_client import CrlClient

logger = logging.getLogger(__name__)


class RevocationWindow(enum.Enum):
    TWENTY_FOUR_HOURS = datetime.timedelta(hours=24)
    FIVE_DAYS = datetime.timedelta(days=5)
    SEVEN_DAYS = datetime.timedelta(days=7)

    @classmethod
    def from_string(cls, s):
        s = s.upper()

        if s == "24H":
            return cls.TWENTY_FOUR_HOURS
        elif s == "5D":
            return cls.FIVE_DAYS
        elif s == "7D":
            return cls.SEVEN_DAYS
        else:
            raise ValueError(f"Invalid value: {s}")

    def __str__(self):
        if self == RevocationWindow.TWENTY_FOUR_HOURS:
            return "24H"
        elif self == RevocationWindow.FIVE_DAYS:
            return "5D"
        elif self == RevocationWindow.SEVEN_DAYS:
            return "7D"
        else:
            # should never happen
            raise ValueError(f"Invalid value: {self}")


class RevocationClassifier:
    def __init__(
        self,
        revocation_timeline: RevocationWindow,
        incident_discovery_datetime: datetime.datetime,
        current_time: datetime.datetime,
    ):
        self._revocation_deadline_datetime = (
            incident_discovery_datetime + revocation_timeline.value
        )
        self._current_time = current_time

    def classify_revocation(self, crl_entry: Optional[x509.RevokedCertificate]) -> str:
        if crl_entry is None:
            statistics.INSTANCE.valid_cert_count += 1

            if self._current_time > self._revocation_deadline_datetime:
                statistics.INSTANCE.delayed_valid_cert_count += 1

            return "Planned"
        else:
            if crl_entry.revocation_date_utc > self._revocation_deadline_datetime:
                statistics.INSTANCE.delayed_revoked_cert_count += 1

                return "Delayed"
            else:
                statistics.INSTANCE.timely_revoked_cert_count += 1

                return "Yes"


class RevocationInfo(typing.NamedTuple):
    status: str
    date: str
    reason: str


class RevocationManager:
    def __init__(
        self,
        http_client: httpx.Client,
        ccadb_client: CcadbClient,
        classifier: RevocationClassifier,
        current_time: datetime.datetime,
    ):
        self._http_client = http_client
        self._ccadb_client = ccadb_client
        self._classifier = classifier
        self._current_time = current_time

    @functools.lru_cache()
    def _get_crl_client(self, issuer: CcadbEntry):
        return CrlClient(
            issuer.cert,
            self._http_client,
            self._current_time,
            issuer.full_crl_uri,
            issuer.partitioned_crl_uris,
        )

    @classmethod
    def _extract_reason_code_str(
        cls, crl_entry: x509.RevokedCertificate
    ) -> typing.Optional[str]:
        try:
            reason_code_ext = crl_entry.extensions.get_extension_for_class(
                x509.CRLReason
            )

            return reason_code_ext.value.reason.name
        except x509.ExtensionNotFound:
            return None

    def get_revocation_info(self, cert: x509.Certificate) -> RevocationInfo:
        revocation_status = "N/A"
        revocation_date = "N/A"
        revocation_reason = "N/A"

        issuer_entry = self._ccadb_client.find_issuer_entry(cert)
        if issuer_entry is None:
            statistics.INSTANCE.error_count += 1

            logging.error(
                "Could not find issuer %s for %s",
                cert.issuer.rfc4514_string(),
                cert.subject.rfc4514_string(),
            )
        else:
            crl_client = self._get_crl_client(issuer_entry)

            if cert.not_valid_after_utc >= self._current_time:
                crl_entry = crl_client.get_revocation_status(cert.serial_number)

                revocation_status = self._classifier.classify_revocation(crl_entry)
            else:
                crl_entry = None

                statistics.INSTANCE.expired_cert_count += 1

            if crl_entry is not None:
                revocation_date = crl_entry.revocation_date_utc.isoformat()

                reason_code = self._extract_reason_code_str(crl_entry)
                if reason_code is not None:
                    revocation_reason = reason_code

                    statistics.INSTANCE.cert_count_by_revocation_reason_code[
                        reason_code
                    ] += 1

        return RevocationInfo(revocation_status, revocation_date, revocation_reason)
