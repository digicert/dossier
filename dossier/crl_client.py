import datetime
import logging
from typing import Optional, List

import httpx
from cryptography import x509
from cryptography.x509 import oid

logger = logging.getLogger(__name__)


class CrlClient:

    def __init__(
        self,
        issuer: x509.Certificate,
        http_client: httpx.Client,
        current_time: datetime.datetime,
        crl_full_uri: Optional[str] = None,
        crl_partitioned_uris: Optional[List[str]] = None,
    ):
        self._issuer = issuer
        self._http_client = http_client
        self._current_time = current_time

        if (not crl_full_uri and not crl_partitioned_uris) or (
            crl_full_uri and crl_partitioned_uris
        ):
            raise ValueError(
                "Either 'crl_full_uri' or 'crl_partitioned_uris' must be provided, but not both."
            )

        uris = crl_partitioned_uris or [crl_full_uri]
        is_full = bool(crl_full_uri)

        self.crls = []
        for uri in uris:
            try:
                self.crls.append(self._download_and_validate_crl(uri, is_full))
            except (ValueError, httpx.HTTPError) as e:
                logger.exception(
                    "Failed to download and validate %s CRL from %s: %s",
                    "full" if is_full else "partitioned",
                    uri,
                    e,
                )

                raise e

    def get_revocation_status(
        self, serial_number: int
    ) -> Optional[x509.RevokedCertificate]:
        for crl in self.crls:
            revoked_cert = crl.get_revoked_certificate_by_serial_number(serial_number)
            if revoked_cert is not None:
                return revoked_cert

        return None

    def _download_and_validate_crl(
        self, uri: str, is_full: bool
    ) -> x509.CertificateRevocationList:
        logger.info("Downloading CRL from %s", uri)

        resp = self._http_client.get(uri)
        resp.raise_for_status()

        content = resp.content

        logger.info("Downloaded %d bytes from %s", len(content), uri)

        crl = x509.load_der_x509_crl(content)

        self._validate_crl(crl, None if is_full else uri)

        return crl

    def _validate_crl(
        self, crl: x509.CertificateRevocationList, expected_idp: Optional[str]
    ) -> None:
        # TODO: add more checks

        if crl.issuer != self._issuer.subject:
            raise ValueError(
                "CRL issuer does not match the provided issuer certificate."
            )

        if crl.next_update_utc < self._current_time:
            raise ValueError("CRL is expired.")

        if not crl.is_signature_valid(self._issuer.public_key()):
            raise ValueError("CRL signature is invalid.")

        try:
            idp_ext = crl.extensions.get_extension_for_oid(
                oid.ExtensionOID.ISSUING_DISTRIBUTION_POINT
            )
        except x509.ExtensionNotFound:
            idp_ext = None

        if expected_idp is None and idp_ext is not None:
            raise ValueError("Unexpected IDP extension found in CRL.")
        elif expected_idp is not None and idp_ext is None:
            raise ValueError("Expected IDP extension not found in CRL.")

        if expected_idp is not None and not any(
            isinstance(g, x509.UniformResourceIdentifier) and g.value == expected_idp
            for g in idp_ext.value.full_name or []
        ):
            raise ValueError(
                f"Expected IDP {expected_idp} not found in CRL IDP extension."
            )
