import logging
from time import monotonic

import requests
from asn1crypto import ocsp
from asn1crypto.core import Integer
from cryptography import x509
from cryptography.x509 import ocsp as crypto_ocsp

import util

logger = logging.getLogger(__name__)


def naive_fetch(cert: x509.Certificate):
    issuer_name_hash = util.get_sha1_hash(cert.issuer.public_bytes())

    try:
        aki_ext = cert.extensions.get_extension_for_oid(x509.OID_AUTHORITY_KEY_IDENTIFIER)
    except x509.ExtensionNotFound:
        logger.error('Certificate "{}" does not have an Authority Key Identifier extension', cert)
        return None

    try:
        aia_ext = cert.extensions.get_extension_for_oid(x509.OID_AUTHORITY_INFORMATION_ACCESS)
    except x509.ExtensionNotFound:
        logger.error('Certificate "{}" does not have an Authority Info Access extension', cert)
        return None

    uri = next((
        ad.access_location.value for ad in aia_ext.value if (
            ad.access_method == x509.OID_OCSP and isinstance(ad.access_location, x509.UniformResourceIdentifier) and
            ad.access_location.value.lower().startswith('http://'))
    ), None)

    if uri is None:
        logger.error('Certificate "{}" does not have an OCSP URI in its Authority Info Access extension', cert)
        return None

    request_der = ocsp.OCSPRequest({'tbs_request': ocsp.TBSRequest({
        'request_list': [
            {
                'req_cert': {
                    'hash_algorithm': {
                        'algorithm': 'sha1'
                    },
                    'issuer_name_hash': issuer_name_hash,
                    'issuer_key_hash': aki_ext.value.key_identifier,
                    'serial_number': Integer(cert.serial_number)
                }
            }
        ],
        'request_extensions': []
    })}).dump()

    start_sec = monotonic()
    try:
        resp = requests.post(
            uri,
            data=request_der,
            headers={'Content-Type': 'application/ocsp-request'},
            timeout=5
        )
        resp.raise_for_status()
    except requests.RequestException:
        logger.exception('Exception occurred when fetching OCSP response for certificate {} at "{}"', cert, uri)

        return None

    end_sec = monotonic()

    logger.debug('Fetched OCSP response for certificate "{}" from "{}" in {:.2f} seconds', cert, uri, end_sec - start_sec)

    try:
        ocsp_resp = crypto_ocsp.load_der_ocsp_response(resp.content)
    except ValueError:
        logger.exception('Failed to parse OCSP response for certificate "{}" from "{}"', cert, uri)

        return None

    if ocsp_resp.response_status != crypto_ocsp.OCSPResponseStatus.SUCCESSFUL:
        logger.error('OCSP response for certificate "{}" from "{}" is not successful: {}', cert, uri, ocsp_resp.response_status)
        return None

    return ocsp_resp
