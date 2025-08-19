import collections
import datetime

from cryptography import x509
import csv
import json
import argparse
import logging
import sys
import tqdm
import os
import io

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import oid
from datetime import timedelta

from . import naive_ocsp_client
from .cert_loader import load_cert_from_file, load_certs_from_directory, load_certs_from_zip

logging.basicConfig(stream=sys.stderr, level=logging.INFO)
logger = logging.getLogger(__name__)

ocsp_cache = {}

now = datetime.datetime.now(datetime.timezone.utc)

def get_revocation_status(cert):
    serial_number = cert.serial_number

    if serial_number in ocsp_cache:
        return ocsp_cache[serial_number]

    try:
        ocsp_resp = naive_ocsp_client.naive_fetch(cert)
        ocsp_cache[serial_number] = ocsp_resp
        return ocsp_resp
    except Exception as e:
        logger.error(f"Error fetching OCSP status for cert {hex(cert.serial_number)[2:]}: {e}")
        ocsp_cache[serial_number] = None
        return None
    
def check_cert(cert, incident_discovered, revocation_window):
    now = datetime.datetime.now(datetime.timezone.utc)

    if revocation_window is None:
        revocation_window = datetime.timedelta(hours=24)

    if cert.not_valid_after_utc < now:
        logger.info(f'[EXPIRED] Certificate with serial: {hex(cert.serial_number)[2:]} at {cert.not_valid_after_utc} | Revoked status: N/A')
        return

    result = get_revocation_status(cert)
    if not result:
        logger.error(f'[NO RESPONSE] Certificate with serial: {hex(cert.serial_number)[2:]} | Revoked status: OCSP Error')
        return

    revocation_time = getattr(result, 'revocation_time_utc', None)

    if revocation_time is not None:
        if incident_discovered:
            delay = revocation_time - incident_discovered
            revocation_status = "Delayed" if delay > revocation_window else "Yes"
        else:
            revocation_status = "Yes"

        logger.info(f'[REVOKED] Certificate with serial: {hex(cert.serial_number)[2:]} at {revocation_time} | Revoked status: {revocation_status}')
    else:
        revocation_status = "Planned"
        logger.info(f'[GOOD] Certificate with serial: {hex(cert.serial_number)[2:]} | Revoked status: {revocation_status}')

def _get_dnsnames(cert):
    try:
        san_ext = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
        return ','.join(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        return ''

def _is_precert(cert):
    try:
        cert.extensions.get_extension_for_oid(oid.ExtensionOID.PRECERT_POISON)

        return True
    except x509.ExtensionNotFound:
        return False

def process_pem_csv(pem_csvs, output_format, incident_discovered, revocation_window, crtsh_flag):
    all_certs = {}
    year_bucket = collections.Counter()

    total_certs = 0
    revoked_count = 0
    expired_without_revocation_count = 0
    valid_not_revoked_count = 0
    final_without_precert = 0
    precert_without_final = 0

    for pem_csv in pem_csvs:
        logger.info('Parsing %s', pem_csv.name if hasattr(pem_csv, 'name') else 'certificates')

        for line_idx, row in tqdm.tqdm(enumerate(csv.DictReader(pem_csv))):
            pem = row.get('pem')
            if not pem:
                logger.error('No PEM found in row #%d: %s', line_idx, row)
                continue

            try:
                cert = x509.load_pem_x509_certificate(pem.encode())
            except ValueError as e:
                logger.error('Failed to parse PEM in row %s: %s', row, e)
                continue

            serial_number = hex(cert.serial_number)[2:]
            total_certs += 1

            cert_entry = all_certs.get(serial_number)
            if cert_entry is None:
                cert_entry = {
                    'subject': cert.subject.rfc4514_string(),
                    'issuer': cert.issuer.rfc4514_string(),
                    'not_before': cert.not_valid_before_utc.isoformat(),
                    'not_after': cert.not_valid_after_utc.isoformat(),
                    'dns_names': _get_dnsnames(cert),
                }

                revocation_status = 'N/A'
                revocation_date = 'N/A'
                revocation_reason = 'N/A'

                if cert.not_valid_after_utc < now:
                    revocation_status = 'N/A'
                    revocation_date = 'N/A'
                    revocation_reason = 'N/A'
                else:
                    ocsp_resp = get_revocation_status(cert)

                    if ocsp_resp is None:
                        logger.error('No OCSP response returned for certificate with serial: %s', serial_number)
                        revocation_status = 'OCSP Error'
                        revocation_date = 'N/A'
                        revocation_reason = 'N/A'
                    else:
                        is_revoked = ocsp_resp.revocation_time_utc is not None

                        if is_revoked:
                            revocation_date_dt = ocsp_resp.revocation_time_utc
                            revocation_date = revocation_date_dt.isoformat()
                            revocation_reason = ocsp_resp.revocation_reason.name if ocsp_resp.revocation_reason else "unspecified"

                            if incident_discovered:
                                delta = revocation_date_dt - incident_discovered
                                revocation_status = "Delayed" if delta > revocation_window else "Yes"
                            else:
                                revocation_status = "Yes"
                        else:
                            revocation_status = "Planned"

                cert_entry['revocation_status'] = revocation_status
                cert_entry['revocation_date'] = revocation_date
                cert_entry['revocation_reason'] = revocation_reason

                issued_year = cert.not_valid_before_utc.year
                year_bucket[issued_year] += 1

                all_certs[serial_number] = cert_entry

            fingerprint_key = 'precert_fingerprint_sha256' if _is_precert(cert) else 'final_cert_fingerprint_sha256'
            if fingerprint_key in cert_entry:
                logger.error('Duplicate key "%s" for serial number %s found, overwriting', fingerprint_key, cert.serial_number)

            cert_entry[fingerprint_key] = cert.fingerprint(hashes.SHA256()).hex()

            if revocation_status == 'Yes':
                revoked_count += 1
            elif cert.not_valid_after_utc < now:
                expired_without_revocation_count += 1
            else:
                valid_not_revoked_count += 1

    if crtsh_flag or len(all_certs) >= 10000:
        logger.info("Over 10,000 certificates found. Writing crt.sh links to crtsh_links.txt")

        with open("crtsh_links.txt", "w") as f:
            for cert_entry in all_certs.values():
                final_fingerprint = cert_entry.get('final_cert_fingerprint_sha256')
                precert_fingerprint = cert_entry.get('precert_fingerprint_sha256')
                if final_fingerprint:
                    f.write(f"https://crt.sh/?sha256={final_fingerprint}\n")
                if precert_fingerprint:
                    f.write(f"https://crt.sh/?sha256={precert_fingerprint}\n")

    for entry in all_certs.values():
        has_final = "final_cert_fingerprint_sha256" in entry
        has_precert = "precert_fingerprint_sha256" in entry

        if has_final and not has_precert:
            final_without_precert += 1
        elif has_precert and not has_final:
            precert_without_final += 1

    if output_format == 'csv':
        c = csv.writer(sys.stdout, lineterminator='\n')
        c.writerow(['Precertificate SHA-256 Hash', 'Certificate SHA-256 Hash', 'Subject', 'Issuer', 'Not before', 'Not after', 'Serial #', 'dNSNames', 'Is Revoked?', 'Revocation Date', 'Revocation Reason'])

        for serial_number, cert_entry in sorted(list(all_certs.items()), key=lambda x: x[1]['not_before'], reverse=True):
            if not cert_entry.get('precert_fingerprint_sha256'):
                logger.error('Missing precert_fingerprint_sha256 for serial number %s', serial_number)

            if not cert_entry.get('final_cert_fingerprint_sha256'):
                logger.error('Missing final_cert_fingerprint_sha256 for serial number %s', serial_number)

            c.writerow([
                cert_entry.get('precert_fingerprint_sha256', 'N/A'),
                cert_entry.get('final_cert_fingerprint_sha256', 'N/A'),
                cert_entry['subject'],
                cert_entry['issuer'],
                cert_entry['not_before'],
                cert_entry['not_after'],
                serial_number,
                cert_entry['dns_names'],
                cert_entry['revocation_status'],
                cert_entry['revocation_date'],
                cert_entry['revocation_reason'],
            ])
    else:
        output_list = []
        for serial_number, cert_entry in sorted(all_certs.items(), key=lambda x: x[1]['not_before'], reverse=True):
            cert_entry_with_serial = {'serial_number': serial_number, **cert_entry}
            output_list.append(cert_entry_with_serial)

        json.dump(output_list, sys.stdout, indent=2)
        sys.stdout.write('\n')

    sys.stderr.write("\nSummary:\n")
    sys.stderr.write(f'{year_bucket}\n')
    sys.stderr.write(f"Total Certs: {total_certs}\n")
    sys.stderr.write(f"Revoked: {revoked_count}\n")
    sys.stderr.write(f"Expired without revocation: {expired_without_revocation_count}\n")
    sys.stderr.write(f"Still valid & not revoked: {valid_not_revoked_count}\n")
    sys.stderr.write(f"Final cert without precert: {final_without_precert}\n")
    sys.stderr.write(f"Precert without final cert: {precert_without_final}\n")

def process_cert_list(cert_list, output_format='csv', incident_discovered=None, revocation_window=datetime.timedelta(hours=24), crtsh_flag=False):
    """Convert cert list to CSV format and process using existing process_pem_csv function"""
    import io
    
    # Create a temporary CSV in memory
    csv_content = io.StringIO()
    csv_writer = csv.writer(csv_content)
    csv_writer.writerow(['pem'])  # Header
    
    for cert_info in cert_list:
        csv_writer.writerow([cert_info['pem_data']])
    
    # Reset to beginning and process
    csv_content.seek(0)
    process_pem_csv([csv_content], output_format, incident_discovered, revocation_window, crtsh_flag)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input_path', help='Path to .pem file, .csv file, directory containing .pem files, or .zip file containing .pem files')
    parser.add_argument('--format', choices=['csv', 'json'], default='csv', help='Output format (csv or json)')
    parser.add_argument('--incident', help="Optional incident discovery datetime in ISO 8601 (e.g. 2025-07-29T15:00:00Z)")
    parser.add_argument('--revocation-window', choices=['24h', '5d', '7d'], default='24h',
                        help="Time allowed for revocation after incident discovery. Options: 24h (default), 5d, 7d.")
    parser.add_argument('--crtsh', action='store_true', help="Write crt.sh links to crtsh_links.txt if over 10k certs")
    args = parser.parse_args()

    incident_discovered = None
    if args.incident:
        try:
            incident_discovered = datetime.datetime.fromisoformat(args.incident.replace("Z", "+00:00"))
        except ValueError:
            logger.error("Invalid incident datetime format. Use ISO 8601 like '2025-07-29T15:00:00Z'.")
            sys.exit(1)

    revocation_windows = {
        '24h': datetime.timedelta(hours=24),
        '5d': datetime.timedelta(days=5),
        '7d': datetime.timedelta(days=7)
    }
    revocation_window = revocation_windows[args.revocation_window]

    input_path = args.input_path

    if input_path.endswith('.csv'):
        with open(input_path, newline='') as csvfile:
            process_pem_csv([csvfile], args.format, incident_discovered, revocation_window, args.crtsh)
    elif input_path.endswith('.pem') and os.path.exists(input_path):
        cert = load_cert_from_file(input_path)
        check_cert(cert, incident_discovered, revocation_window)
    elif input_path.endswith('.zip'):
        logger.info("Processing ZIP file...")
        cert_generator = load_certs_from_zip(input_path)
        cert_list = list(tqdm.tqdm(cert_generator, desc="Loading PEMs from zip"))
        if not cert_list:
            logger.error("No certificates found to process")
            sys.exit(1)
        process_cert_list(cert_list, args.format, incident_discovered, revocation_window, args.crtsh)
    elif os.path.isdir(input_path):
        logger.info("Processing directory...")
        cert_generator = load_certs_from_directory(input_path)
        cert_list = list(tqdm.tqdm(cert_generator, desc="Loading PEMs from directory"))
        if not cert_list:
            logger.error("No certificates found to process")
            sys.exit(1)
        process_cert_list(cert_list, args.format, incident_discovered, revocation_window, args.crtsh)
    else:
        logger.error("Unsupported input. Provide a .pem file, .csv file, directory containing .pem files, or .zip file containing .pem files.")

if __name__ == "__main__":
    main()