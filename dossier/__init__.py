"""
Dossier: Certificate processing and OCSP validation tool

This package provides tools for:
- Loading X.509 certificates from various sources (PEM files, directories, ZIP archives)
- Validating certificate revocation status via OCSP
- Processing certificate data in bulk
- Generating reports in CSV and JSON formats
"""

from .cert_loader import (
    load_cert_from_file,
    load_cert_from_base64,
    load_certs_from_directory,
    load_certs_from_zip,
    load_certs_from_directory_list,
    load_certs_from_zip_list,
)
from .crl_client import CrlClient
from .main import main

__all__ = [
    "load_cert_from_file",
    "load_cert_from_base64", 
    "load_certs_from_directory",
    "load_certs_from_zip",
    "load_certs_from_directory_list",
    "load_certs_from_zip_list",
    "CrlClient",
    "main",
]