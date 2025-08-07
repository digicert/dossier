"""
Certificate loading utilities for various input formats.

This module provides functions to load X.509 certificates from different sources:
- Individual PEM files
- Directories containing PEM files
- ZIP archives containing PEM files
- Base64 encoded certificate data
"""

import base64
import glob
import logging
import os
import zipfile
from typing import List, Dict, Any, Optional

import tqdm
from cryptography import x509
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


def load_cert_from_file(pem_path: str) -> x509.Certificate:
    """Load a single certificate from a PEM file.
    
    Args:
        pem_path: Path to the PEM file
        
    Returns:
        X.509 certificate object
    """
    with open(pem_path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())


def load_cert_from_base64(base64_str: str) -> Optional[x509.Certificate]:
    """Load a certificate from base64 encoded DER data.
    
    Args:
        base64_str: Base64 encoded certificate data
        
    Returns:
        X.509 certificate object or None if failed
    """
    try:
        pem_data = base64.b64decode(base64_str.encode('utf-8'))
        return x509.load_der_x509_certificate(pem_data, default_backend())
    except Exception as e:
        logger.error(f'Error decoding base64 string: {e}')
        return None


def load_certs_from_directory(directory_path: str) -> List[Dict[str, Any]]:
    """Load all PEM certificates from a directory.
    
    Args:
        directory_path: Path to directory containing .pem files
        
    Returns:
        List of dictionaries containing cert, source, and pem_data
    """
    certs = []
    pem_files = glob.glob(os.path.join(directory_path, "*.pem"))
    
    if not pem_files:
        logger.warning(f"No .pem files found in directory: {directory_path}")
        return certs
    
    logger.info(f"Found {len(pem_files)} PEM files in directory: {directory_path}")
    
    for pem_file in tqdm.tqdm(pem_files, desc="Loading PEMs from directory"):
        try:
            with open(pem_file, 'rb') as f:
                cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                certs.append({
                    'cert': cert,
                    'source': os.path.basename(pem_file),
                    'pem_data': cert_data.decode('utf-8')
                })
        except Exception as e:
            logger.error(f"Failed to load certificate from {pem_file}: {e}")
    
    return certs


def load_certs_from_zip(zip_path: str) -> List[Dict[str, Any]]:
    """Load all PEM certificates from a zip file.
    
    Args:
        zip_path: Path to ZIP file containing .pem files
        
    Returns:
        List of dictionaries containing cert, source, and pem_data
    """
    certs = []
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_file:
            pem_files = [f for f in zip_file.namelist() if f.endswith('.pem') and not f.endswith('/')]
            
            if not pem_files:
                logger.warning(f"No .pem files found in zip: {zip_path}")
                return certs
            
            logger.info(f"Found {len(pem_files)} PEM files in zip: {zip_path}")
            
            for pem_file in tqdm.tqdm(pem_files, desc="Loading PEMs from zip"):
                try:
                    cert_data = zip_file.read(pem_file)
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                    certs.append({
                        'cert': cert,
                        'source': os.path.basename(pem_file),
                        'pem_data': cert_data.decode('utf-8')
                    })
                except Exception as e:
                    logger.error(f"Failed to load certificate from {pem_file} in zip: {e}")
    
    except zipfile.BadZipFile:
        logger.error(f"Invalid zip file: {zip_path}")
    except Exception as e:
        logger.error(f"Error reading zip file {zip_path}: {e}")
    
    return certs
