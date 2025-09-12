import csv
import io
import logging
import os
import zipfile
from typing import Iterator, Optional

from cryptography import x509

logger = logging.getLogger(__name__)


class CertificateReader:
    def read(self) -> Iterator[x509.Certificate]:
        pass


class CsvFileReader(CertificateReader):
    def __init__(self, csv_io: io.FileIO):
        self._text_io = io.TextIOWrapper(csv_io, encoding="utf-8")

        self._csv = csv.reader(self._text_io, newline="")

    def read(self) -> Iterator[x509.Certificate]:
        try:
            for idx, row in enumerate(self._csv):
                try:
                    yield x509.load_pem_x509_certificate(row[0].encode())
                except ValueError as e:
                    logging.error("Failed to parse PEM in CSV row #%d: %s", idx + 1, e)

                    continue
        finally:
            self._text_io.detach()


class PemFileReader(CertificateReader):
    def __init__(self, pem_io: io.FileIO):
        self._pem_io = pem_io

    def read(self) -> Iterator[x509.Certificate]:
        # TODO: handle multiple PEM-encoded certificates

        try:
            yield x509.load_pem_x509_certificate(self._pem_io.read())
        except ValueError as e:
            logging.error("Failed to parse PEM: %s", e)


class ZipFileReader(CertificateReader):
    def __init__(self, zip_io: io.FileIO):
        self._zip_io = zipfile.ZipFile(zip_io, "r")

    def read(self) -> Iterator[x509.Certificate]:
        for file_info in self._zip_io.infolist():
            if not file_info.filename.endswith(".pem"):
                logging.warning("Skipping non-PEM file in ZIP: %s", file_info.filename)

                continue

            with self._zip_io.open(file_info) as pem_file:
                try:
                    yield x509.load_pem_x509_certificate(pem_file.read())
                except ValueError as e:
                    logging.error(
                        "Failed to parse PEM in ZIP file %s: %s", file_info.filename, e
                    )
                    continue

        self._zip_io.close()


_FILE_EXTENSION_TO_READER_CLS = {
    ".csv": CsvFileReader,
    ".pem": PemFileReader,
    ".zip": ZipFileReader,
}


def get_certificate_reader(file_io: io.FileIO) -> Optional[CertificateReader]:
    _, ext = os.path.splitext(file_io.name)

    reader = _FILE_EXTENSION_TO_READER_CLS.get(ext)
    if reader is None:
        logging.error("Unsupported file extension: %s", ext)
    else:
        reader = reader(file_io)

    return reader
