import csv
import io
import logging
import os
import typing
import zipfile
from typing import Iterator

from cryptography import x509

from dossier import statistics

logger = logging.getLogger(__name__)


def _read_csv(csv_io: typing.IO, _: str) -> Iterator[x509.Certificate]:
    text_io = io.TextIOWrapper(csv_io, encoding="utf-8")

    csv_reader = csv.DictReader(text_io)

    try:
        for idx, row in enumerate(csv_reader):
            pem = row.get("pem") or row.get("PEM")
            if pem is None:
                statistics.INSTANCE.error_count += 1

                msg = f'No "pem" or "PEM" column found in CSV row #{idx + 1}'

                logging.error(msg)

                raise ValueError(msg)
            try:
                yield x509.load_pem_x509_certificate(pem.encode())
            except ValueError as e:
                statistics.INSTANCE.error_count += 1

                logging.error("Failed to parse PEM in CSV row #%d: %s", idx + 1, e)

                continue
    finally:
        text_io.detach()


def _read_pem_and_der(
    pem_and_der_io: typing.IO, filename: str
) -> Iterator[x509.Certificate]:
    content = pem_and_der_io.read()

    file_format = ""
    try:
        if content.startswith(b"\x30"):
            file_format = "DER"

            yield x509.load_der_x509_certificate(content)
        else:
            file_format = "PEM"

            yield x509.load_pem_x509_certificate(content)
    except ValueError as e:
        statistics.INSTANCE.error_count += 1

        logging.error("Failed to parse %s as %s: %s", filename, file_format, e)


def _read_zip(zip_io: typing.IO, _: str) -> Iterator[x509.Certificate]:
    with zipfile.ZipFile(zip_io, "r") as zip_file:
        for file_info in zip_file.infolist():
            filename = file_info.filename

            reader = get_certificate_reader(filename)

            if not reader:
                continue

            with zip_file.open(file_info) as f:
                yield from reader(f, filename)


_FILE_EXTENSION_TO_READER_FUNC = {
    ".csv": _read_csv,
    ".zip": _read_zip,
    ".pem": _read_pem_and_der,
    ".der": _read_pem_and_der,
    ".crt": _read_pem_and_der,
    ".cer": _read_pem_and_der,
}


def get_certificate_reader(filename: str):
    _, ext = os.path.splitext(filename)

    reader = _FILE_EXTENSION_TO_READER_FUNC.get(ext)
    if reader is None:
        statistics.INSTANCE.error_count += 1

        logging.error("Unsupported file extension: %s", ext)

    return reader
