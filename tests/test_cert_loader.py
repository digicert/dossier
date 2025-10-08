import csv
import io
import os
import tempfile
import zipfile

from cryptography.hazmat.primitives import serialization, hashes

from tests import pki_maker

from dossier import cert_loader

_ROOT_CERT = pki_maker.generate_root()
_ICA_CERT = pki_maker.generate_inter_a_key_1_ca(_ROOT_CERT)


def test_der():
    with tempfile.NamedTemporaryFile(suffix=".crt") as f:
        f.write(_ROOT_CERT.public_bytes(encoding=serialization.Encoding.DER))
        f.flush()

        f.seek(0)

        reader = cert_loader.get_certificate_reader(f.name)

        cert = next(reader(f, f.name))

        assert cert.fingerprint(hashes.SHA256()) == _ROOT_CERT.fingerprint(
            hashes.SHA256()
        )


def test_pem():
    with tempfile.NamedTemporaryFile(suffix=".crt") as f:
        f.write(_ROOT_CERT.public_bytes(encoding=serialization.Encoding.PEM))
        f.flush()

        f.seek(0)

        reader = cert_loader.get_certificate_reader(f.name)

        cert = next(reader(f, f.name))

        assert cert.fingerprint(hashes.SHA256()) == _ROOT_CERT.fingerprint(
            hashes.SHA256()
        )


def test_zip():
    with tempfile.NamedTemporaryFile(suffix=".zip") as f:
        with zipfile.ZipFile(f, "w") as zf:
            zf.writestr(
                "root.crt", _ROOT_CERT.public_bytes(encoding=serialization.Encoding.DER)
            )
            zf.writestr(
                "ica.crt", _ICA_CERT.public_bytes(encoding=serialization.Encoding.PEM)
            )

        f.flush()

        f.seek(0)

        reader = cert_loader.get_certificate_reader(f.name)

        certs = list(reader(f, f.name))

        assert len(certs) == 2
        assert _ROOT_CERT in certs
        assert _ICA_CERT in certs


def test_zip_nested():
    with tempfile.NamedTemporaryFile(suffix=".zip") as f:
        with zipfile.ZipFile(f, "w") as zf:
            zf.writestr(
                "root.crt", _ROOT_CERT.public_bytes(encoding=serialization.Encoding.DER)
            )
            with io.BytesIO() as bf:
                with zipfile.ZipFile(bf, "w") as nested_zf:
                    nested_zf.writestr(
                        "nested_ica.crt",
                        _ICA_CERT.public_bytes(encoding=serialization.Encoding.PEM),
                    )

                zf.writestr("nested.zip", bf.getvalue())

        f.flush()

        f.seek(0)

        reader = cert_loader.get_certificate_reader(f.name)

        certs = list(reader(f, f.name))

        assert len(certs) == 2
        assert _ROOT_CERT in certs
        assert _ICA_CERT in certs


def test_csv():
    temp_f = None

    try:
        temp_f = tempfile.NamedTemporaryFile("w+", suffix=".csv", delete=False)
        writer = csv.DictWriter(temp_f, fieldnames=["pem"], lineterminator="\n")

        writer.writeheader()
        writer.writerow(
            {
                "pem": _ROOT_CERT.public_bytes(
                    encoding=serialization.Encoding.PEM
                ).decode()
            }
        )
        writer.writerow(
            {
                "pem": _ICA_CERT.public_bytes(
                    encoding=serialization.Encoding.PEM
                ).decode()
            }
        )

        temp_f.close()

        with open(temp_f.name, "rb") as f:
            reader = cert_loader.get_certificate_reader(f.name)

            certs = list(reader(f, f.name))

            assert len(certs) == 2
            assert _ROOT_CERT in certs
            assert _ICA_CERT in certs
    finally:
        if temp_f:
            os.remove(temp_f.name)
