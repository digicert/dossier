import csv
import io

import httpx


def create_http_client(pems_content: bytes, entries_content: bytes) -> httpx.Client:
    def handle_request(request: httpx.Request) -> httpx.Response:
        url = str(request.url)

        if "NotBeforeYear=2025" in url:
            content = pems_content
        elif "AllCertificateRecordsCSVFormatv5" in url:
            content = entries_content
        else:
            content = _EMPTY_PEMS

        return httpx.Response(200, content=content)

    return httpx.Client(transport=httpx.MockTransport(handle_request))


def write_ccadb_all_certs(entries: list[dict]) -> bytes:
    with io.StringIO() as buffer:
        c = csv.DictWriter(
            buffer,
            fieldnames=[
                "SHA-256 Fingerprint",
                "Revocation Status",
                "Valid To (GMT)",
                "JSON Array of All Full CRL URLs",
                "JSON Array of Partitioned CRLs",
                "Subject Key Identifier",
            ],
            lineterminator="\n",
            restval="",
        )
        c.writeheader()
        c.writerows(entries)

        return buffer.getvalue().encode()


def write_ccadb_pems(entries: list[str]) -> bytes:
    with io.StringIO() as buffer:
        c = csv.DictWriter(
            buffer,
            fieldnames=["X.509 Certificate (PEM)"],
            lineterminator="\n",
        )
        c.writeheader()
        c.writerows([{"X.509 Certificate (PEM)": e} for e in entries])

        return buffer.getvalue().encode()


_EMPTY_PEMS = write_ccadb_pems([])
