import datetime

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import SubjectAlternativeName, ExtendedKeyUsage

RFC9500_ROOT_KEY = serialization.load_pem_private_key(
    b"""
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----""",
    password=None,
)

RFC9500_INTER_A_KEY_1 = serialization.load_pem_private_key(
    b"""
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIObLW92AqkWunJXowVR2Z5/+yVPBaFHnEedDk5WJxk/BoAoGCCqGSM49
AwEHoUQDQgAEQiVI+I+3gv+17KN0RFLHKh5Vj71vc75eSOkyMsxFxbFsTNEMTLjV
uKFxOelIgsiZJXKZNCX0FBmrfpCkKklCcg==
-----END EC PRIVATE KEY-----
""",
    password=None,
)

RFC9500_INTER_A_KEY_2 = serialization.load_pem_private_key(
    b"""
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDiVjMo36v2gYhga5EyQoHB1YpEVkMbCdUQs1/syfMHyhgihG+iZxNx
qagbrA41dJ2gBwYFK4EEACKhZANiAARbCQG4hSMpbrkZ1Q/6GpyzdLxNQJWGKCv+
yhGx2VrbtUc0r1cL+CtyKM8ia89MJd28/jsaOtOUMO/3Y+HWjS4VHZFyC3eVtY2m
s0Y5YTqPubWo2kjGdHEX+ZGehCTzfsg=
-----END EC PRIVATE KEY-----
""",
    password=None,
)

RFC9500_INTER_B_KEY = serialization.load_pem_private_key(
    b"""-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIB2STcygqIf42Zdno32HTmN6Esy0d9bghmU1ZpTWi3ZV5QaWOP3ntF
yFQBPcd6NbGGVbhMlmpgIg1A+R7Z9RRYAuqgBwYFK4EEACOhgYkDgYYABAHQ/XJX
qEx0f1YldcBzhdvr8vUr6lgIPbgv3RUx2KrjzIdf8C/3+i2iYNjrYtbS9dZJJ44y
FzagYoy7swMItuYY2wD2KtIExkYDWbyBiriWG/Dw/A7FquikKBc85W8A3psVfB5c
gsZPVi/K3vxKTCj200LPPvYW/ILTO3KFySHyvzb92A==
-----END EC PRIVATE KEY-----""",
    password=None,
)

_NOT_BEFORE = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)


def generate_root():
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Example Root CA"),
        ]
    )

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(RFC9500_ROOT_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_BEFORE + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=2),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(RFC9500_ROOT_KEY.public_key()),
            critical=False,
        )
        .sign(RFC9500_ROOT_KEY, hashes.SHA256())
    )


def _generate_ica(issuer_cert, subject_key, subject_name):
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_name),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ]
    )

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_BEFORE + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                RFC9500_ROOT_KEY.public_key()
            ),
            critical=False,
        )
        .sign(RFC9500_ROOT_KEY, hashes.SHA256())
    )


def generate_inter_a_key_1_ca(root_cert):
    return _generate_ica(root_cert, RFC9500_INTER_A_KEY_1, "Example Inter A CA")


def generate_inter_a_key_2_ca(root_cert):
    return _generate_ica(root_cert, RFC9500_INTER_A_KEY_2, "Example Inter A CA")


def generate_inter_b_ca(root_cert):
    return _generate_ica(root_cert, RFC9500_INTER_B_KEY, "Example Inter B CA")


def _generate_ee(
    issuer_cert, issuer_key, san_value, serial_number=None, is_precert=False
):
    temp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    gn = x509.RFC822Name(san_value) if "@" in san_value else x509.DNSName(san_value)
    eku = x509.OID_EMAIL_PROTECTION if "@" in san_value else x509.OID_SERVER_AUTH

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(issuer_cert.subject)
        .public_key(temp_key.public_key())
        .serial_number(serial_number or x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_BEFORE + datetime.timedelta(days=100))
        .add_extension(SubjectAlternativeName([gn]), critical=True)
        .add_extension(ExtendedKeyUsage([eku]), critical=False)
    )

    if is_precert:
        builder = builder.add_extension(x509.PrecertPoison(), critical=True)

    return builder.sign(issuer_key, hashes.SHA256())


dnsname_counter = 0


def generate_tls_ee(issuer_cert, issuer_key, serial_number=None, is_precert=False):
    global dnsname_counter

    dnsname_counter += 1

    return _generate_ee(
        issuer_cert,
        issuer_key,
        f"test{dnsname_counter}.example",
        serial_number,
        is_precert,
    )


rfc822_name_counter = 0


def generate_smime_ee(issuer_cert, issuer_key):
    global rfc822_name_counter

    rfc822_name_counter += 1

    return _generate_ee(
        issuer_cert, issuer_key, f"test{rfc822_name_counter}@test.example"
    )


def generate_crl(
    issuer_cert, issuer_key, revoked_certs, idp_uri=None, this_update=None
):
    this_update = this_update or _NOT_BEFORE

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(this_update)
        .next_update(this_update + datetime.timedelta(days=7))
    )

    for serial_number, revocation_date, reason in revoked_certs:
        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial_number)
            .revocation_date(revocation_date)
        )
        if reason:
            revoked_cert = revoked_cert.add_extension(
                x509.CRLReason(reason),
                critical=False,
            )
        revoked_cert = revoked_cert.build()

        builder = builder.add_revoked_certificate(revoked_cert)

    if idp_uri:
        builder = builder.add_extension(
            x509.IssuingDistributionPoint(
                full_name=[x509.UniformResourceIdentifier(idp_uri)],
                relative_name=None,
                only_contains_user_certs=False,
                only_contains_ca_certs=False,
                only_some_reasons=None,
                indirect_crl=False,
                only_contains_attribute_certs=False,
            ),
            critical=True,
        )

    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
