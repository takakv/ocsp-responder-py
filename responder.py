import os
import sys
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.x509 import ocsp, load_pem_x509_certificate, Certificate
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response

load_dotenv()
OCSP_KEY_FILE = os.getenv("OCSP_KEY_FILE")
OCSP_CERT_FILE = os.getenv("OCSP_CERT_FILE")
OCSP_KEY_SECRET = os.getenv("OCSP_KEY_SECRET").encode("utf-8")
USER_CERT_DIR = os.getenv("USER_CERT_DIR")

OCSP_CERT: Certificate
OCSP_KEY: EllipticCurvePrivateKey
OCSP_KEY_ID: bytes

NEXT_UPDATE_DAYS = 7


def init():
    global OCSP_CERT
    global OCSP_KEY
    global OCSP_KEY_ID

    if not os.path.exists(USER_CERT_DIR):
        print("User certificate directory does not exist!")
        sys.exit(1)

    try:
        with open(OCSP_CERT_FILE, "rb") as f:
            OCSP_CERT = load_pem_x509_certificate(f.read())
            ski_extension = OCSP_CERT.extensions.get_extension_for_oid(x509.SubjectKeyIdentifier.oid)
            # noinspection PyTypeChecker
            ski_extension_value: x509.SubjectKeyIdentifier = ski_extension.value
            OCSP_KEY_ID = ski_extension_value.digest
    except Exception as e:
        print(e)
        sys.exit(1)

    try:
        with open(OCSP_KEY_FILE, "rb") as f:
            OCSP_KEY = serialization.load_pem_private_key(f.read(), OCSP_KEY_SECRET)
    except Exception as e:
        print(e)
        sys.exit(1)


def prepare_response(response: ocsp.OCSPResponse) -> Response:
    return Response(content=response.public_bytes(serialization.Encoding.DER),
                    media_type="application/ocsp-response")


init()

app = FastAPI()


@app.post("/")
async def read_root(request: Request):
    req_bin = await request.body()
    try:
        ocsp_req = ocsp.load_der_ocsp_request(req_bin)
    except ValueError as e:
        print(e)
        response = ocsp.OCSPResponseBuilder().build_unsuccessful(
            ocsp.OCSPResponseStatus.MALFORMED_REQUEST
        )
        return Response(status_code=400, content=response.public_bytes(serialization.Encoding.DER),
                        media_type="application/ocsp-response")

    requested_cert_serial = ocsp_req.serial_number
    issuer_name_hash = ocsp_req.issuer_name_hash
    issuer_key_hash = ocsp_req.issuer_key_hash

    rcs_hex = requested_cert_serial.to_bytes(20, "big").hex()

    is_unknown = OCSP_KEY_ID != issuer_key_hash
    if not is_unknown:
        try:
            with open(f"{USER_CERT_DIR}/{rcs_hex}.pem", "rb") as f:
                requested_cert = load_pem_x509_certificate(f.read())
        except FileNotFoundError as e:
            print(e)
            is_unknown = True

    # Additional validations needed, e.g. verify issuer name hash.
    if is_unknown:
        response = ocsp.OCSPResponseBuilder().build_unsuccessful(
            ocsp.OCSPResponseStatus.UNAUTHORIZED
        )
        return prepare_response(response)

    cert_status = ocsp.OCSPCertStatus.GOOD
    revocation_time = None
    revocation_reason = None

    next_update = datetime.now(timezone.utc) + timedelta(days=NEXT_UPDATE_DAYS)

    builder = ocsp.OCSPResponseBuilder()
    builder = builder.add_response(
        cert=requested_cert,
        issuer=OCSP_CERT,
        algorithm=hashes.SHA1(),
        cert_status=cert_status,
        this_update=datetime.now(timezone.utc),
        next_update=next_update,
        revocation_time=revocation_time,
        revocation_reason=revocation_reason
    ).responder_id(
        ocsp.OCSPResponderEncoding.NAME, OCSP_CERT
    )

    response = builder.sign(OCSP_KEY, hashes.SHA384())
    return prepare_response(response)
