import base64
import io
import qrcode
import re
import pem
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.backends import default_backend
def qr_png_base64(data: str) -> str:
    """Return a data URI (base64) for a PNG QR of the provided data string."""
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"




def _extract_iin(serial_number: str | None) -> str | None:
    if not serial_number:
        return None
    # В личных сертификатах обычно есть "IIN" или просто 12 цифр
    m = re.search(r"\b(\d{12})\b", serial_number)
    return m.group(1) if m else None

def parse_cms_get_subject_and_iin(pem_data: str, cert_type: str = "personal") -> dict:
    """
    Возвращает:
      {
        'success': True/False,
        'payload': {
            'subject': {...},
            'issuer':  {...},
            'iin': '123456789012' | None
        } | {'error': '...'}
      }
    """
    try:
        pem_bytes = pem_data.encode("utf-8")
        if pem.detect(pem_bytes):
            _, _, der_bytes = pem.unarmor(pem_bytes)
        else:
            der_bytes = pem_bytes

        content_info = cms.ContentInfo.load(der_bytes)
        if content_info["content_type"].native != "signed_data":
            raise ValueError("Это не CMS SignedData")

        signed_data = content_info["content"]
        certs = signed_data["certificates"] or []
        if not certs:
            raise ValueError("Сертификаты не найдены в CMS")

        signer_cert_der = certs[0].chosen.dump()
        cert = x509.load_der_x509_certificate(signer_cert_der, default_backend())

        subject_attrs = {attr.oid._name: attr.value for attr in cert.subject}
        issuer_attrs = {attr.oid._name: attr.value for attr in cert.issuer}

        serial_number = subject_attrs.get("serialNumber")
        iin = _extract_iin(serial_number)

        wanted_personal = ["commonName", "surname", "givenName", "serialNumber", "countryName"]
        wanted_org = ["commonName", "organizationName", "organizationalUnitName", "serialNumber", "countryName"]
        wanted = wanted_personal if cert_type == "personal" else wanted_org

        subject = {k: v for k, v in subject_attrs.items() if k in wanted}
        issuer = {
            "commonName": issuer_attrs.get("commonName"),
            "organizationName": issuer_attrs.get("organizationName"),
            "countryName": issuer_attrs.get("countryName"),
        }
        return {"success": True, "payload": {"subject": subject, "issuer": issuer, "iin": iin}}
    except Exception as e:
        return {"success": False, "payload": {"error": str(e)}}