"""
/api/v1/certificates — PKI management: issue, revoke, list, download.
Implements internal CA for EAP-TLS client certificate authentication.
"""

import json
import os
import subprocess
import tempfile
import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.core.database import get_db

router = APIRouter()

CERT_DIR = os.getenv("CERT_DIR", "/app/certs")
CA_CERT = os.path.join(CERT_DIR, "client-ca.pem")
CA_KEY = os.path.join(CERT_DIR, "client-ca.key")
CA_CHAIN = os.path.join(CERT_DIR, "ca-chain.pem")


class CertIssueRequest(BaseModel):
    common_name: str
    cert_type: str = "user"  # user | machine
    username: Optional[str] = None
    email: Optional[str] = None
    department: Optional[str] = None
    mac_address: Optional[str] = None
    validity_days: int = 365
    p12_password: str = "changeme"


class CertRevokeRequest(BaseModel):
    reason: str = "unspecified"  # unspecified, keyCompromise, cessationOfOperation, superseded


# ─── List certificates ───

@router.get("/certificates")
async def list_certificates(
    status: Optional[str] = None,
    cert_type: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 200,
    db: AsyncSession = Depends(get_db),
):
    where = ["1=1"]
    params = {"limit": limit}
    if status:
        where.append("status = :status")
        params["status"] = status
    if cert_type:
        where.append("cert_type = :cert_type")
        params["cert_type"] = cert_type
    if search:
        where.append("(common_name LIKE :s OR username LIKE :s OR email LIKE :s OR serial_number LIKE :s)")
        params["s"] = f"%{search}%"

    q = f"""
        SELECT id, serial_number, common_name, subject_dn, issuer_dn,
               not_before, not_after, status, revocation_date, revocation_reason,
               cert_type, username, mac_address, department, email,
               fingerprint_sha256, created_at
        FROM nac_certificates
        WHERE {' AND '.join(where)}
        ORDER BY created_at DESC LIMIT :limit
    """
    result = await db.execute(text(q), params)
    rows = result.fetchall()

    items = []
    for r in rows:
        items.append({
            "id": r[0], "serial_number": r[1], "common_name": r[2],
            "subject_dn": r[3], "issuer_dn": r[4],
            "not_before": str(r[5]) if r[5] else None,
            "not_after": str(r[6]) if r[6] else None,
            "status": r[7], "revocation_date": str(r[8]) if r[8] else None,
            "revocation_reason": r[9], "cert_type": r[10],
            "username": r[11], "mac_address": r[12],
            "department": r[13], "email": r[14],
            "fingerprint_sha256": r[15], "created_at": str(r[16]) if r[16] else None,
        })

    # Stats
    stats_result = await db.execute(text("""
        SELECT status, COUNT(*) FROM nac_certificates GROUP BY status
    """))
    stats = {r[0]: r[1] for r in stats_result.fetchall()}

    return {
        "total": len(items),
        "items": items,
        "stats": {
            "active": stats.get("active", 0),
            "revoked": stats.get("revoked", 0),
            "expired": stats.get("expired", 0),
            "pending": stats.get("pending", 0),
        },
    }


# ─── Get single certificate ───

@router.get("/certificates/{cert_id}")
async def get_certificate(cert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(text(
        "SELECT * FROM nac_certificates WHERE id = :id"
    ), {"id": cert_id})
    row = result.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Certificate not found")
    cols = result.keys()
    return dict(zip(cols, row))


# ─── Issue new certificate ───

@router.post("/certificates/issue")
async def issue_certificate(req: CertIssueRequest, db: AsyncSession = Depends(get_db)):
    if not os.path.exists(CA_KEY):
        raise HTTPException(status_code=500, detail="CA key not found. Mount certs volume.")

    serial = secrets.token_hex(8).upper()
    not_before = datetime.utcnow()
    not_after = not_before + timedelta(days=req.validity_days)

    # Build subject
    subj_parts = ["/C=RU", "/ST=Moscow", "/O=Open NAC"]
    if req.department:
        subj_parts.append(f"/OU={req.department}")
    else:
        subj_parts.append(f"/OU={'Users' if req.cert_type == 'user' else 'Machines'}")
    subj_parts.append(f"/CN={req.common_name}")
    if req.email:
        subj_parts.append(f"/emailAddress={req.email}")
    subject = "".join(subj_parts)

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, "client.key")
            csr_path = os.path.join(tmpdir, "client.csr")
            cert_path = os.path.join(tmpdir, "client.pem")
            p12_path = os.path.join(tmpdir, "client.p12")
            ext_path = os.path.join(tmpdir, "client.ext")

            # Generate key
            subprocess.run(
                ["openssl", "genrsa", "-out", key_path, "2048"],
                check=True, capture_output=True
            )

            # Generate CSR
            subprocess.run(
                ["openssl", "req", "-new", "-key", key_path, "-out", csr_path,
                 "-subj", subject],
                check=True, capture_output=True
            )

            # Extensions
            ext_content = f"""basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
"""
            with open(ext_path, "w") as f:
                f.write(ext_content)

            # Sign with Client CA
            subprocess.run(
                ["openssl", "x509", "-req", "-days", str(req.validity_days),
                 "-in", csr_path, "-CA", CA_CERT, "-CAkey", CA_KEY,
                 "-set_serial", f"0x{serial}",
                 "-out", cert_path, "-extfile", ext_path],
                check=True, capture_output=True
            )

            # Read cert PEM
            with open(cert_path, "r") as f:
                cert_pem = f.read()

            # Read key PEM
            with open(key_path, "r") as f:
                key_pem = f.read()

            # Create PKCS#12
            subprocess.run(
                ["openssl", "pkcs12", "-export", "-out", p12_path,
                 "-inkey", key_path, "-in", cert_path, "-certfile", CA_CHAIN,
                 "-passout", f"pass:{req.p12_password}"],
                check=True, capture_output=True
            )

            with open(p12_path, "rb") as f:
                p12_data = base64.b64encode(f.read()).decode()

            # Fingerprint
            fp_result = subprocess.run(
                ["openssl", "x509", "-in", cert_path, "-noout", "-fingerprint", "-sha256"],
                capture_output=True, text=True
            )
            fingerprint = fp_result.stdout.strip().split("=", 1)[-1] if fp_result.returncode == 0 else ""

            # Issuer DN
            issuer_result = subprocess.run(
                ["openssl", "x509", "-in", CA_CERT, "-noout", "-subject"],
                capture_output=True, text=True
            )
            issuer_dn = issuer_result.stdout.strip().replace("subject=", "") if issuer_result.returncode == 0 else ""

    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"OpenSSL error: {e.stderr.decode()}")

    # Store in database
    await db.execute(
        text("""
            INSERT INTO nac_certificates
            (serial_number, common_name, subject_dn, issuer_dn, not_before, not_after,
             status, cert_type, username, mac_address, department, email,
             certificate_pem, fingerprint_sha256)
            VALUES (:serial, :cn, :subj, :issuer, :nb, :na,
                    'active', :ctype, :user, :mac, :dept, :email,
                    :pem, :fp)
        """),
        {
            "serial": serial, "cn": req.common_name, "subj": subject,
            "issuer": issuer_dn, "nb": not_before, "na": not_after,
            "ctype": req.cert_type, "user": req.username or req.common_name,
            "mac": req.mac_address, "dept": req.department,
            "email": req.email, "pem": cert_pem, "fp": fingerprint,
        },
    )
    await db.commit()

    return {
        "status": "issued",
        "serial_number": serial,
        "common_name": req.common_name,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "fingerprint_sha256": fingerprint,
        "p12_base64": p12_data,
        "p12_password": req.p12_password,
        "cert_pem": cert_pem,
        "key_pem": key_pem,
    }


# ─── Revoke certificate ───

@router.post("/certificates/{cert_id}/revoke")
async def revoke_certificate(cert_id: int, req: CertRevokeRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(text(
        "SELECT serial_number, status FROM nac_certificates WHERE id = :id"
    ), {"id": cert_id})
    row = result.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Certificate not found")
    if row[1] == "revoked":
        raise HTTPException(status_code=400, detail="Already revoked")

    await db.execute(
        text("""
            UPDATE nac_certificates
            SET status = 'revoked', revocation_date = NOW(), revocation_reason = :reason
            WHERE id = :id
        """),
        {"id": cert_id, "reason": req.reason},
    )
    await db.commit()

    return {"status": "revoked", "id": cert_id, "serial_number": row[0], "reason": req.reason}


# ─── Download certificate as PEM ───

@router.get("/certificates/{cert_id}/download/pem")
async def download_cert_pem(cert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(text(
        "SELECT common_name, certificate_pem FROM nac_certificates WHERE id = :id"
    ), {"id": cert_id})
    row = result.fetchone()
    if not row or not row[1]:
        raise HTTPException(status_code=404, detail="Certificate PEM not found")
    return Response(
        content=row[1],
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{row[0]}.pem"'},
    )


# ─── CA Info ───

@router.get("/certificates/ca/info")
async def ca_info():
    info = {"ca_available": False}
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", CA_CERT, "-noout", "-subject", "-issuer", "-dates", "-serial"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            info["ca_available"] = True
            for line in result.stdout.strip().split("\n"):
                if "subject=" in line:
                    info["subject"] = line.split("subject=", 1)[1].strip()
                elif "issuer=" in line:
                    info["issuer"] = line.split("issuer=", 1)[1].strip()
                elif "notBefore=" in line:
                    info["not_before"] = line.split("=", 1)[1].strip()
                elif "notAfter=" in line:
                    info["not_after"] = line.split("=", 1)[1].strip()
                elif "serial=" in line:
                    info["serial"] = line.split("=", 1)[1].strip()

        # Chain info
        chain_result = subprocess.run(
            ["openssl", "x509", "-in", CA_CHAIN, "-noout", "-subject"],
            capture_output=True, text=True
        )
        if chain_result.returncode == 0:
            info["chain_subject"] = chain_result.stdout.strip().split("subject=", 1)[-1].strip()
    except Exception as e:
        info["error"] = str(e)

    return info
