#!/usr/bin/env python3
"""
Mail Rakhwala — Synthetic Demo PCAP Training Dataset Generator

This script generates synthetic, clearly labeled demonstration PCAPs for local
development, pipeline testing, and proof-of-concept ML experiments.

IMPORTANT:
These captures are deliberately synthetic and generated for demonstration purposes.
They must NOT be represented as models or telemetry validated on real-world email traffic.
"""

import argparse
import csv
import datetime
from pathlib import Path
import random

from scapy.all import Ether, IP, TCP, wrpcap
from scapy.layers.tls.all import (
    TLS,
    TLSClientHello,
    TLSServerHello,
    TLS_Ext_SupportedGroups,
    TLS_Ext_ServerName,
    ServerName,
)

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate deterministic RSA keys for synthetic demo certificates
_RNG = random.Random(20261002)
RSA_KEY_2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_KEY_1024 = rsa.generate_private_key(public_exponent=65537, key_size=1024)

# 1. Valid modern certificate for mail.demo.local
CERT_MODERN = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mail.demo.local")]))
    .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Demo CA")]))
    .public_key(RSA_KEY_2048.public_key())
    .serial_number(1001)
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([x509.DNSName("mail.demo.local")]),
        critical=False,
    )
    .sign(RSA_KEY_2048, hashes.SHA256())
)
DER_MODERN = CERT_MODERN.public_bytes(serialization.Encoding.DER)

# 2. Defective certificate: Expired, 1024-bit key, self-signed, hostname mismatch
CERT_BAD = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil.attacker.local")]))
    .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil.attacker.local")]))
    .public_key(RSA_KEY_1024.public_key())
    .serial_number(1002)
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=200))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=20))
    .sign(RSA_KEY_1024, hashes.SHA256())
)
DER_BAD = CERT_BAD.public_bytes(serialization.Encoding.DER)


def make_tls_cert_record(cert_der: bytes, version=(3, 3)) -> bytes:
    """Builds a binary TLS Certificate Handshake Record (msg_type=11)."""
    c_len = len(cert_der)
    cert_entry = bytes([(c_len >> 16) & 0xff, (c_len >> 8) & 0xff, c_len & 0xff]) + cert_der
    certs_len = len(cert_entry)
    certs_bytes = bytes([(certs_len >> 16) & 0xff, (certs_len >> 8) & 0xff, certs_len & 0xff]) + cert_entry
    msg_len = len(certs_bytes)
    hs_msg = bytes([11, (msg_len >> 16) & 0xff, (msg_len >> 8) & 0xff, msg_len & 0xff]) + certs_bytes
    rec_len = len(hs_msg)
    rec_hdr = bytes([0x16, version[0], version[1], (rec_len >> 8) & 0xff, rec_len & 0xff])
    return rec_hdr + hs_msg


def pkt(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: str, payload: bytes = b""):
    smac = "00:11:22:33:44:55" if src == "10.10.0.10" else "00:66:77:88:99:aa"
    dmac = "00:66:77:88:99:aa" if src == "10.10.0.10" else "00:11:22:33:44:55"
    return Ether(src=smac, dst=dmac) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags) / payload


def smtp_capture(kind: str, seed: int):
    """
    Constructs a deterministic synthetic SMTP session corresponding to one of six demonstration scenarios:
      - tls_modern:          Clean STARTTLS upgrade with TLS 1.2/1.3 ECDHE-RSA-AES128-GCM-SHA256 and valid cert.
      - starttls_clean:      Clean STARTTLS upgrade with valid parameters and cert.
      - weak_tls:            STARTTLS upgrade with legacy TLS 1.0, static RSA, CBC ciphers, no PFS.
      - starttls_downgrade:  Server advertises STARTTLS, client initiates STARTTLS, server accepts, but cleartext follows.
      - plaintext:           Cleartext SMTP with authentication in plain text, no STARTTLS negotiation.
      - cert_bad:            STARTTLS upgrade with TLS 1.2, but certificate is expired, self-signed, 1024-bit key.
    """
    client, server = "10.10.0.10", "10.10.0.20"
    sport, dport = 40000 + (seed % 20000), 25
    cseq, sseq = 1000 + (seed % 1000), 5000 + (seed % 1000)
    packets = []

    # 3-Way TCP Handshake
    packets.append(pkt(client, server, sport, dport, cseq, sseq, "S"))
    cseq += 1
    packets.append(pkt(server, client, dport, sport, sseq, cseq, "SA"))
    sseq += 1
    packets.append(pkt(client, server, sport, dport, cseq, sseq, "A"))

    def c(data):
        nonlocal cseq
        b = data if isinstance(data, bytes) else data.encode()
        packets.append(pkt(client, server, sport, dport, cseq, sseq, "PA", b))
        cseq += len(b)

    def s(data):
        nonlocal sseq
        b = data if isinstance(data, bytes) else data.encode()
        packets.append(pkt(server, client, dport, sport, sseq, cseq, "PA", b))
        sseq += len(b)

    # Initial SMTP Banner & Greeting
    s("220 mail.demo.local ESMTP MailRakhwalaDemo\r\n")
    c("EHLO client.demo.local\r\n")

    if kind == "plaintext":
        if seed % 2 == 0:
            s("250-mail.demo.local\r\n250 AUTH PLAIN LOGIN\r\n")
            c("AUTH LOGIN\r\n")
            s("334 VXNlcm5hbWU6\r\n")
            c("dGVzdHVzZXI=\r\n")
            s("334 UGFzc3dvcmQ6\r\n")
            c("cGFzc3dvcmQ=\r\n")
            s("235 2.7.0 Authentication successful\r\n")
        else:
            s("250-mail.demo.local\r\n250 HELP\r\n")
        c("MAIL FROM:<alice@example.test>\r\n")
        s("250 2.1.0 OK\r\n")
        c("RCPT TO:<bob@example.test>\r\n")
        s("250 2.1.5 OK\r\n")
        c("QUIT\r\n")
        s("221 2.0.0 Bye\r\n")

    elif kind == "starttls_downgrade":
        s("250-mail.demo.local\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n")
        c("STARTTLS\r\n")
        s("220 2.0.0 Ready to start TLS\r\n")
        # Attacker intercepts/strips TLS transition; cleartext commands continue
        if seed % 2 == 0:
            c("AUTH LOGIN\r\n")
            s("334 VXNlcm5hbWU6\r\n")
            c("dGVzdHVzZXI=\r\n")
            s("334 UGFzc3dvcmQ6\r\n")
            c("cGFzc3dvcmQ=\r\n")
            s("235 2.7.0 Authentication successful\r\n")
        c("MAIL FROM:<alice@example.test>\r\n")
        s("250 2.1.0 OK\r\n")
        c("RCPT TO:<bob@example.test>\r\n")
        s("250 2.1.5 OK\r\n")
        c("QUIT\r\n")
        s("221 2.0.0 Bye\r\n")

    elif kind == "tls_modern":
        s("250-mail.demo.local\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")
        c("STARTTLS\r\n")
        s("220 2.0.0 Ready to start TLS\r\n")
        # TLS 1.2/1.3 with ECDHE and AEAD cipher suites, X25519, and valid certificate
        cipher_choice = 0xc030 if (seed % 2 == 1) else 0xc02f  # AES-256-GCM vs AES-128-GCM
        ch = bytes(TLS(msg=[TLSClientHello(
            version=0x0303,
            ciphers=[cipher_choice, 0x1301],
            ext=[
                TLS_Ext_ServerName(servernames=[ServerName(servername="mail.demo.local")]),
                TLS_Ext_SupportedGroups(groups=[0x001d, 0x0017]),
            ]
        )]))
        c(ch)
        sh = bytes(TLS(msg=[TLSServerHello(
            version=0x0303,
            cipher=cipher_choice,
        )]))
        cert_rec = make_tls_cert_record(DER_MODERN, version=(3, 3))
        sh_done = bytes([0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00])
        s(sh + cert_rec + sh_done)
        # Encrypted application data records
        c(bytes([0x17, 0x03, 0x03, 0x00, 0x20]) + b"\xaa" * 32)
        s(bytes([0x17, 0x03, 0x03, 0x00, 0x20]) + b"\xbb" * 32)

    elif kind == "starttls_clean":
        s("250-mail.demo.local\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")
        c("STARTTLS\r\n")
        s("220 2.0.0 Ready to start TLS\r\n")
        ch = bytes(TLS(msg=[TLSClientHello(
            version=0x0303,
            ciphers=[0xc02f, 0xc02b],
            ext=[
                TLS_Ext_ServerName(servernames=[ServerName(servername="mail.demo.local")]),
                TLS_Ext_SupportedGroups(groups=[0x001d]),
            ]
        )]))
        c(ch)
        sh = bytes(TLS(msg=[TLSServerHello(
            version=0x0303,
            cipher=0xc02f,
        )]))
        cert_rec = make_tls_cert_record(DER_MODERN, version=(3, 3))
        sh_done = bytes([0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00])
        s(sh + cert_rec + sh_done)
        c(bytes([0x17, 0x03, 0x03, 0x00, 0x20]) + b"\xaa" * 32)
        s(bytes([0x17, 0x03, 0x03, 0x00, 0x20]) + b"\xbb" * 32)

    elif kind == "weak_tls":
        s("250-mail.demo.local\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")
        c("STARTTLS\r\n")
        s("220 2.0.0 Ready to start TLS\r\n")
        # Legacy TLS 1.0/1.1 with static RSA and AES-CBC, no PFS
        tls_ver = 0x0301 if (seed % 2 == 0) else 0x0302  # TLS 1.0 or TLS 1.1
        cipher_choice = 0x002f if (seed % 3 == 0) else (0x0035 if (seed % 3 == 1) else 0x000a)  # AES-128-CBC, AES-256-CBC, or 3DES
        ch = bytes(TLS(msg=[TLSClientHello(
            version=tls_ver,
            ciphers=[cipher_choice],
            ext=[
                TLS_Ext_ServerName(servernames=[ServerName(servername="mail.demo.local")]),
            ]
        )]))
        c(ch)
        sh = bytes(TLS(msg=[TLSServerHello(
            version=tls_ver,
            cipher=cipher_choice,
        )]))
        ver_bytes = (3, 1) if tls_ver == 0x0301 else (3, 2)
        cert_rec = make_tls_cert_record(DER_MODERN, version=ver_bytes)
        sh_done = bytes([0x16, ver_bytes[0], ver_bytes[1], 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00])
        s(sh + cert_rec + sh_done)
        c(bytes([0x17, ver_bytes[0], ver_bytes[1], 0x00, 0x20]) + b"\xaa" * 32)
        s(bytes([0x17, ver_bytes[0], ver_bytes[1], 0x00, 0x20]) + b"\xbb" * 32)

    elif kind == "cert_bad":
        s("250-mail.demo.local\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")
        c("STARTTLS\r\n")
        s("220 2.0.0 Ready to start TLS\r\n")
        ch = bytes(TLS(msg=[TLSClientHello(
            version=0x0303,
            ciphers=[0xc02f],
            ext=[
                TLS_Ext_ServerName(servernames=[ServerName(servername="mail.demo.local")]),
                TLS_Ext_SupportedGroups(groups=[0x001d]),
            ]
        )]))
        c(ch)
        sh = bytes(TLS(msg=[TLSServerHello(
            version=0x0303,
            cipher=0xc02f,
        )]))
        # Defective certificate: Expired, self-signed, 1024-bit RSA, hostname mismatch
        cert_rec = make_tls_cert_record(DER_BAD, version=(3, 3))
        sh_done = bytes([0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00])
        s(sh + cert_rec + sh_done)
        c(bytes([0x17, 0x03, 0x03, 0x00, 0x20]) + b"\xaa" * 32)
        s(bytes([0x17, 0x03, 0x03, 0x00, 0x20]) + b"\xbb" * 32)

    # TCP Teardown
    packets.append(pkt(client, server, sport, dport, cseq, sseq, "FA"))
    return packets


KINDS = [
    ("tls_modern", "LOW"),
    ("starttls_clean", "LOW"),
    ("weak_tls", "MEDIUM"),
    ("starttls_downgrade", "HIGH"),
    ("plaintext", "HIGH"),
    ("cert_bad", "CRITICAL"),
]


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic demo PCAP corpus for Mail Rakhwala.")
    parser.add_argument("--output", default="data/demo_dataset", help="Output directory for generated PCAPs")
    parser.add_argument("--per-class", type=int, default=40, help="Number of captures per scenario class")
    parser.add_argument("--seed", type=int, default=20261002, help="Deterministic random seed")
    args = parser.parse_args()

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    n = 0
    for kind, label in KINDS:
        for i in range(args.per_class):
            n += 1
            filename = f"{n:04d}_{kind}_{i:03d}.pcap"
            file_path = out_dir / filename
            pkts = smtp_capture(kind, args.seed + n)
            wrpcap(str(file_path), pkts)
            rows.append([filename, kind, label, "synthetic-demo-v1"])

    manifest_path = out_dir / "manifest.csv"
    with manifest_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["pcap", "scenario", "risk_label", "dataset"])
        writer.writerows(rows)

    print(f"Generated {n} synthetic demo PCAP files in {out_dir}")
    print(f"Manifest written to: {manifest_path}")


if __name__ == "__main__":
    main()
