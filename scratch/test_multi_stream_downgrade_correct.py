import sys
from pathlib import Path

backend_dir = Path("backend")
sys.path.insert(0, str(backend_dir))

from scapy.all import wrpcap
from scripts.generate_demo_pcaps import pkt, make_tls_cert_record, DER_BAD, DER_MODERN
from scripts.extract_demo_features import process_single_pcap
from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello, TLS_Ext_ServerName, ServerName

# Multi-stream downgrade PCAP:
# Stream 1: SMTP session where STARTTLS is offered and downgraded
# Stream 2: TLS probe session where defective certificate is observed
client, server = "10.10.0.10", "10.10.0.20"
sport1, dport = 45000, 25
sport2 = 45002

packets = []

# Stream 1: SMTP Downgrade
cseq1, sseq1 = 1000, 5000
packets.append(pkt(client, server, sport1, dport, cseq1, sseq1, "S"))
cseq1 += 1
packets.append(pkt(server, client, dport, sport1, sseq1, cseq1, "SA"))
sseq1 += 1
packets.append(pkt(client, server, sport1, dport, cseq1, sseq1, "A"))

def s1(data):
    global sseq1
    b = data.encode()
    packets.append(pkt(server, client, dport, sport1, sseq1, cseq1, "PA", b))
    sseq1 += len(b)

def c1(data):
    global cseq1
    b = data.encode()
    packets.append(pkt(client, server, sport1, dport, cseq1, sseq1, "PA", b))
    cseq1 += len(b)

s1("220 mail.demo.local ESMTP MailRakhwalaDemo\r\n")
c1("EHLO client.demo.local\r\n")
s1("250-mail.demo.local\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n")
c1("STARTTLS\r\n")
s1("220 2.0.0 Ready to start TLS\r\n")
c1("AUTH LOGIN\r\n")
s1("334 VXNlcm5hbWU6\r\n")
c1("dGVzdHVzZXI=\r\n")
s1("334 UGFzc3dvcmQ6\r\n")
c1("cGFzc3dvcmQ=\r\n")
s1("235 2.7.0 Authentication successful\r\n")
c1("MAIL FROM:<alice@example.test>\r\n")
s1("250 2.1.0 OK\r\n")
c1("RCPT TO:<bob@example.test>\r\n")
s1("250 2.1.5 OK\r\n")
c1("QUIT\r\n")
s1("221 2.0.0 Bye\r\n")
packets.append(pkt(client, server, sport1, dport, cseq1, sseq1, "FA"))

# Stream 2: Probe TLS session
cseq2, sseq2 = 2000, 6000
packets.append(pkt(client, server, sport2, dport, cseq2, sseq2, "S"))
cseq2 += 1
packets.append(pkt(server, client, dport, sport2, sseq2, cseq2, "SA"))
sseq2 += 1
packets.append(pkt(client, server, sport2, dport, cseq2, sseq2, "A"))

ch = bytes(TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0x002f])]))
packets.append(pkt(client, server, sport2, dport, cseq2, sseq2, "PA", ch))
cseq2 += len(ch)

sh = bytes(TLS(msg=[TLSServerHello(version=0x0303, cipher=0x002f)]))
cert_rec = make_tls_cert_record(DER_BAD, version=(3, 3))
sh_done = bytes([0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00])
combined_sh = sh + cert_rec + sh_done
packets.append(pkt(server, client, dport, sport2, sseq2, cseq2, "PA", combined_sh))
sseq2 += len(combined_sh)
packets.append(pkt(client, server, sport2, dport, cseq2, sseq2, "FA"))

test_p = Path("scratch/test_ms_downgrade.pcap")
wrpcap(str(test_p), packets)
print(f"Generated {len(packets)} packets in {test_p}")

res = process_single_pcap(test_p, "starttls_downgrade", "HIGH")
print("Process single pcap result:")
print("  Posture Score:", res["posture_score"])
print("  Downgrade:    ", res["features"]["starttls_downgrade"])
print("  Cert Key Size:", res["features"]["certificate_key_size"])
print("  Violations:   ", res["features"]["compliance_violation_count"])
print("  High/Crit:    ", res["features"]["high_critical_finding_count"])
print("  Score feat:   ", res["features"]["cryptographic_security_score"])
