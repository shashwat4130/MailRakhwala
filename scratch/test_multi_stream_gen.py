import sys
from pathlib import Path

backend_dir = Path("backend")
sys.path.insert(0, str(backend_dir))

from scapy.all import wrpcap
from scripts.generate_demo_pcaps import pkt, make_tls_cert_record, DER_BAD, DER_MODERN
from scripts.extract_demo_features import process_single_pcap
from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello, TLS_Ext_ServerName, ServerName

# Let's create a synthetic multi-stream downgrade pcap
client, server = "10.10.0.10", "10.10.0.20"
sport1, dport = 45000, 25
sport2 = 45002

packets = []
# Stream 1: TLS probe with 1024-bit cert
cseq, sseq = 1000, 5000
packets.append(pkt(client, server, sport1, dport, cseq, sseq, "S"))
cseq += 1
packets.append(pkt(server, client, dport, sport1, sseq, cseq, "SA"))
sseq += 1
packets.append(pkt(client, server, sport1, dport, cseq, sseq, "A"))

ch = bytes(TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0x002f])]))
packets.append(pkt(client, server, sport1, dport, cseq, sseq, "PA", ch))
cseq += len(ch)

sh = bytes(TLS(msg=[TLSServerHello(version=0x0303, cipher=0x002f)]))
cert_rec = make_tls_cert_record(DER_BAD, version=(3, 3))
sh_done = bytes([0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00])
combined_sh = sh + cert_rec + sh_done
packets.append(pkt(server, client, dport, sport1, sseq, cseq, "PA", combined_sh))
sseq += len(combined_sh)
packets.append(pkt(client, server, sport1, dport, cseq, sseq, "FA"))

# Stream 2: SMTP with STARTTLS downgrade
cseq2, sseq2 = 2000, 6000
packets.append(pkt(client, server, sport2, dport, cseq2, sseq2, "S"))
cseq2 += 1
packets.append(pkt(server, client, dport, sport2, sseq2, cseq2, "SA"))
sseq2 += 1
packets.append(pkt(client, server, sport2, dport, cseq2, sseq2, "A"))

def s2(data):
    global sseq2
    b = data.encode()
    packets.append(pkt(server, client, dport, sport2, sseq2, cseq2, "PA", b))
    sseq2 += len(b)

def c2(data):
    global cseq2
    b = data.encode()
    packets.append(pkt(client, server, sport2, dport, cseq2, sseq2, "PA", b))
    cseq2 += len(b)

s2("220 mail.demo.local ESMTP MailRakhwalaDemo\r\n")
c2("EHLO client.demo.local\r\n")
s2("250-mail.demo.local\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n")
c2("STARTTLS\r\n")
s2("220 2.0.0 Ready to start TLS\r\n")
c2("AUTH LOGIN\r\n")
s2("334 VXNlcm5hbWU6\r\n")
c2("dGVzdHVzZXI=\r\n")
s2("334 UGFzc3dvcmQ6\r\n")
c2("cGFzc3dvcmQ=\r\n")
s2("235 2.7.0 Authentication successful\r\n")
c2("MAIL FROM:<alice@example.test>\r\n")
s2("250 2.1.0 OK\r\n")
c2("RCPT TO:<bob@example.test>\r\n")
s2("250 2.1.5 OK\r\n")
c2("QUIT\r\n")
s2("221 2.0.0 Bye\r\n")
packets.append(pkt(client, server, sport2, dport, cseq2, sseq2, "FA"))

test_pcap_path = Path("scratch/test_multi_downgrade.pcap")
wrpcap(str(test_pcap_path), packets)
print(f"Wrote multi-stream pcap with {len(packets)} packets to {test_pcap_path}")

res = process_single_pcap(test_pcap_path, "starttls_downgrade", "HIGH")
print("Process single pcap result:")
print("  Posture Score:", res["posture_score"])
print("  Downgrade:", res["features"]["starttls_downgrade"])
print("  Cert Key Size:", res["features"]["certificate_key_size"])
print("  Violations:", res["features"]["compliance_violation_count"])
print("  High/Crit:", res["features"]["high_critical_finding_count"])
