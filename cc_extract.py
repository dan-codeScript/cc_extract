#!/usr/bin/env python3
"""
cc_extract.py — extraction de numéros de carte bancaire depuis un fichier .pcap/.pcapng
Zéro dépendance externe : lecteur pcap écrit à la main, regex par réseau de carte,
validation Luhn, reassemblage des flux TCP (capte un numéro coupé entre deux paquets).

Usage:
    python3 cc_extract.py capture.pcap
    python3 cc_extract.py capture.pcap --full              # numéros non masqués
    python3 cc_extract.py capture.pcap -o resultats.txt
    python3 cc_extract.py capture.pcap --json -o out.json
"""
import argparse
import json
import re
import struct
import sys
from datetime import datetime, timezone

VERSION = "cc_extract 2.0"

# ==================================================================
# Lecteur pcap / pcapng minimal
# ==================================================================
def iter_pcap_packets(path):
    """Yield (linktype, timestamp_float, raw_packet_bytes) pour chaque paquet."""
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < 24:
        return

    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, nano = "<", False
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, nano = ">", False
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, nano = "<", True
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, nano = ">", True
    elif magic == b"\x0a\x0d\x0d\x0a":
        yield from iter_pcapng_packets(data)
        return
    else:
        raise ValueError("Format de fichier non reconnu (ni pcap classique, ni pcapng)")

    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        sec, frac, incl_len, orig_len = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl_len]
        off += incl_len
        ts = sec + (frac / 1_000_000_000 if nano else frac / 1_000_000)
        yield linktype, ts, pkt


def iter_pcapng_packets(data):
    """Support minimal pcapng : Interface Description Block + Enhanced Packet Block."""
    off = 0
    linktype = 1
    ts_resol = 1_000_000  # microsecondes par défaut (if_tsresol absent)
    while off + 8 <= len(data):
        block_type, block_len = struct.unpack("<II", data[off:off + 8])
        if block_len < 12 or off + block_len > len(data):
            break
        body = data[off + 8: off + block_len - 4]
        if block_type == 0x00000001:  # Interface Description Block
            if len(body) >= 4:
                linktype = struct.unpack("<H", body[0:2])[0]
        elif block_type == 0x00000006:  # Enhanced Packet Block
            if len(body) >= 20:
                ts_high, ts_low = struct.unpack("<II", body[4:12])
                cap_len = struct.unpack("<I", body[12:16])[0]
                pkt = body[20:20 + cap_len]
                ts = ((ts_high << 32) | ts_low) / ts_resol
                yield linktype, ts, pkt
        off += block_len


# ==================================================================
# Décodage Ethernet -> IPv4 -> TCP/UDP
# ==================================================================
class Segment:
    __slots__ = ("ts", "src", "sport", "dst", "dport", "proto", "seq", "payload")

    def __init__(self, ts, src, sport, dst, dport, proto, seq, payload):
        self.ts, self.src, self.sport = ts, src, sport
        self.dst, self.dport, self.proto = dst, dport, proto
        self.seq, self.payload = seq, payload


LINKTYPE_ETHERNET = 1
LINKTYPE_NULL = 0        # loopback BSD (DLT_NULL)
LINKTYPE_LOOP = 108      # loopback OpenBSD (DLT_LOOP)
LINKTYPE_LINUX_SLL = 113   # capture "linux cooked" (tcpdump -i any)
LINKTYPE_LINUX_SLL2 = 276  # variante SLL2 (tcpdump récent -i any)

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_VLAN = 0x8100     # 802.1Q
ETHERTYPE_VLAN_QINQ = 0x88A8  # 802.1ad (double tag)


def unwrap_to_ipv4(linktype, pkt):
    """Déballe l'en-tête de lien (Ethernet+VLAN, SLL, SLL2, loopback) et renvoie
    les octets du paquet IPv4, ou None si ce n'est pas de l'IPv4 / format non géré."""

    if linktype == LINKTYPE_ETHERNET:
        if len(pkt) < 14:
            return None
        ethertype = struct.unpack("!H", pkt[12:14])[0]
        off = 14
        # VLAN simple ou empilé (QinQ) : chaque tag ajoute 4 octets avant l'ethertype réel
        while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_VLAN_QINQ):
            if len(pkt) < off + 4:
                return None
            ethertype = struct.unpack("!H", pkt[off + 2:off + 4])[0]
            off += 4
        if ethertype != ETHERTYPE_IPV4:
            return None
        return pkt[off:]

    elif linktype in (LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2):
        if linktype == LINKTYPE_LINUX_SLL:
            if len(pkt) < 16:
                return None
            ethertype = struct.unpack("!H", pkt[14:16])[0]
            off = 16
        else:  # SLL2
            if len(pkt) < 20:
                return None
            ethertype = struct.unpack("!H", pkt[0:2])[0]
            off = 20
        # un paquet "linux cooked" peut lui-même contenir un tag VLAN
        while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_VLAN_QINQ):
            if len(pkt) < off + 4:
                return None
            ethertype = struct.unpack("!H", pkt[off + 2:off + 4])[0]
            off += 4
        if ethertype != ETHERTYPE_IPV4:
            return None
        return pkt[off:]

    elif linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        if len(pkt) < 4:
            return None
        family = struct.unpack("<I", pkt[0:4])[0]  # souvent AF_INET=2, mais varie selon l'OS
        if family not in (2, 0x00000002, 0x02000000):  # host order / swapped selon la plateforme
            # DLT_NULL encode la famille dans l'ordre natif de la machine qui a capturé ;
            # on tente quand même IPv4 par défaut plutôt que d'abandonner.
            pass
        return pkt[4:]

    return None


def decode_segment(linktype, ts, pkt):
    ip = unwrap_to_ipv4(linktype, pkt)
    if ip is None or len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if len(ip) < ihl:
        return None
    proto = ip[9]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])

    if proto == 6:
        tcp = ip[ihl:]
        if len(tcp) < 20:
            return None
        sport, dport = struct.unpack("!HH", tcp[0:4])
        seq = struct.unpack("!I", tcp[4:8])[0]
        data_off = (tcp[12] >> 4) * 4
        payload = tcp[data_off:]
        return Segment(ts, src, sport, dst, dport, "TCP", seq, payload)
    elif proto == 17:
        udp = ip[ihl:]
        if len(udp) < 8:
            return None
        sport, dport = struct.unpack("!HH", udp[0:4])
        payload = udp[8:]
        return Segment(ts, src, sport, dst, dport, "UDP", None, payload)
    return None


def reassemble_tcp(segments):
    """Regroupe les segments TCP par sens de flux et les remet dans l'ordre (par seq)."""
    flows = {}
    for s in segments:
        if s.proto != "TCP" or not s.payload:
            continue
        key = (s.src, s.sport, s.dst, s.dport)
        flows.setdefault(key, []).append(s)

    reassembled = []  # (first_ts, src, sport, dst, dport, stream_bytes)
    for key, segs in flows.items():
        segs.sort(key=lambda s: s.seq)
        chunks, last_end = [], None
        for s in segs:
            if last_end is not None and s.seq < last_end:
                continue  # retransmission / recouvrement : on saute
            chunks.append(s.payload)
            last_end = s.seq + len(s.payload)
        stream = b"".join(chunks)
        src, sport, dst, dport = key
        reassembled.append((segs[0].ts, src, sport, dst, dport, stream))
    return reassembled


# ==================================================================
# Regex par réseau de carte + Luhn
# ==================================================================
CARD_PATTERNS = {
    "VISA":       re.compile(rb"4[0-9]{12}(?:[0-9]{3})?"),
    "MASTERCARD": re.compile(rb"5[1-5][0-9]{14}|2(?:2[2-9][0-9]{2}|[3-6][0-9]{3}|7[01][0-9]{2}|720)[0-9]{10}"),
    "AMEX":       re.compile(rb"3[47][0-9]{13}"),
    "DISCOVER":   re.compile(rb"6(?:011|5[0-9]{2})[0-9]{12}"),
}
SEPARATED = re.compile(rb"(?:\d[ -]?){12,19}")

# Date d'expiration et CVV : on exige un label à proximité pour éviter les faux positifs
# (un "12/27" ou un "123" isolé ne veut rien dire en soi).
EXPIRY_RE = re.compile(
    rb'(?:exp(?:iry|dat[ey]|ir(?:e|ation))?|valid[_ ]?thru)["\']?\s*[:=]\s*["\']?'
    rb'(\d{1,2}\s*[/\-]\s*\d{2,4})',
    re.IGNORECASE,
)
CVV_RE = re.compile(
    rb'(?:cvv2?|cvc2?|card[_ ]?code|security[_ ]?code)["\']?\s*[:=]\s*["\']?(\d{3,4})\b',
    re.IGNORECASE,
)
CONTEXT_WINDOW = 60  # caractères avant/après le numéro de carte à inspecter


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number]
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def guess_brand(number: str) -> str:
    if number.startswith("4"):
        return "VISA"
    if number[:2].isdigit() and 51 <= int(number[:2]) <= 55:
        return "MASTERCARD"
    if number[:2] in {"34", "37"}:
        return "AMEX"
    if number.startswith("6011") or number[:2] == "65":
        return "DISCOVER"
    return "INCONNU"


def find_expiry_cvv(payload: bytes, span):
    """Cherche date d'expiration et CVV labellisés dans une fenêtre autour du numéro."""
    start = max(0, span[0] - CONTEXT_WINDOW)
    end = min(len(payload), span[1] + CONTEXT_WINDOW)
    window = payload[start:end]

    expiry = None
    m = EXPIRY_RE.search(window)
    if m:
        expiry = re.sub(rb"\s+", b"", m.group(1)).decode("latin-1")

    cvv = None
    m = CVV_RE.search(window)
    if m:
        cvv = m.group(1).decode("latin-1")

    return expiry, cvv


def find_cards_in_payload(payload: bytes):
    """Retourne une liste de (brand, number, span, expiry, cvv)."""
    found = []
    seen_spans = set()

    for brand, pattern in CARD_PATTERNS.items():
        for m in pattern.finditer(payload):
            span = m.span()
            if span in seen_spans:
                continue
            number = m.group().decode("latin-1")
            if luhn_valid(number):
                seen_spans.add(span)
                expiry, cvv = find_expiry_cvv(payload, span)
                found.append((brand, number, span, expiry, cvv))

    for m in SEPARATED.finditer(payload):
        raw = m.group().decode("latin-1")
        digits_only = re.sub(r"\D", "", raw)
        if 13 <= len(digits_only) <= 19 and luhn_valid(digits_only):
            if not any(digits_only == num for _, num, *_ in found):
                span = m.span()
                expiry, cvv = find_expiry_cvv(payload, span)
                found.append((guess_brand(digits_only), digits_only, span, expiry, cvv))

    return found


def mask(number: str) -> str:
    if len(number) <= 8:
        return number
    return number[:6] + "*" * (len(number) - 10) + number[-4:]


def group_digits(number: str) -> str:
    """Formate '4111111111111111' -> '4111 1111 1111 1111' pour la lisibilité."""
    return " ".join(number[i:i + 4] for i in range(0, len(number), 4))


# ==================================================================
# Collecte des résultats
# ==================================================================
def scan_pcap(path):
    """Retourne une liste de dicts triés par horodatage, dédupliqués par numéro."""
    segments = []
    for linktype, ts, pkt in iter_pcap_packets(path):
        seg = decode_segment(linktype, ts, pkt)
        if seg is not None:
            segments.append(seg)

    results = {}  # number -> dict (le premier trouvé l'emporte, complété si exp/cvv manquants)

    def record(number, brand, ts, src, sport, dst, dport, reassembled, expiry, cvv):
        if number not in results:
            results[number] = {
                "brand": brand,
                "number": number,
                "timestamp": ts,
                "src": src, "sport": sport,
                "dst": dst, "dport": dport,
                "reassembled": reassembled,
                "expiry": expiry,
                "cvv": cvv,
            }
        else:
            # complète avec exp/cvv si une autre occurrence du même numéro les a trouvés
            r = results[number]
            if not r["expiry"] and expiry:
                r["expiry"] = expiry
            if not r["cvv"] and cvv:
                r["cvv"] = cvv

    # 1) scan paquet par paquet (TCP + UDP)
    for s in segments:
        if not s.payload:
            continue
        for brand, number, span, expiry, cvv in find_cards_in_payload(s.payload):
            record(number, brand, s.ts, s.src, s.sport, s.dst, s.dport, False, expiry, cvv)

    # 2) scan des flux TCP reassemblés (capte les numéros coupés entre paquets)
    for ts, src, sport, dst, dport, stream in reassemble_tcp(segments):
        for brand, number, span, expiry, cvv in find_cards_in_payload(stream):
            record(number, brand, ts, src, sport, dst, dport, True, expiry, cvv)

    return sorted(results.values(), key=lambda r: r["timestamp"])


# ==================================================================
# Affichage
# ==================================================================
def fmt_time(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")


def print_table(results, full, use_color):
    def c(text, code):
        return f"\x1b[{code}m{text}\x1b[0m" if use_color else text

    if not results:
        print(c("Aucune carte bancaire trouvée dans ce pcap.", "33"))
        return

    headers = ["HEURE", "RÉSEAU", "NUMÉRO", "EXP", "CVV", "FLUX", "SRC -> DST"]
    rows = []
    for r in results:
        shown = r["number"] if full else mask(r["number"])
        shown = group_digits(shown)
        exp_str = r["expiry"] or "-"
        cvv_str = (r["cvv"] or "-") if full else ("***" if r["cvv"] else "-")
        flux = "TCP (reassemblé)" if r["reassembled"] else "paquet unique"
        src_str = f'{r["src"]}:{r["sport"]} -> {r["dst"]}:{r["dport"]}'
        rows.append([fmt_time(r["timestamp"]), r["brand"], shown, exp_str, cvv_str, flux, src_str])

    widths = [max(len(h), *(len(row[i]) for row in rows)) for i, h in enumerate(headers)]
    sep = "  "

    def line(cells, bold=False):
        parts = [cells[i].ljust(widths[i]) for i in range(len(cells))]
        text = sep.join(parts)
        return c(text, "1") if bold else text

    print(line(headers, bold=True))
    print(c("-" * (sum(widths) + len(sep) * (len(headers) - 1)), "90"))
    for row in rows:
        print(line(row))

    print()
    msg = f"{len(results)} carte(s) trouvée(s)."
    print(c(msg, "32") if use_color else msg)


def write_text_file(results, path, full):
    lines = []
    for r in results:
        shown = r["number"] if full else mask(r["number"])
        exp_str = r["expiry"] or "?"
        cvv_str = (r["cvv"] or "?") if full else ("***" if r["cvv"] else "?")
        lines.append(
            f'[{fmt_time(r["timestamp"])}] [{r["brand"]}] {group_digits(shown)}  '
            f'EXP={exp_str} CVV={cvv_str}  '
            f'({r["src"]}:{r["sport"]} -> {r["dst"]}:{r["dport"]})'
            f'{"  [reassemblé TCP]" if r["reassembled"] else ""}'
        )
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


def results_to_json(results, full):
    out = []
    for r in results:
        out.append({
            "brand": r["brand"],
            "number": r["number"] if full else mask(r["number"]),
            "expiry": r["expiry"],
            "cvv": (r["cvv"] if full else ("***" if r["cvv"] else None)),
            "timestamp_utc": datetime.fromtimestamp(r["timestamp"], tz=timezone.utc).isoformat(),
            "src": f'{r["src"]}:{r["sport"]}',
            "dst": f'{r["dst"]}:{r["dport"]}',
            "reassembled_tcp": r["reassembled"],
        })
    return out


# ==================================================================
# Main
# ==================================================================
def main():
    ap = argparse.ArgumentParser(description=VERSION)
    ap.add_argument("pcap", help="Fichier .pcap ou .pcapng à analyser")
    ap.add_argument("-o", dest="outfile", help="Fichier de sortie (texte, ou JSON avec --json)")
    ap.add_argument("--full", dest="full", action="store_true", help="Affiche les numéros complets (sinon masqués)")
    ap.add_argument("--json", dest="as_json", action="store_true", help="Sortie au format JSON")
    ap.add_argument("--no-color", dest="no_color", action="store_true", help="Désactive la couleur dans le terminal")
    args = ap.parse_args()

    try:
        results = scan_pcap(args.pcap)
    except (FileNotFoundError, ValueError) as e:
        print(f"Erreur : {e}", file=sys.stderr)
        sys.exit(1)

    if args.as_json:
        payload = results_to_json(results, args.full)
        if args.outfile:
            with open(args.outfile, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            print(f"{len(results)} carte(s) écrite(s) dans {args.outfile}")
        else:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    use_color = (not args.no_color) and sys.stdout.isatty()
    print_table(results, args.full, use_color)

    if args.outfile:
        write_text_file(results, args.outfile, args.full)
        print(f"\nRésultats écrits dans {args.outfile}")


if __name__ == "__main__":
    main()
