# cc_extract

Outil autonome en Python 3 (zéro dépendance) qui extrait les numéros de
carte bancaire présents en clair dans un fichier `.pcap` / `.pcapng`.

Contrairement à PCredz (dont le module de détection CC a disparu du code
dans les versions récentes malgré le flag `-c`), ce script réimplémente
uniquement cette brique, en allant plus loin sur la fiabilité :

1. Lecteur pcap/pcapng écrit à la main (pas de `pcapy`, `scapy` ou `dpkt`
   à installer).
2. Reconstruction du payload applicatif : Ethernet (avec VLAN 802.1Q et
   QinQ empilé), capture "Linux cooked" (SLL / SLL2, le format par
   défaut de `tcpdump -i any`), ou loopback (DLT_NULL) -> IPv4 ->
   TCP/UDP.
3. **Reassemblage des flux TCP** (par numéro de séquence) : un numéro de
   carte coupé entre deux paquets est quand même détecté, en plus du
   scan paquet par paquet.
4. Regex par préfixe de réseau (Visa, Mastercard, Amex, Discover) + une
   regex générique pour les numéros avec espaces/tirets.
5. Validation **Luhn** systématique pour éliminer les faux positifs
   (suites de chiffres qui matchent le pattern mais ne sont pas un vrai
   numéro de carte).
6. Détection de la **date d'expiration** et du **CVV** s'ils sont
   labellisés (`exp=`, `expiry`, `cvv`, `cvc`, etc.) à proximité du
   numéro dans le même paquet/flux — pas de détection "à l'aveugle"
   pour éviter les faux positifs.

## Usage

```bash
# Tableau clair : heure, réseau, numéro (masqué), origine du match, IP:port
python3 cc_extract.py capture.pcap

# Numéros complets (non masqués)
python3 cc_extract.py capture.pcap --full

# Export texte
python3 cc_extract.py capture.pcap -o resultats.txt

# Export JSON (pour scripts / CI / intégration dans un autre outil)
python3 cc_extract.py capture.pcap --json -o resultats.json
```

### Exemple de sortie

```
HEURE     RÉSEAU      NUMÉRO               EXP    CVV  FLUX              SRC -> DST
---------------------------------------------------------------------------------------------------
18:07:13  VISA        4111 11** **** 1111  12/27  ***  paquet unique     10.10.14.55:49326 -> 10.10.10.21:80
18:38:45  VISA        4111 1111 1111 1111  -      -    TCP (reassemblé)  10.10.14.55:51000 -> 10.10.10.99:7777

2 carte(s) trouvée(s).
```

Le CVV est masqué (`***`) par défaut comme le numéro — utilisez `--full`
pour tout afficher en clair. `-` signifie qu'aucune date/CVV labellisé
n'a été trouvé à proximité du numéro.

La colonne `FLUX` indique si la carte a été vue dans un seul paquet ou
reconstituée à partir de plusieurs segments TCP — utile pour savoir si
l'info aurait échappé à un outil qui ne scanne que paquet par paquet.

## Structure du repo

```
cc_extract/
├── cc_extract.py              # l'outil (seul fichier nécessaire pour l'utiliser)
├── demo.pcap                  # pcap d'exemple : Ethernet, VLAN, SLL, reassemblage TCP
├── LICENSE                    # MIT
└── README.md
```

## Limites connues

- Encapsulations gérées : Ethernet (+ VLAN 802.1Q/QinQ), SLL/SLL2
  (Linux cooked), loopback (DLT_NULL/DLT_LOOP), en pcap classique et
  pcapng (Interface Description Block + Enhanced Packet Block).
  Pas encore de support IPv6 ni de fragmentation IP.
- Le reassemblage TCP est volontairement simple (tri par numéro de
  séquence, retransmissions ignorées) : suffisant pour l'analyse
  forensique post-capture, mais ce n'est pas un moteur de reassemblage
  complet type Wireshark (pas de gestion des fenêtres TCP, des paquets
  hors-ordre extrêmes, etc.).
- La validation Luhn élimine la majorité des faux positifs mais pas
  tous (un numéro aléatoire de 16 chiffres a ~10% de chance de passer
  Luhn par hasard).
