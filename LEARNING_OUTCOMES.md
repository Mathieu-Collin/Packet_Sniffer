# Compétences et apprentissages — Packet Sniffer

##  Objectif du projet
Ce projet a été réalisé dans le cadre de mon portfolio en **cybersécurité**.  
L’objectif principal était de concevoir un **analyseur de paquets réseau (packet sniffer)** en Python, capable de capturer, décoder et afficher les trames réseau brutes en temps réel.

Ce développement m’a permis de renforcer ma compréhension du fonctionnement des **réseaux bas-niveau**, des **protocoles de communication**, et des **mécanismes de sécurité** associés à la capture de trafic.

---

##  Compétences techniques développées

###  Réseaux et protocoles
- Compréhension détaillée de la **pile TCP/IP** et de ses couches (Ethernet, IP, ICMP, TCP, UDP).
- Décodage manuel des **en-têtes réseau** à partir de données binaires.
- Analyse du contenu des trames : adresses MAC, IP, ports, flags TCP, checksum, payloads, etc.
- Utilisation de **sockets brutes (raw sockets)** pour intercepter des paquets au niveau le plus bas du modèle OSI.

###  Programmation bas-niveau en Python
- Manipulation de **données binaires** et de **structures de paquets** à l’aide du module `struct`.
- Gestion de la **conversion endianness** (big/little endian).
- Construction d’un outil CLI complet avec **arguments dynamiques** (`argparse`).
- Utilisation de **Colorama** pour un affichage enrichi et ergonomique en console.
- Export des résultats vers des formats **JSON** et **texte** pour exploitation ou archivage.

###  Cybersécurité & éthique
- Mise en œuvre d’un outil de capture réseau dans le respect des **principes légaux et éthiques**.
- Compréhension des risques liés à l’**écoute du trafic (sniffing)** et à l’usage des raw sockets.
- Sensibilisation aux notions de **confidentialité des données**, **traçabilité** et **responsabilité de l’opérateur**.
- Ajout d’un avertissement clair sur l’usage autorisé (périmètre légal du pentesting).

###  Systèmes d’exploitation & privilèges
- Étude du comportement des sockets brutes sur différents OS (Windows, Linux, macOS).
- Gestion des **privilèges administrateur/root** nécessaires à la capture réseau.
- Tests de compatibilité et d’adaptation du code aux environnements systèmes.

###  Structuration logicielle & maintenance
- Organisation d’un projet Python complet avec `requirements.txt`, `.gitignore` et scripts de build (`build_exe.py`).
- Documentation claire du code et du fonctionnement dans le `README.md`.
- Conception d’un outil modulaire et extensible, prêt à intégrer des fonctions futures (ex. export PCAP, interface graphique, analyse statistique).

---

##  Outils et technologies utilisés
| Domaine | Outils / Librairies |
|----------|--------------------|
| Langage | Python 3 |
| Réseau | `socket`, `struct` |
| Interface CLI | `argparse`, `colorama` |
| Export | JSON, TXT |
| Packaging | `build_exe.py` |
| OS ciblés | Windows / Linux / macOS |

---

##  Difficultés rencontrées et solutions apportées
- **Problème :** privilèges root nécessaires sur certains OS.  
  **Solution :** documentation claire + détection d’OS pour alerter l’utilisateur.

- **Problème :** affichage non lisible des paquets bruts.  
  **Solution :** mise en forme colorée et décodage structuré des couches protocolaires.

- **Problème :** compatibilité multi-OS des sockets brutes.  
  **Solution :** ajout de conditions spécifiques et modularisation possible pour futurs backends (pcapy/scapy).

---

##  Perspectives d’amélioration
- Support de **libpcap / scapy** pour une capture plus performante et portable.
- Ajout d’un **mode graphique** (interface Tkinter ou web) pour visualiser les paquets en temps réel.
- Intégration d’un **export au format PCAP** compatible Wireshark.
- Développement d’un **mode d’analyse automatisée** pour la détection d’anomalies ou d’activités suspectes.

---

##  Bilan personnel
Ce projet m’a permis de :
- M’approprier le **fonctionnement interne des protocoles réseau**.
- Renforcer mes compétences en **Python système** et en **programmation bas-niveau**.
- Approfondir ma **culture sécurité** (éthique, légalité, exploitation maîtrisée des outils réseau).
- Développer une approche rigoureuse et documentée, essentielle en **cybersécurité**.

---
