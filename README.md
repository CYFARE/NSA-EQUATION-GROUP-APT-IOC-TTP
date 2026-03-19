# Equation Group APT: IoC's & TTP's | CYFARE.NET

- **Report By**: CYFARE.NET
- **Site**: https://cyfare.net/
- **Telegram**: https://t.me/CYFARELABS
- **X/Twitter**: https://t.me/CYFARELABS
- **Mappings**: https://t.me/TACMAPS
- **GitHub**: https://github.com/CYFARE

## Equation Group?

**The Equation Group represents the most technically sophisticated cyber-espionage operation ever publicly documented.** Exposed by Kaspersky Lab in February 2015 and further revealed through the Shadow Brokers leaks beginning in August 2016, this threat actor — widely attributed to the **United States of America - NSA's Tailored Access Operations (TAO)** unit — deployed an arsenal of malware platforms capable of reprogramming hard drive firmware, bridging air-gapped networks via USB, and persisting through OS reinstallation. Active since at least 2001 (with C2 domain registrations dating to 1996), the group operated **300+ C2 domains across 100+ servers** in 10+ countries and targeted victims in over 30 nations, with a focus on Iran, Russia, Pakistan, Afghanistan, and other strategic targets. This report compiles all publicly documented IOCs across malware hashes, C2 infrastructure, registry artifacts, exploitation techniques, detection signatures, and the Shadow Brokers tool dump.

## Countries Affected

Confirmed infections across 42+ countries │ 500+ documented victims. Actual number estimated in the tens of thousands (self-destruct protocol)

```
├── MIDDLE EAST & NORTH AFRICA
│   ├── Iran ★ ──────────────── [Highest infection count globally]
│   ├── Syria ★ ─────────────── [Top-tier target]
│   ├── Yemen
│   ├── Lebanon
│   ├── United Arab Emirates
│   ├── Algeria
│   ├── Libya
│   ├── Palestine
│   ├── Egypt
│   └── Qatar
│
├── SOUTH & CENTRAL ASIA
│   ├── Afghanistan ★ ───────── [Top-tier target]
│   ├── Pakistan ★ ──────────── [Top-tier target; Fanny worm]
│   ├── India ★ ─────────────── [Top-tier target]
│   ├── Bangladesh
│   └── Kazakhstan
│
├── EAST & SOUTHEAST ASIA
│   ├── China ───────────────── [NPU attack 2022; Bvp47 targets]
│   ├── Hong Kong
│   ├── Japan ───────────────── [Jump server infrastructure]
│   ├── South Korea ─────────── [Jump server infrastructure]
│   ├── Indonesia ───────────── [Fanny worm]
│   ├── Vietnam ─────────────── [Fanny worm]
│   ├── Malaysia
│   ├── Philippines
│   └── Thailand
│
├── EUROPE
│   ├── United Kingdom ──────── [Also hosted C&C servers]
│   ├── Germany ─────────────── [Bvp47 targets; Merkel surveillance]
│   ├── France
│   ├── Switzerland
│   ├── Italy ───────────────── [C&C server host]
│   ├── Netherlands ─────────── [C&C server host]
│   ├── Spain ───────────────── [Bvp47 targets]
│   ├── Sweden ──────────────── [Jump server infrastructure]
│   ├── Poland ──────────────── [Jump server infrastructure]
│   ├── Ukraine
│   ├── Czech Republic ──────── [C&C server host]
│   ├── Romania
│   └── Belgium
│
├── AFRICA (SUB-SAHARAN)
│   ├── Mali ★ ──────────────── [Top-tier target]
│   ├── Kenya
│   ├── Nigeria
│   ├── Somalia
│   └── South Africa
│
├── AMERICAS
│   ├── United States ───────── [C&C infrastructure; some domestic targets]
│   ├── Mexico
│   ├── Colombia ────────────── [C&C server host]
│   ├── Brazil
│   ├── Ecuador
│   ├── Panama ──────────────── [C&C server host]
│   └── Costa Rica ──────────── [C&C server host]
│
└── TARGETED SECTORS (across all regions)
    ├── Government & diplomatic institutions
    ├── Telecommunications
    ├── Aerospace & defense
    ├── Energy & oil/gas
    ├── Nuclear research
    ├── Military
    ├── Nanotechnology
    ├── Financial institutions
    ├── Mass media
    ├── Transportation
    ├── Islamic activists & scholars
    └── Cryptographic technology companies

─── KEY MALWARE PLATFORMS ────────────────────
│ EQUATIONLASER  (2001–2004)  │ Early implant, Win95/98      │
│ EQUATIONDRUG   (2003–2013)  │ Modular attack platform      │
│ DOUBLEFANTASY  (2004+)      │ Validator/backdoor           │
│ TRIPLEFANTASY  (2012+)      │ Upgraded validator           │
│ FANNY          (2008+)      │ USB worm, air-gap bridging   │
│ GRAYFISH       (2008+)      │ Most advanced; firmware mod  │
│ BVP47          (2013+)      │ Linux backdoor, 45 countries │
│ NOPEN          (TAO tool)   │ Remote access trojan         │

```
---

## 1. Malware families and their known file hashes

The Equation Group deployed a layered malware ecosystem with distinct platforms for different operational phases. Each family served a specific role in a multi-stage infection chain: **DoubleFantasy** validates target value, then deploys either **EquationDrug** (legacy systems) or **GrayFish** (modern Windows), with specialized tools like **Fanny** for air-gap bridging and **GROK** for keystroke capture.

### EquationLaser (earliest implant, 2001–2004)

| Hash Type | Value |
|-----------|-------|
| MD5 | `752af597e6d9fd70396accc0b9013dbe` |
| SHA1 | `5e1f56c1e57fbff96d4999db1fd6dd0f7d8221df` |

Windows 95/98-compatible implant. Compiled October 18, 2004. Predecessor to the full EquationDrug platform. File artifact: `lsasrv32.dll`.

### DoubleFantasy (validator trojan, 2004–2015+)

| Hash Type | Value | Notes |
|-----------|-------|-------|
| MD5 | `2a12630ff976ba0994143ca93fecd17f` | Installer, compiled April 30, 2010 |
| MD5 | `03718676311de33dd0b8f4f18cffd488` | `_SD_IP_CF.dll` installer + LNK exploit, compiled Feb 13, 2009 |
| SHA1 | `d09b4b6d3244ac382049736ca98d7de0c6787fa2` | Primary detection hash |
| SHA256 | `a2a9e948fb829685d0a9161cac845fd0dfa943d023a6b2faab205fa8664b7c26` | Associated with C2 `moretimeads[.]com` |

First-stage reconnaissance trojan that confirms the target is of interest before deploying advanced platforms. Internal versioning spans **8.x through 13.x**. Stores configuration in Base64+RC6 encrypted registry values. Injects into Internet Explorer process.

### EquationDrug / EQUESTRE (main espionage platform, 2003–2013)

| Hash Type | Value |
|-----------|-------|
| MD5 | `4556ce5eb007af1de5bd3b457f0b216d` |
| SHA1 | `61fab1b8451275c7fd580895d9c68e152ff46417` |

Modular espionage platform with **35+ plugins and 18 kernel-mode drivers**. Plugin architecture uses ID system (IDs starting with 0x80). Stores exfiltrated data as encrypted `*.FON` files in `Windows\Fonts\`. The HDD firmware reprogramming plugin carries ID **0x80AA**. Internal codename: **LUTEUSOBSTOS**.

### GrayFish (most sophisticated platform, 2008–2015+)

| Hash Type | Value |
|-----------|-------|
| MD5 | `9b1ca66aab784dc5f1dfe635d8f8a904` |
| SHA1 | `58d15d1581f32f36542f3e9fb4b1fc84d2a6ba35` |

**Entirely registry-resident** — no malicious files on disk. Uses a VBR bootkit to hijack the OS boot sequence through 4–5 decryption layers. Computes **SHA-256 hash of the NTFS Object_ID 1,000 times** to derive a machine-bound AES decryption key. Self-destructs completely if any decryption stage fails, confounding forensic analysis. Installer binary: `DOGROUND.exe`. Exploits `ElbyCDIO.sys` (CloneCD driver) for kernel code execution.

### Fanny worm (USB propagation, compiled July 2008)

| Hash Type | Value |
|-----------|-------|
| MD5 | `0a209ac0de4ac033f31d6ba9191a8f7a` |
| SHA1 | `1f0ae54ac3f10d533013f74f48849de4e65817a7` |

USB-propagating worm designed for **air-gap bridging**. Creates a hidden **1MB FAT16/FAT32 storage area** on USB drives using undocumented filesystem flags. Exploited CVE-2010-2568 (LNK vulnerability) and MS09-025 (kernel privilege escalation) — both zero-days later reused by Stuxnet. C2: `webuysupplystore.mooo[.]com`. Approximately **11,000 victims** detected, concentrated in Pakistan (~60%).

### TripleFantasy (advanced validator)

| Hash Type | Value | Notes |
|-----------|-------|-------|
| MD5 | `9180d5affe1e5df0717d7385e7f54386` | Loader DLL (17,920 bytes) |
| MD5 | `ba39212c5b58b97bfc9f5bc431170827` | Encrypted payload (.DAT) |
| SHA1 | `b2b2cd9ca6f5864ef2ac6382b7b6374a9fb2cbe9` | Primary detection hash |

### GROK keylogger

| Hash Type | Value |
|-----------|-------|
| MD5 | `24a6ec8ebf9c0867ed1c097f4a653b8d` |
| SHA1 | `50b8f125ed33233a545a1aac3c9d4bb6aa34b48f` |

Described as a "keylogger on steroids." Driver filename: `msrtdv.sys`. Internal name: `standalonegrok_2.1.1.1`. Codename matches NSA Snowden documents and the ANT catalog.

### nls_933w.dll (HDD firmware reprogramming module)

| Hash Type | Value |
|-----------|-------|
| MD5 | `11fb08b9126cdb4668b3f5135cf7a6c5` |
| SHA1 | `ff2b50f371eb26f22eb8a2118e9ab0e015081500` |

Reprograms firmware of **12+ hard drive brands** including Seagate, Western Digital, Toshiba, Samsung, Maxtor, Hitachi, Micron, and IBM. Releases kernel driver `win32m.sys` for direct HDD controller communication. Matched to the NSA ANT catalog program **IRATEMONK**.

### Additional hashes

| Component | Hash Type | Value |
|-----------|-----------|-------|
| EquationDrug network sniffer (tdip.sys) | SHA1 | `7e3cd36875c0e5ccb076eb74855d627ae8d4627f` |
| tdip.sys (Shadow Brokers dump) | SHA256 | `A5EC4D102D802ADA7C5083AF53FD9D3C9B5AA83BE9DE58DBB4FAC7876FAF6D29` |
| EoP package ("Houston" exploit disk) | MD5 | `6fe6c03b938580ebf9b82f3b9cd4c4aa` |
| EoP package | SHA1 | `2bd1b1f5b4384ce802d5d32d8c8fd3d1dc04b962` |
| Shadow Brokers free file archive | SHA256 | `b5961eee7cb3eca209b92436ed7bdd74e025bf615b90c408829156d128c7a169` |
| Shadow Brokers auction file | SHA256 | `af1dabd8eceec79409742cc9d9a20b9651058bbb8d2ce60a0edcfa568d91dbea` |

---

## 2. Command and control infrastructure spans 300+ domains

The Equation Group registered **300+ C2 domains** through privacy-protected registrars, hosted across **100+ servers** in the US, UK, Italy, Germany, Netherlands, Panama, Costa Rica, Malaysia, Colombia, and Czech Republic. Kaspersky Lab sinkholed approximately 24 of these domains during their investigation. Mac OS X callbacks and evidence of iPhone targeting were observed from sinkholed infrastructure.

### DoubleFantasy C2 domains
`advancing-technology[.]com` · `avidnewssource[.]com` · `businessdealsblog[.]com` · `businessedgeadvance[.]com` · `charging-technology[.]com` · `computertechanalysis[.]com` · `config.getmyip[.]com` *(sinkholed)* · `globalnetworkanalys[.]com` · `melding-technology[.]com` · `myhousetechnews[.]com` *(sinkholed)* · `newsterminalvelocity[.]com` *(sinkholed)* · `selective-business[.]com` · `slayinglance[.]com` · `successful-marketing-now[.]com` *(sinkholed)* · `taking-technology[.]com` · `techasiamusicsvr[.]com` *(sinkholed)* · `technicaldigitalreporting[.]com` · `timelywebsitehostesses[.]com` · `www.dt1blog[.]com` · `www.forboringbusinesses[.]com`

### EquationDrug C2 domains
`newjunk4u[.]com` · `easyadvertonline[.]com` · `newip427.changeip[.]net` *(sinkholed)* · `ad-servicestats[.]net` *(sinkholed)* · `subad-server[.]com` *(sinkholed)* · `ad-noise[.]net` · `ad-void[.]com` · `aynachatsrv[.]com` · `damavandkuh[.]com` · `fnlpic[.]com` · `monster-ads[.]net` · `nowruzbakher[.]com` · `sherkhundi[.]com` · `quik-serv[.]com` · `nickleplatedads[.]com` · `arabtechmessenger[.]net` · `amazinggreentechshop[.]com` · `foroushi[.]net` · `technicserv[.]com` · `goldadpremium[.]com` · `honarkhaneh[.]net` · `parskabab[.]com` · `technicupdate[.]com` · `technicads[.]com` · `customerscreensavers[.]com` · `darakhit[.]com` · `ghalibaft[.]com` · `adservicestats[.]com` · `247adbiz[.]net` *(sinkholed)* · `webbizwild[.]com` · `roshanavar[.]com` · `afkarehroshan[.]com` · `thesuperdeliciousnews[.]com` · `adsbizsimple[.]com` · `goodbizez[.]com` · `meevehdar[.]com` · `xlivehost[.]com` · `downloadmpplayer[.]com` · `honarkhabar[.]com` · `techsupportpwr[.]com` · `zhalehziba[.]com` · `serv-load[.]com` · `wangluoruanjian[.]com` · `islamicmarketing[.]net` · `noticiasftpsrv[.]com` · `coffeehausblog[.]com` · `platads[.]com` · `havakhosh[.]com` · `toofanshadid[.]com` · `bazandegan[.]com` · `sherkatkonandeh[.]com` · `mashinkhabar[.]com` · `quickupdateserv[.]com` · `rapidlyserv[.]com`

### GrayFish C2 domains
`ad-noise[.]net` · `business-made-fun[.]com` · `businessdirectnessource[.]com` · `charmedno1[.]com` · `cribdare2no[.]com` · `dowelsobject[.]com` · `following-technology[.]com` · `forgotten-deals[.]com` · `functional-business[.]com` · `housedman[.]com` · `industry-deals[.]com` · `listennewsnetwork[.]com` · `phoneysoap[.]com` · `posed2shade[.]com` · `quik-serv[.]com` · `rehabretie[.]com` · `speedynewsclips[.]com` · `teatac4bath[.]com` · `unite3tubes[.]com` · `unwashedsound[.]com`

### TripleFantasy C2 domains
`arm2pie[.]com` · `brittlefilet[.]com` · `cigape[.]net` · `crisptic01[.]net` · `fliteilex[.]com` · `itemagic[.]net` · `micraamber[.]net` · `mimicrice[.]com` · `rampagegramar[.]com` · `rubi4edit[.]com` · `rubiccrum[.]com` · `rubriccrumb[.]com` · `team4heat[.]net` · `tropiccritics[.]com`

### EquationLaser C2 domains
`lsassoc[.]com` · `gar-tech[.]com` *(sinkholed)*

### Exploitation/watering-hole servers
`standardsandpraiserepurpose[.]com` · `suddenplot[.]com` · `technicalconsumerreports[.]com` · `technology-revealed[.]com`

### Hardcoded IP addresses from malware configurations

```
41.222.35.70       62.216.152.67      62.216.152.69
64.76.82.52        80.77.4.3          81.31.34.175
81.31.36.174       81.31.38.163       81.31.38.166
84.233.205.37      84.233.205.99      85.112.1.83
87.255.38.2        89.18.177.3        149.12.71.2
190.60.202.4       190.242.96.212     195.128.235.227
195.128.235.231    195.128.235.233    195.128.235.235
195.81.34.67       202.95.84.33       203.150.231.49
203.150.231.73     210.81.52.120      212.61.54.239
```

---

## 3. Registry keys, file paths, and persistence artifacts

### EquationDrug registry artifacts

The EquationDrug platform stores its encrypted configuration under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\MemSubSys` using three named values:

- **`{42E14DD3-F07A-78F1-7659-26AE141569AC-E0B3EE89}`** — RC5-encrypted configuration block (1024-bit key, 24 rounds)
- **`{F4CF0326-6DCD-EEC8-5323-01CEDB66741A-B55F6F12}`** — "SkyhookChow Payload" (path to orchestrator DLL `mscfg32.dll`)
- **`{B6F5CD13-A74D-8B82-A6AA-6FA1BE2484C1-6832DF06}`** — "SkyhookChow Target" (executable host path)

Rootkit persistence via `HKLM\System\CurrentControlSet\Services\%driver_name%` storing protected object lists.

### DoubleFantasy registry artifacts

Configuration stored at `HKLM\Software\Classes\CLSID\{6AF33D21-9BC5-4f65-8654-B8059B822D91}\TypeLib`:
- Value `DigitalProductId` — Base64-encoded, RC6-encrypted config (key: `66 39 71 3C 0F 85 99 81 20 19 35 43 FE 9A 84 11`)
- `...\Version` subkey (Default) — version string (e.g., "008.002.000.003")
- `...\MiscStatus` (Default) — security software detection marker
- Stolen data at `HKLM\SOFTWARE\Classes\CLSID\{77032DAA-B7F2-101B-A1F0-01C29183BCA1}\Containers` with `@WriteHeader` values

Security software detection probes: `HKLM\Software\KasperskyLab\protected\AVP7\...`, `HKLM\Software\KasperskyLab\AVP6\...`, `HKLM\Software\PWI, Inc.`

### Fanny registry artifacts

Module registry at `HKLM\System\CurrentControlSet\Control\MediaResources\acm\ECELP4\` with values `filter2`, `filter3`, `filter8` containing host process + DLL paths. Persistence via `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` appended with `c:\windows\system32\msdtc32.exe`.

### GrayFish registry storage

GrayFish stores its **entire virtual file system encrypted in the Windows registry** — all modules, configuration, and exfiltrated data exist only as encrypted registry values. No malicious files exist on the filesystem. The first-stage loader derives its AES key by computing SHA-256 of the `%Windows%` or `%System%` NTFS Object_ID **1,000 times**, binding decryption to the specific machine.

### Key file paths across all families

| Malware | File Path | Description |
|---------|-----------|-------------|
| EquationDrug | `%SYSTEM%\mscfg32.dll` | Orchestrator DLL |
| EquationDrug | `%SYSTEM%\mscfg32.exe` | Loader process |
| EquationDrug | `Windows\Fonts\*.FON` | Encrypted exfiltration containers |
| EquationDrug | `msndsrv.sys` | Kernel rootkit driver |
| EquationDrug | `tdip.sys` | NDIS network sniffer driver |
| EquationDrug | `nls_933w.dll` | HDD firmware reprogramming module |
| EquationDrug | `win32m.sys` | HDD controller communication driver |
| DoubleFantasy | `%system%\ee.dll` | Main payload |
| Fanny | `%WINDIR%\system32\comhost.dll` | Main worm code |
| Fanny | `c:\windows\system32\msdtc32.exe` | Persistence executable |
| Fanny | `AGENTCPD.DLL` | Fanny component |
| TripleFantasy | `%WINDIR%\System32\ahlhcib.dll` | DLL component |
| TripleFantasy | `%WINDIR%\sjyntmv.dat` | Data file |
| GROK | `msrtdv.sys` | Keylogger driver |
| GrayFish | `DOGROUND.exe` | Installer executable |
| GrayFish | `ElbyCDIO.sys` | Exploited CloneCD driver |
| EquationLaser | `lsasrv32.dll` | Main component |

### Mutexes and unique event names

- **`prkMtx`** — Equation Group exploitation library ("PrivLib")
- **`cnFormSyncExFBC`** and **`cnFormVoidFBC`** — exploitation library mutexes
- **`D0385CB7-B834-45d1-A501-1A1700E6C34E`** — EquationDrug module event
- **`Global\{8c38e4f3-591f-91cf-06a6-67b84d8a0102}`** — TripleFantasy global mutex

---

## 4. CVEs exploited span a decade of zero-days

The Equation Group leveraged at least **4 confirmed zero-day exploits** in their pre-Shadow Brokers operations, with the leaked April 2017 dump revealing **12+ additional vulnerabilities** across SMB, RDP, Kerberos, and IIS attack surfaces.

### Pre-Shadow Brokers exploits (Kaspersky-documented)

| CVE | Target | Usage |
|-----|--------|-------|
| **CVE-2010-2568** | Windows Shell LNK parsing | Used by Fanny worm (2008) — **two years before Stuxnet** |
| **MS09-025** | Windows kernel privilege escalation | Fanny worm local privilege escalation |
| **CVE-2012-0159** (MS12-034) | Windows TrueType font parsing | Remote code execution |
| **CVE-2012-1723** | Java runtime | Browser-based exploitation |
| **CVE-2013-3918** | IE ActiveX (InformationCardSigninHelper) | Web exploitation; originally from Aurora APT, repurposed |
| **CVE-2013-3894** (MS13-081) | Windows TrueType font parsing | Remote code execution |
| Unknown | Firefox 17 / Tor Browser | Targeted Tor users |

### Shadow Brokers April 2017 "Lost in Translation" exploits

| CVE | Tool | Target | MS Bulletin |
|-----|------|--------|-------------|
| **CVE-2017-0143** | EternalRomance, EternalSynergy | SMBv1 type confusion | MS17-010 |
| **CVE-2017-0144** | **EternalBlue** | SMBv1 buffer overflow | MS17-010 |
| **CVE-2017-0145** | EternalRomance | SMBv1 type confusion | MS17-010 |
| **CVE-2017-0146** | EternalChampion, EternalSynergy | SMBv1 race condition | MS17-010 |
| **CVE-2017-0147** | EternalChampion, EternalSynergy | SMBv1 info disclosure | MS17-010 |
| **CVE-2017-0148** | (MS17-010 family) | SMBv1 | MS17-010 |
| **CVE-2017-0005** | EpMe (DanderSpritz LPE) | Windows local privilege escalation | — |
| **CVE-2017-0176** | EsteemAudit | RDP smart card auth | — |
| **CVE-2017-7269** | ExplodingCan | IIS 6.0 WebDAV | — |
| **CVE-2017-8487** | EnglishmanDentist | Outlook/Exchange | — |
| **CVE-2014-6324** | EskimoRoll | Kerberos PAC forging | MS14-068 |

### Shadow Brokers August 2016 firewall exploits

| CVE | Tool | Target |
|-----|------|--------|
| **CVE-2016-6366** | EXTRABACON | Cisco ASA SNMP overflow |
| **CVE-2016-6367** | EPICBANANA | Cisco ASA/PIX CLI buffer overflow |

### Additional exploits from older dumps

| Tool | Target | Bulletin |
|------|--------|----------|
| EmeraldThread | Windows XP/2003 print spooler | MS10-061 |
| EducatedScholar | SMBv2 (Vista/2008) | MS09-050 |
| EclipsedWing | SMB/RPC (multiple Windows) | MS08-067 |
| ErraticGopher | SMBv1 (XP/2003) | Pre-patched |

---

## 5. Unique TTPs define nation-state sophistication

### HDD firmware reprogramming (MITRE T1542.002)

The module `nls_933w.dll` reprograms hard drive firmware across **12+ drive categories** from Seagate, Western Digital, Toshiba, Samsung, Maxtor, Hitachi, Micron, and IBM. This creates both **extreme persistence** (survives disk formatting, OS reinstallation, and standard forensics) and **hidden storage** (invisible sectors accessible only through a secret API). Because hard drive firmware is write-only with no standard read-back mechanism, detection from software is **practically impossible**. F-Secure confirmed this matches the NSA ANT catalog program IRATEMONK. Kaspersky found only a handful of victims targeted with this capability — reserved for highest-value targets.

### USB-based air-gap bridging via Fanny worm

Fanny creates a hidden **1MB FAT16/FAT32 storage area** on USB drives using undocumented filesystem flag combinations that make the container appear as corrupt data to standard OS drivers. The worm includes its own modified FAT driver. The bidirectional C2 flow works as follows: Fanny collects system information from air-gapped machines, stores it in the hidden USB area, exfiltrates when the USB reaches an internet-connected infected host, and returns commands via the same hidden channel. This mechanism enabled mapping of air-gapped network topologies.

### Supply chain interdiction

Participants at a scientific conference in Houston received **trojanized CD-ROMs** containing conference materials plus two zero-day exploits and DoubleFantasy. Kaspersky noted: "We do not believe the conference organizers did this on purpose." Cisco routers were also intercepted in transit for firmware implantation. This aligns with NSA TAO's documented equipment interception operations revealed in the Snowden documents.

### Multi-stage infection chain with environmental keying

The canonical infection flow proceeds: *initial access* (web exploit, USB, supply chain, or SMB exploit) → *validation via DoubleFantasy/TripleFantasy* (confirms target value; uninstalls if not of interest) → *platform deployment* (EquationDrug for legacy Windows, GrayFish for Windows 7+) → *plugin-based collection* (GROK keylogger, HDD firmware module, etc.). GrayFish employs environmental keying by deriving its AES decryption key from the target machine's specific NTFS Object_ID, ensuring payloads only decrypt on intended targets.

### GrayFish bootkit — entirely registry-resident malware

GrayFish hijacks the Volume Boot Record (VBR) to execute **before the Windows kernel loads**. The entire platform lives in encrypted Windows registry values — no malicious files touch the filesystem. Four to five decryption layers cascade during boot; if any layer fails, GrayFish **deletes itself entirely**, destroying all forensic evidence. Kaspersky described it: "After infection, the computer is not run by itself anymore: it is GrayFish that runs it step by step."

---

## 6. MITRE ATT&CK mapping for group G0020

MITRE ATT&CK officially maps four techniques to the Equation Group (G0020), reflecting their conservative evidentiary standard. Analysis of published research reveals many additional applicable techniques.

### Officially mapped techniques

| ID | Technique | Tactic | Usage |
|----|-----------|--------|-------|
| **T1480.001** | Execution Guardrails: Environmental Keying | Defense Evasion | GrayFish uses SHA-256 iterated 1,000x over NTFS Object_ID as AES key; DoubleFantasy validates targets before payload delivery |
| **T1564.005** | Hide Artifacts: Hidden File System | Defense Evasion | GrayFish encrypted VFS in registry; Fanny hidden USB storage; EquationDrug encrypted *.FON containers |
| **T1120** | Peripheral Device Discovery | Discovery | nls_933w.dll queries HDD identifiers to determine manufacturer/model before firmware reprogramming |
| **T1542.002** | Pre-OS Boot: Component Firmware | Persistence, Defense Evasion | HDD firmware reprogramming via nls_933w.dll; matches NSA IRATEMONK |

### Additional techniques demonstrated in documented behavior

| ID | Technique | Evidence |
|----|-----------|----------|
| T1542.003 | Pre-OS Boot: Bootkit | GrayFish VBR bootkit hijacks OS boot |
| T1091 | Replication Through Removable Media | Fanny USB worm propagation |
| T1052.001 | Exfiltration Over Physical Medium: USB | Fanny hidden USB storage for air-gap exfiltration |
| T1195.002 | Supply Chain Compromise | Houston CD-ROM interdiction; Cisco router interception |
| T1203 | Exploitation for Client Execution | Multiple zero-day exploits (LNK, Java, TTF, ActiveX, Firefox) |
| T1056.001 | Input Capture: Keylogging | GROK keylogger plugin |
| T1112 | Modify Registry | GrayFish stores entire payload in Windows registry |
| T1027 | Obfuscated Files or Information | RC5/RC6/AES encryption throughout all platforms |
| T1071 | Application Layer Protocol | 300+ C2 domains, HTTP/HTTPS communications |

---

## 7. Shadow Brokers leaked tools and the FuzzBunch framework

The April 14, 2017 "Lost in Translation" release (>300 MB) contained the **FuzzBunch exploitation framework** — a Python 2.6-based modular tool analogous to Metasploit — along with the **DanderSpritz** post-exploitation platform and **12 Windows exploits**.

### FuzzBunch Windows exploits

| Tool | CVE | Target | Description |
|------|-----|--------|-------------|
| **EternalBlue** | CVE-2017-0144 | SMBv1 (XP–Win8, Server 2003–2008R2) | Buffer overflow in `srv!SrvOS2FeaListSizeToNt`; enabled WannaCry, NotPetya |
| **EternalRomance** | CVE-2017-0145 | SMBv1 (XP–Win8) | Type confusion between Transaction and WriteAndX |
| **EternalSynergy** | CVE-2017-0143/0146/0147 | SMBv3 (Win8, Server 2012) | Combined type confusion + race condition |
| **EternalChampion** | CVE-2017-0146/0147 | SMBv1 (multiple) | Race condition in Transaction requests |
| **EskimoRoll** | CVE-2014-6324 | Kerberos (Server 2000–2008R2) | PAC forging for domain privilege escalation |
| **EsteemAudit** | CVE-2017-0176 | RDP (XP, Server 2003) | Smart card authentication exploit |
| **ExplodingCan** | CVE-2017-7269 | IIS 6.0 WebDAV (Server 2003) | PROPFIND buffer overflow |
| **EmeraldThread** | MS10-061 | Print spooler (XP, Server 2003) | SMB print spooler exploit |
| **EducatedScholar** | MS09-050 | SMBv2 (Vista, Server 2008) | Negotiate function index exploit |
| **EclipsedWing** | MS08-067 | SMB/RPC (XP–Win7) | Same vulnerability as Conficker worm |
| **EnglishmanDentist** | CVE-2017-8487 | Outlook/Exchange | OWA rule-based code execution |
| **ErraticGopher** | (patched) | SMBv1 (XP, Server 2003) | Already patched before leak |

### Post-exploitation tools

**DoublePulsar** is a kernel-mode (Ring 0) SMB backdoor that hooks the SYSENTER routine. It supports four operations: ping (opcode 0x23), shellcode execution (0xC8), DLL injection, and uninstall (0x77). It is non-persistent (memory-only) and uses the SMB Trans2 SESSION_SETUP subcommand (0x0E, normally unimplemented) as its covert channel. Over **200,000 systems** were infected within two weeks of the April 2017 leak.

**DanderSpritz** is a comprehensive Java-based post-exploitation framework with GUI, supporting Listening Posts (LP) for C2, credential harvesting, privilege escalation, event log deletion, and deployment of the **PeddleCheap** persistent implant. It includes local privilege escalation exploits EpMe (CVE-2017-0005), ElEi, ErNi, and EpMo.

**DarkPulsar** provides persistent administrative backdoor access to Windows systems. **OddJob** is an implant builder and C2 server configured via HTA files. **MofConfig** uses Managed Object Format files for persistence.

### NSA ANT catalog tools (Snowden/Der Spiegel documents)

| Tool | Type | Description |
|------|------|-------------|
| **IRATEMONK** | HDD firmware implant | MBR substitution persistence via HDD firmware; matches nls_933w.dll |
| **UNITEDRAKE** | Modular framework | Extensible collection platform with plugins: GROK, SALVAGERABBIT (USB), FOGGYBOTTOM (browser), GUMFISH (webcam), CAPTIVATEDAUDIENCE (microphone) |
| **STRAITBIZARRE** | Multi-platform malware | Works across mobile/desktop/multiple architectures; receives commands from TURBINE C2 |
| **FOXACID** | Exploit delivery | Web-based exploit server using QUANTUM man-on-the-side attacks; unique URLs per target |
| **VALIDATOR** | First-stage implant | Initial access and reconnaissance; precursor to UNITEDRAKE/STRAITBIZARRE |
| **SCHOOLMONTANA** | Router BIOS implant | Persists in Juniper J-Series BIOS via SMM handler |
| **SIERRAMONTANA** | Router BIOS implant | Targets Juniper M-Series routers |
| **STUCCOMONTANA** | Router BIOS implant | Targets Juniper T-Series routers |

---

## 8. YARA rules for signature-based detection

Multiple YARA rule sets provide detection coverage across Equation Group malware families. The primary public repositories are Kaspersky Lab's official rules, Florian Roth's `Neo23x0/signature-base` (file `spy_equation_fiveeyes.yar` at ~604 lines), and the community `Yara-Rules/rules` repository (file `APT_Equation.yar` at ~663 lines).

### Equation Group exploitation library detection

```yara
rule apt_equation_exploitlib_mutexes {
    meta:
        copyright = "Kaspersky Lab"
        description = "Equation group Exploitation library"
        version = "1.0"
        last_modified = "2015-02-16"
    strings:
        $mz="MZ"
        $a1="prkMtx" wide
        $a2="cnFormSyncExFBC" wide
        $a3="cnFormVoidFBC" wide
        $a4="cnFormSyncExFBC"
        $a5="cnFormVoidFBC"
    condition:
        (($mz at 0) and any of ($a*))
}
```

### Equation Group cryptographic library signature

```yara
rule apt_equation_cryptolib {
    meta:
        copyright = "Kaspersky Lab"
        description = "Crypto library used in Equation group malware"
    strings:
        $a={37 DF E8 B6 C7 9C 0B AE 91 EF F0 3B 90 C6 80 85
            5D 19 4B 45 44 12 3C E2 0D 5C 1C 7B C4 FF D6 05
            17 14 4F 03 74 1E 41 DA 8F 7D DE 7E 99 F1 35 AC
            B8 46 93 CE 23 82 07 EB 2B D4 72 71 40 F3 B0 F7
            78 D7 4C D1 55 1A 39 83 18 FA E1 9A 56 B1 96 AB
            A6 30 C5 5F BE 0C 50 C1}
    condition:
        $a
}
```

### HDD firmware reprogramming module (nls_933w.dll)

```yara
rule EquationDrug_HDDSSD_Op {
    meta:
        description = "EquationDrug HDD/SSD firmware operation"
        hash = "ff2b50f371eb26f22eb8a2118e9ab0e015081500"
    strings:
        $mz = { 4d 5a }
        $s0 = "nls_933w.dll" fullword ascii
        $s1 = "BINARY" fullword wide
        $s2 = "KfAcquireSpinLock" fullword ascii
    condition:
        ( $mz at 0 ) and all of ($s*)
}
```

### DoubleFantasy detection

```yara
rule Equation_Kaspersky_DoubleFantasy {
    meta:
        description = "Equation Group - DoubleFantasy"
        author = "Florian Roth"
        hash = "d09b4b6d3244ac382049736ca98d7de0c6787fa2"
    strings:
        $mz = { 4d 5a }
        $z1 = "msvcp5%d.dll" fullword ascii
        $s0 = "actxprxy.GetProxyDllInfo" fullword ascii
        $s3 = "actxprxy.DllGetClassObject" fullword ascii
        $s5 = "actxprxy.DllRegisterServer" fullword ascii
        $s6 = "actxprxy.DllUnregisterServer" fullword ascii
        $x1 = "yyyyy..." ascii
        $x3 = "November " fullword ascii
        $x5 = "January " fullword ascii
    condition:
        ($mz at 0) and filesize < 350000 and
        (($z1) or (all of ($s*) and 6 of ($x*)))
}
```

### TripleFantasy detection

```yara
rule Equation_Kaspersky_TripleFantasy {
    meta:
        description = "Equation Group - TripleFantasy"
        hash = "b2b2cd9ca6f5864ef2ac6382b7b6374a9fb2cbe9"
    strings:
        $s0 = "%SystemRoot%\\system32\\hnetcfg.dll" fullword wide
        $s1 = "%WINDIR%\\System32\\ahlhcib.dll" fullword wide
        $s2 = "%WINDIR%\\sjyntmv.dat" fullword wide
        $s3 = "Global\\{8c38e4f3-591f-91cf-06a6-67b84d8a0102}" fullword wide
        $x1 = "itemagic.net@443" fullword wide
        $x2 = "team4heat.net@443" fullword wide
    condition:
        filesize < 300000 and (all of ($s*) or 1 of ($x*))
}
```

### Equation Group keyword detection

```yara
rule apt_equation_keyword {
    meta:
        description = "Equation group keyword in executable"
    strings:
        $a1 = "Backsnarf_AB25" wide
        $a2 = "Backsnarf_AB25" ascii
    condition:
        any of them
}
```

### DoublePulsar XOR shellcode (NotPetya variant)

```yara
rule DoublePulsarXor_Petya {
    meta:
        description = "XORed DoublePulsar shellcode"
        author = "Patrick Jones, Booz Allen Hamilton"
    strings:
        $DoublePulsarXor_Petya = { FD 0C 8C 5C B8 C4 24 C5
            CC CC CC 0E E8 CC 24 6B CC CC CC 0F 24 CD CC CC
            CC 27 5C 97 75 BA CD CC CC C3 FE }
    condition:
        $DoublePulsarXor_Petya
}
```

Additional YARA rule repositories cover the full Shadow Brokers tool dump in `Neo23x0/signature-base/yara/apt_eqgrp_apr17.yar` (dozens of rules for individual tools like emptycriss, ftshell, magicjack, pclean) and `apt_eternalblue_non_wannacry.yar` for non-WannaCry EternalBlue usage.

---

## 9. Network signatures for IDS/IPS detection

### Snort rules for EternalBlue (MS17-010)

**Cisco Talos SID 1:41978** — the primary official EternalBlue detection rule:
```
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (
  msg:"OS-WINDOWS Microsoft Windows SMB remote code execution attempt";
  flow:to_server,established;
  content:"|FF|SMB3|00 00 00 00|"; depth:9; offset:4;
  byte_extract:2,26,TotalDataCount,relative,little;
  byte_test:2,>,TotalDataCount,20,relative,little;
  reference:cve,2017-0144; reference:cve,2017-0146;
  sid:41978; rev:3;)
```

### Emerging Threats EternalBlue rules

**ET SID 2024217** — heap spray detection:
```
alert tcp any any -> any any (
  msg:"ET EXPLOIT Possible ETERNALBLUE MS17-010 Heap Spray";
  content:"|ff|SMB|33 00 00 00 00 18 07 c0 00 00 00 00 00 00
  00 00 00 00 00 00 00|"; offset:4; depth:25;
  content:"|08 ff fe 00 08 41 00 09 00 00 00 10|"; within:12;
  pcre:"/^[a-zA-Z0-9+/]{1000,}/R";
  threshold: type threshold, track by_src, count 12, seconds 1;
  sid:2024217; rev:1;)
```

**ET SID 2024220/2024218** — EternalBlue echo request/response flowbit pair for sequential detection.

### DoublePulsar detection rules (WithSecureLabs/Countercept)

Three Snort rules detect DoublePulsar's use of the unimplemented Trans2 SESSION_SETUP subcommand (0x0E):

```
# Request detection (SID 1618009)
alert tcp any any -> $HOME_NET 445 (
  msg:"DOUBLEPULSAR SMB implant - Unimplemented Trans2 Session Setup Request";
  flow:to_server, established;
  content:"|FF|SMB|32|"; depth:5; offset:4;
  content:"|0E 00|"; distance:56; within:2;
  sid:1618009; rev:1;)

# Successful implant ping - MultiplexID 81 (SID 1618008)
alert tcp $HOME_NET 445 -> any any (
  msg:"DOUBLEPULSAR SMB implant - Response MultiplexID 81";
  flow:to_client, established;
  content:"|FF|SMB|32|"; depth:5; offset:4;
  content:"|51 00|"; distance:25; within:2;
  sid:1618008; rev:1;)

# Successful installation - MultiplexID 82 (SID 1618010)
alert tcp $HOME_NET 445 -> any any (
  msg:"DOUBLEPULSAR SMB implant - Response MultiplexID 82";
  flow:to_client, established;
  content:"|FF|SMB|32|"; depth:5; offset:4;
  content:"|52 00|"; distance:25; within:2;
  sid:1618010; rev:1;)
```

### DoublePulsar protocol-level indicators

DoublePulsar communicates via **SMB Trans2 subcommand 0x0E (SESSION_SETUP)**, which is normally unimplemented. The implant uses MultiplexID field steganography — the delta between request and response MultiplexID values encodes status (0x10 = success, 0x20 = invalid params, 0x30 = allocation failure). The RDP variant uses magic bytes **`44 37 28 19`** with a 288-byte ping response.

### Official Snort DoublePulsar SIDs

| SID | Description |
|-----|-------------|
| 1:42329 | Win.Trojan.Doublepulsar successful ping response |
| 1:42331 | Win.Trojan.Doublepulsar process injection command |
| 1:42332 | Win.Trojan.Doublepulsar ping command |

### Vendor IPS signatures

| Vendor | Signature |
|--------|-----------|
| Fortinet/FortiGuard | IPS Signature "Backdoor.DoublePulsar" (ID 43963) |
| Broadcom/Symantec | Attack Signature "SMB Double Pulsar Ping" (ASID 21331) |
| ExtraHop | "DoublePulsar RDP Scan" — monitors for magic bytes `44 37 28 19` |

### Detection tools

The **WithSecureLabs DoublePulsar Detection Script** (Python) provides unauthenticated remote scanning via `detect_doublepulsar_smb.py` (port 445) and `detect_doublepulsar_rdp.py` (port 3389), supporting IP, file, and subnet parameters with multi-threading and remote uninstall capability.

---

## 10. Kaspersky detection names and internal codenames

### Antivirus detection signatures

Key Kaspersky detection names: `Trojan.Win32.EquationDrug.b` through `.k`, `Trojan.Win64.EquationDrug.a/.b`, `Trojan.Win32.EquationLaser.a/.c/.d`, `HEUR:Trojan.Win32.DoubleFantasy.gen`, `HEUR:Trojan.Win32.EquationDrug.gen`, `HEUR:Trojan.Win32.GrayFish.gen`, `HEUR:Trojan.Win32.TripleFantasy.gen`, `Rootkit.Boot.Grayfish.a`, `Worm.Win32.AutoRun.wzs` (Fanny), and `Backdoor.Win32.Laserv.b` (EquationLaser).

### Internal codenames embedded in binaries

These NSA-style codenames were found in malware samples: **SKYHOOKCHOW** (EquationDrug orchestrator), **STEALTHFIGHTER**, **DRINKPARSLEY**, **STRAITACID**, **LUTEUSOBSTOS**, **STRAITSHOOTER**, **DESERTWINTER** (PDB path artifact), **UR/URInstall** (possible UNITEDRAKE reference), and **Backsnarf_AB25**. The presence of codenames like STRAITACID and STRAITSHOOTER that match known NSA program names from the Snowden documents formed a key element of the attribution case.

### Encryption fingerprint

All Equation Group malware families share a distinctive RC5/RC6 implementation using magic constants **P=0xB7E15163** and **Q stored as -0x61C88647** (added rather than subtracting 0x9E3779B9). This cryptographic fingerprint, combined with 1024-bit RC5 keys with 24 rounds for registry encryption, serves as a reliable cross-family identification marker.

---

## Conclusion

The Equation Group IOC landscape reveals an adversary operating at a scale and sophistication unmatched by any other publicly documented threat actor. Three characteristics stand apart as defining. First, the **layered persistence architecture** — from registry-only malware (GrayFish) through VBR bootkits to HDD firmware implants — created redundant footholds that conventional forensics cannot fully enumerate. Second, the **multi-stage validation pipeline** (DoubleFantasy → EquationDrug/GrayFish) with environmental keying ensured tools were deployed only against confirmed targets, limiting exposure for over a decade. Third, the **bidirectional USB covert channel** (Fanny) demonstrated operational creativity in reaching air-gapped targets years before similar techniques became widely known.

For defenders, the most actionable detection opportunities are the network-level DoublePulsar signatures (Trans2 SESSION_SETUP subcommand 0x0E with MultiplexID anomalies), the cryptographic constant fingerprint in RC5/RC6 implementations, the specific registry paths under `HKLM\Software\Classes\CLSID\{6AF33D21-...}` and `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\MemSubSys`, and the mutex names `prkMtx`/`cnFormSyncExFBC`/`cnFormVoidFBC`. The YARA rules from Neo23x0/signature-base and Yara-Rules/rules repositories provide the most maintained open-source detection coverage. The Chinese APT groups Buckeye (APT3) and APT31 (Zirconium) independently obtained and deployed Equation Group tools — Buckeye as early as March 2016, a full year before the Shadow Brokers public release — demonstrating that these IOCs remain relevant for tracking secondary proliferation of nation-state capabilities.
