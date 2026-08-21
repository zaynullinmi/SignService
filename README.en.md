# SignService — Digital Signature Tool

[Русский](README.md) | **English**

A desktop application (C# / [Avalonia UI](https://avaloniaui.net/)) for signing
documents with electronic signatures (CMS/PKCS#7) and working with signature
files. The signing logic is ported from the ReportGGE document-signing service
and targets the Russian GOST cryptography ecosystem (CryptoPro CSP), while
plain RSA/ECDSA certificates work as well.

**Download:** a ready-to-run `SignService.exe` (Windows x64, no .NET required)
is published on the [Releases](https://github.com/zaynullinmi/SignService/releases) page.

## Features

### Signing

- **Drag & drop** files or whole folders into the window, add via a file
  browser, batch signing with a per-file status; file paths are also accepted
  as command-line arguments ("Open with");
- **detached** signature (`name.sig` next to the document — the format required
  by government portals) or **attached** (document embedded in the `.sig`);
- **CAdES-BES by default**: signed attributes signing-time and
  signing-certificate-v2 (RFC 5035, protects against certificate substitution);
  for GOST-2012 certificates certHash is computed with Streebog — a managed
  GOST R 34.11-2012 implementation validated against RFC 6986 test vectors;
- optional **timestamp (CAdES-T)**: a trusted timestamp from an RFC 3161 TSA
  (URL is configurable); for GOST signatures the TSA request is hashed with
  Streebog;
- **GOST via CryptoPro**: on Windows signatures are created through native
  CryptoAPI (`CryptSignMessage`) — the certificate's CSP (CryptoPro CSP for
  GOST) performs the operation and prompts for the container PIN when needed;
  the hash OID is selected by key type (GOST R 34.10-2012 256/512,
  34.10-2001, RSA/ECDSA);
- the **full certificate chain** is embedded into each signature (for offline
  verification) and cached per certificate for batch signing.

### Co-signing and verification

- other people's signatures are **merged with yours into a single `.sig`**
  with multiple signers: automatically with an existing `name.sig` next to the
  document (can be turned off), via the "＋.sig" button, or by dropping
  a signature file onto the window;
- re-signing with the same certificate **replaces** your previous signature
  instead of duplicating it;
- every merged signature is **verified against the document hash**
  (messageDigest; Streebog for GOST): signatures made over a different file
  or an older revision are excluded automatically, reporting the signer name;
- input signatures are accepted in DER/BER (including indefinite lengths and
  trailing bytes) and base64/PEM.

### Tools (no signature created)

- **Merge .sig…** — combine several signature files into one containing all
  signers (attached containers are accepted; the embedded document is kept);
- **Extract from .sig…** — pull out of a container: the embedded document
  (byte-exact), a detached signature with all signers, and individual `.sig`
  files per signer (signer names in the file names);
- **Build container…** — pack a document together with its existing
  signatures into an attached `.sig` (the inverse of extraction);
- **Stamp PDF…** — save a stamped copy of a document without signing.

### Machine-readable power of attorney (MChD)

- the "Add power of attorney…" button works like Kontur: pick the MChD XML
  (EMCHD_1 format) and the head's signature (.sig; a neighbouring
  `name.xml.sig` is picked up automatically);
- the app verifies: the head's signature matches the MChD file (by hash,
  Streebog for GOST), the validity period has not expired, and the
  representative in the MChD matches the selected certificate by INN/SNILS;
- when signing, the MChD files (XML + .sig) are copied next to the signed
  document (the MChD is NOT embedded into the CMS signature — Kontur does
  the same), and the visual PDF stamp gains a
  "Acting under power of attorney No. …" line;
- the power of attorney is remembered and re-validated on every signing.

### Visual stamp on PDF

- a "DOCUMENT SIGNED WITH ELECTRONIC SIGNATURE" box on the last page:
  certificate number, owner, validity period, optionally the signing date and
  an **organization logo** (PNG/JPEG);
- the stamped copy `name (stamped).pdf` is created **before** signing and is
  the file that gets signed; the original is left untouched.

### Certificates

- certificate picker from the "Current User → Personal" store, expired-cert
  filter, the selection is remembered;
- **save a certificate to this computer** (💾 button) to sign without the
  hardware token:
  - "inside the app" — a password-protected PFX visible only to SignService;
  - "into the Windows store" — a copy of the key is installed into the system
    store so **other applications** (CryptoARM, browsers, etc.) can sign too;
    works for token certificates as well (export + install in one step);
  - the app shows an **explicit warning** about the reduced security; removal
    via the 🗑 button (the PFX is wiped; only store entries installed by the
    app can be removed); non-exportable keys cannot be saved — that is
    a token/CA restriction.

### Miscellaneous

- an **operation log window** with timestamps;
- an **About window**: version, author contacts, changelog, update check;
- **auto-update**: new releases are checked on GitHub Releases at startup
  (can be disabled) and installed in one click from the About window (Windows).

## Requirements

- Windows 10/11 — the self-contained exe from the Releases page;
- for GOST signatures — **CryptoPro CSP** installed with a personal
  certificate;
- building from source: .NET 8 SDK (Windows/Linux/macOS; outside Windows
  signing is limited to platform algorithms — RSA/ECDSA; GOST requires
  the CSP on Windows).

## Build and run

```bash
dotnet build SignService.sln -c Release
dotnet run --project src/SignService
dotnet run --project tests/SignService.Tests -c Release   # tests
```

Publishing the self-contained exe:

```bash
dotnet publish src/SignService -c Release -r win-x64 --self-contained true \
  -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true \
  -p:EnableCompressionInSingleFile=true \
  -o publish
```

## Usage

1. Start the app — certificates with a private key appear in the drop-down.
2. Pick a certificate and the signature mode; optionally enable the timestamp
   and/or the PDF stamp.
3. Drag files into the window (or use the browser) and press **Sign** —
   a `name.sig` appears next to each file.
4. Operations on existing signatures live in the **Tools** menu.

The change history is in [CHANGELOG.md](CHANGELOG.md) (Russian) and in the
About window.

## Author

**Marat Zaynullin (Зайнуллин Марат Илгамович)**

- Phone: +7-963-694-2461
- E-mail: <zaynullinmi@gmail.com>
- GitHub: <https://github.com/zaynullinmi>

## Project layout

```
src/SignService/
├── Services/
│   ├── CertificateProvider.cs   # certificate access (X509Store)
│   ├── DocumentSigner.cs        # CMS/PKCS#7 signing: GOST OIDs, chain, cache
│   ├── NativeSign.cs            # CryptSignMessage (CryptoAPI) — GOST via CryptoPro
│   ├── CadesAttributes.cs       # CAdES-BES attributes: signing-time, signing-cert-v2
│   ├── Streebog.cs              # GOST R 34.11-2012 for certHash (RFC 6986 vectors)
│   ├── CmsMerger.cs             # ASN.1-level merge/split/build of signatures
│   ├── CmsExtractor.cs          # file operations: extract, merge, container
│   ├── BerDer.cs                # BER → definite-length normalization
│   ├── CertificateVault.cs      # certificate on disk: PFX and Windows store
│   ├── TimestampClient.cs       # RFC 3161 TSA client for CAdES-T
│   ├── PdfStamper.cs            # visual PDF stamp (details, date, logo)
│   ├── UpdateService.cs         # auto-update via GitHub Releases
│   └── AppSettings.cs           # settings (certificate, modes, stamps)
├── ViewModels/                  # MVVM: main window, files, certificates
└── Views/                       # windows: main, password, confirm, about
tests/SignService.Tests/         # integration tests (run in CI)
```
