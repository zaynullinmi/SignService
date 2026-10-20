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
  with multiple signers: the app finds a document's signatures in its folder
  **by content** — the signature file name may be anything
  ("договор-.pdf .sig", `.p7s`, `.p7m`); each file offers "Add to 'X.sig'
  (8 signers)" or "Create new", and a plan line shows what will happen
  ("signature No. 9 will be added to …"); the "Add to existing signature /
  Create new" switch sets the default. Signatures from other folders are
  attached with the "＋.sig" button or by dropping them — to their document
  by content;
- before replacing a signature file without merging and before excluding
  signers the app asks for confirmation and keeps a backup next to it; the
  result shows in the file row: "Подписан: 9 (8 + ваша) → X.sig";
- if the destination signature changes, disappears or appears during signing,
  publication stops and preserves the other version, in both signing modes;
- re-signing with the same certificate **replaces** your previous signature
  instead of duplicating it;
- every merged signature is **cryptographically verified**, including the
  document digest, signature value and CAdES certificate binding — CryptoPro
  signatures with GOST parameters in signatureAlgorithm included. Damaged
  signatures and signatures over another revision are excluded; signers that
  cannot be verified (unknown algorithm, missing certificate) are kept and
  explicitly reported;
- attaching another person's signature or switching the certificate puts an
  already signed file back into the queue so it can be co-signed;
- input signatures are accepted in DER/BER (including indefinite lengths and
  trailing bytes) and base64/PEM.

### Tools (no signature created)

The operations are available in the **Tools** menu (pick files) and in the
**context menu of a file** in the list (right click) — then the neighbouring
`name.sig` is used.

- **Verify signature…** — per-signer CMS/CAdES verification for GOST-2001,
  GOST-2012 256/512, RSA and ECDSA without CryptoPro. Select the original for
  a detached signature; attached signatures use the embedded document. From
  the context menu ("Signers and verification…") verification starts at once.
  Copy or export the detailed report to TXT;
- **Merge .sig…** — combine several signature files into one containing all
  signers (attached containers are accepted; the embedded document is kept);
  when the document is known (by name or found by content) the result is
  `document.sig`, an existing file is never overwritten;
- **Extract from .sig…** — pull out of a container: the embedded document
  (byte-exact), a detached signature with all signers, and individual `.sig`
  files per signer (signer names in the file names);
- **Split a group signature…** — a separate detached `.sig` per signer (the
  embedded document is saved next to them);
- **Remove a signer from .sig…** — pick the signer in a list (identical names
  are told apart by the certificate serial number); a new file
  `name (без подписанта).sig` is created, the source is left untouched and the
  last signer cannot be removed;
- **Build container…** — pack a document together with its existing
  signatures into an attached `.sig` (the inverse of extraction);
- **Stamp PDF…** — save a stamped copy of a document without signing.

### Machine-readable power of attorney (MChD)

- the "Add power of attorney…" button works like Kontur: pick the MChD XML
  (EMCHD_1 format) and the head's signature (.sig; a neighbouring
  `name.xml.sig` is picked up automatically);
- the app verifies the head's signature using the certificate public key,
  checks the MChD validity period and that the representative is the owner of
  the selected certificate: the personal INN (12 digits) and SNILS are compared
  when present on both sides; an organization INN in the certificate is never
  compared with a personal INN;
- a head certificate that expired after the MChD was issued does not reject
  it — the certificate is checked as of the issue date and a warning is shown;
  a certificate that expired before the issue date (or was not yet valid) is
  an error;
- when signing, the MChD files (XML + .sig) are copied next to the signed
  document (the MChD is NOT embedded into the CMS signature — Kontur does
  the same), and the visual PDF stamp gains a
  "Acting under power of attorney No. …" line;
- the power of attorney is remembered and re-validated in the background at
  startup and once before every signing batch.

### Visual stamp on PDF

- a "DOCUMENT SIGNED WITH ELECTRONIC SIGNATURE" box: certificate number, owner,
  validity period, optionally the signing date and an **organization logo**
  (PNG/JPEG);
- the parameters are chosen in a dialog before the operation: pages (first,
  last, all or a list such as "1,3-5"), date, logo; every selected page gets
  a **separate box per signer**;
- by default the **original** file is signed, and the stamped copy
  `name (stamped).pdf` is a separate **unsigned** file recreated after every
  signing with **all signers** of the resulting signature (safe for
  co-signing — the stamp never invalidates other signatures);
- a separate checkbox enables the "sign the stamped copy" mode (stamp before
  signing) for recipients that require the signature over the stamped file.

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

- the **operation log** is always visible in the main window, with timestamps;
- a **Settings window**: timestamp (CAdES-T) and the TSA URL;
- an **About window**: version, author contacts, changelog, update check;
- **auto-update**: new releases are checked on GitHub Releases at startup
  (can be disabled) and installed in one click from the About window (Windows);
  the previous exe is kept as a backup and restored if the new version fails
  to start.

### Trust, revocation and timestamps

The report separates document integrity, signature value, certificate binding,
certificate trust, revocation and TSA results. An embedded root never creates
trust: anchors come from OS root stores and explicitly selected CA certificates.
BouncyCastle verifies certificate-chain, CRL and OCSP signatures without a CSP.

Verification is offline by default. It uses embedded CRLs and selected `.crl`/
`.ocsp` files; HTTP(S) CRL/OCSP requests require the network checkbox (the
setting is remembered and also applies to MChD checks). An unavailable trusted
root file is skipped with a warning. Revocation
is checked for every chain certificate except the trust anchor. Missing, stale,
unverifiable or partial evidence (including delta/indirect CRLs) gives an unknown
status. Missing intermediate certificates must be embedded in the CMS or in OS
intermediate stores.

The signer's `signing-time` does not prove when a signature was created.
Historical certificate validity is assessed only using a TSA timestamp whose
imprint, signature, trust and required revocation checks passed. TSA responses
also must match the request and nonce.

MChD verification re-reads current files before a signing batch, verifies and
copies the same XML/SIG snapshot. If the head certificate expired after the MChD
was issued and there is no TSA timestamp, the signing time is not proven — the app
warns and checks the certificate as of the issue date. Conflicting destination files stop signing before the signature is
saved. Cryptographic verification does not establish the head's authority,
the scope of delegated powers or MChD registry revocation; missing assurances
are reported as warnings.

## Requirements

- Windows 10/11 — the self-contained exe from the Releases page;
- to **create** GOST signatures — **CryptoPro CSP** installed with a personal
  certificate;
- verifying and merging GOST signatures requires **no CryptoPro** on Windows/Linux/macOS;
- building from source: .NET 8 SDK (Windows/Linux/macOS; outside Windows
  signing is limited to platform algorithms — RSA/ECDSA; GOST requires
  the CSP on Windows).

## Build and run

```bash
dotnet build SignService.sln -c Release
dotnet run --project src/SignService
dotnet run --project tests/SignService.Tests -c Release   # tests
```

On a personal workstation append `-- --skip-user-store` to the test command to
skip scenarios that change user certificate stores or application data. CI runs
the full suite in isolated Linux and Windows runners. Managed GOST, CRL/OCSP and
TSA verification tests run without CryptoPro or OpenSSL; the UI is smoke-tested
without a display (Avalonia.Headless).

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
2. Pick a certificate, the signature mode and "Add to existing signature" or
   "Create new"; each file shows which signature yours will be added to.
   Optionally enable the PDF stamp (a dialog asks for its parameters); the
   timestamp is set up in **Settings…**.
3. Drag files into the window (or use the browser) and press **Sign** —
   a `name.sig` appears next to each file.
4. Operations on existing signatures live in the **Tools** menu and in the
   file context menu (right click); progress is shown in the log.

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
│   ├── CmsExtractor.cs          # file operations: extract, merge, split, container
│   ├── SignatureDiscovery.cs    # finding a document's signatures by content
│   ├── SignatureVerifier.cs     # per-signer verification (BouncyCastle, GOST without a CSP)
│   ├── CertificateValidator.cs  # trust chain (PKIX) and OS stores
│   ├── RevocationChecker.cs     # certificate revocation: CRL and OCSP
│   ├── PowerOfAttorneyService.cs # MChD: EMCHD_1 parsing, checks, copying
│   ├── BerDer.cs                # BER → definite-length normalization
│   ├── AtomicFile.cs            # file writes through a temporary file
│   ├── CertificateVault.cs      # certificate on disk: PFX and Windows store
│   ├── TimestampClient.cs       # RFC 3161 TSA client for CAdES-T
│   ├── PdfStamper.cs            # visual PDF stamp (pages, signers, logo)
│   ├── UpdateService.cs         # auto-update via GitHub Releases
│   └── AppSettings.cs           # settings (certificate, modes, stamps, trust)
├── ViewModels/                  # MVVM: main window, files, certificates
└── Views/                       # windows: main, verification, stamp, signers, settings…
tests/SignService.Tests/         # integration tests and UI smoke test (CI: Linux and Windows)
.github/release/                 # release archive packaging: script and license texts
```
