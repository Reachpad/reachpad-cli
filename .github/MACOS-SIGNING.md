# Signing and notarizing the macOS binaries

The `sign and notarize` step in `release.yml` is written and inert. It skips
with a warning while none of the six `MACOS_*` secrets exist, and fails loudly
if only some do. This file is how to make it run.

## What it actually fixes

Nothing that any advertised install path suffers from. `brew install`,
`npm install -g @reachpad/cli` and `curl … | sh` all deliver the binary without
`com.apple.quarantine`, and an ad-hoc signed binary with no quarantine tag just
runs.

It fixes exactly one path: **downloading a tarball from the GitHub releases page
in a browser.** The browser sets the quarantine attribute, macOS then assesses
the binary, and an ad-hoc signature can never pass that assessment — the user
gets "Apple could not verify reachpad is free of malware". Today the release
body explains this and gives them `xattr -d`; notarization removes the dialog
instead of explaining it.

Decide whether that path is worth $99/year before doing any of the below. It is
not on the critical path for any customer we point at an install command.

## One decision first: individual or organization

Organization enrollment shows **Reachpad** in the certificate, and requires a
legal entity and a D-U-N-S number. As of 2026-08 no Reachpad legal entity
exists, so this is weeks of company formation, not an afternoon.

Individual enrollment shows **Seiji Sakurai** in the certificate and takes
hours to days. Gatekeeper does not care which it is; a curious user running
`codesign -dv` sees a person's name rather than a company's.

There is no in-place conversion from individual to organization later — you
enroll the org separately and re-sign. That costs nothing here, because these
are bare binaries with no bundle identity and no update rules keyed to a team
ID. **Start individual.**

## Producing the six secrets

All of this runs on Linux; a Mac is not required at any point. `openssl` is
enough, and it avoids the Keychain Access dance entirely.

### 1. Certificate → `MACOS_CERTIFICATE`, `MACOS_CERTIFICATE_PWD`, `MACOS_SIGN_IDENTITY`

```sh
# A private key and a certificate signing request. Keep devid.key secret and
# out of any repository — the .p12 below is the only thing that leaves here.
openssl genrsa -out devid.key 2048
openssl req -new -key devid.key -out devid.csr \
  -subj "/emailAddress=<your apple id email>/CN=<your name>/C=US"
```

At <https://developer.apple.com/account/resources/certificates> → **+** →
**Developer ID Application**, upload `devid.csr`, and download the resulting
`developerID_application.cer`. Creating a Developer ID certificate needs the
Account Holder role, which on an individual account is you.

```sh
openssl x509 -inform DER -in developerID_application.cer -out devid.pem
openssl pkcs12 -export -out devid.p12 -inkey devid.key -in devid.pem \
  -passout pass:"$P12_PASSWORD"

base64 -w0 devid.p12          # -> MACOS_CERTIFICATE
echo "$P12_PASSWORD"          # -> MACOS_CERTIFICATE_PWD
openssl x509 -in devid.pem -noout -subject   # the CN is MACOS_SIGN_IDENTITY
```

`MACOS_SIGN_IDENTITY` is the full common name, including the team id in
parentheses — `Developer ID Application: Seiji Sakurai (ABCDE12345)`.

### 2. Notarization key → `MACOS_NOTARY_KEY`, `MACOS_NOTARY_KEY_ID`, `MACOS_NOTARY_ISSUER`

At <https://appstoreconnect.apple.com/access/integrations/api> → **Keys** →
generate a key with the **Developer** role. The `.p8` downloads **once** and
cannot be downloaded again.

```sh
base64 -w0 AuthKey_XXXXXXXXXX.p8   # -> MACOS_NOTARY_KEY
```

`MACOS_NOTARY_KEY_ID` is the `XXXXXXXXXX` in that filename.
`MACOS_NOTARY_ISSUER` is the Issuer ID shown above the key list — a UUID,
shared by every key in the account.

### 3. Install them

```sh
gh secret set MACOS_CERTIFICATE     --repo Reachpad/reachpad-cli < cert.b64
gh secret set MACOS_CERTIFICATE_PWD --repo Reachpad/reachpad-cli
gh secret set MACOS_SIGN_IDENTITY   --repo Reachpad/reachpad-cli
gh secret set MACOS_NOTARY_KEY      --repo Reachpad/reachpad-cli < key.b64
gh secret set MACOS_NOTARY_KEY_ID   --repo Reachpad/reachpad-cli
gh secret set MACOS_NOTARY_ISSUER   --repo Reachpad/reachpad-cli
```

Then shred the local copies: `shred -u devid.key devid.p12 cert.b64 key.b64
AuthKey_*.p8`. The `.p8` is the one that cannot be re-downloaded — if you lose
it, revoke the key and make another.

The next `cli-v*` tag signs and notarizes. The workflow asserts afterwards that
the signing authority really is a Developer ID Application certificate, because
`codesign --verify` passes just as happily against an ad-hoc or an "Apple
Development" signature, both of which Gatekeeper refuses exactly like no
signature at all.

## The limit of this, which is real

**A bare Mach-O executable cannot be stapled.** `xcrun stapler` attaches a
notarization ticket to bundles, disk images and installer packages — there is
nowhere in a plain executable to put one. So a notarized `reachpad` still needs
Gatekeeper to check notarization **online** the first time it runs. On a machine
with no network at that moment, the assessment can still fail.

Closing that would mean shipping a signed, notarized, stapled `.pkg` for macOS
alongside the tarball. That is a second artifact, a second signing identity
(`Developer ID Installer`), and a `productbuild` step — worth doing only if
people actually report the offline case. They cannot report it yet, because the
paths we advertise never reach Gatekeeper at all.

## Renewal

Developer ID certificates last five years; the Apple Developer Program
membership is annual and the certificate stops being usable if the membership
lapses. `--timestamp` is passed at signing time, so binaries already released
keep verifying after the certificate expires. Only new signings break.
