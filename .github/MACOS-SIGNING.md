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

## Where the private key is allowed to exist

Generate it on a machine **you** control — a laptop, not a shared devbox and
not a box that runs coding agents with shell access. `openssl` is the only
requirement, so this is thirty seconds anywhere.

The key is the crown jewel of this whole arrangement. Anything holding it can
sign code that macOS trusts as us; that is a different class of secret from a
token, because the damage is done to *users* rather than to our
infrastructure, and it is not repaired by rotation — every binary ever signed
with the leaked key has to be re-signed and re-released, and users who already
installed one have no way to know.

Three places it will exist, and that should be all three:

1. Your laptop, briefly, while you build the `.p12`.
2. An encrypted backup in a password manager.
3. The `release-signing` environment secret, used by tagged releases only.

It should NOT end up in a repository, a scratch directory, a chat transcript,
or an agent's working tree.

## Producing the six secrets

All of this runs on Linux or macOS; the Apple developer portal is the only
part that needs a browser, and Keychain Access is never involved.

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

### 3. Install them — into the ENVIRONMENT, never the repository

```sh
E="--repo Reachpad/reachpad-cli --env release-signing"
gh secret set MACOS_CERTIFICATE     $E < cert.b64
gh secret set MACOS_CERTIFICATE_PWD $E < pwd.txt
gh secret set MACOS_SIGN_IDENTITY   $E < identity.txt
gh secret set MACOS_NOTARY_KEY      $E < key.b64
gh secret set MACOS_NOTARY_KEY_ID   $E < keyid.txt
gh secret set MACOS_NOTARY_ISSUER   $E < issuer.txt
```

`--env release-signing` is not optional and not a detail. A **repository**
secret is readable by any workflow in the repository, on any branch, including
one added by anyone with write access — and this repository is public with two
admins and no branch protection on `main`. An **environment** secret is
reachable only by a job naming that environment, after its rules pass: ours
allow deployment from `cli-v*` tags only, with a required human reviewer.

Read from files, not from arguments: a value passed on a command line is
visible in `ps` to every other process on the machine, and lands in shell
history.

Back the `.p12` up **before** deleting anything — an encrypted note in a
password manager, not a file on a work machine. Apple caps how many Developer
ID Application certificates an account may hold, so "just make another" is not
free, and revoking one invalidates signatures made with it.

Then destroy the local copies:

```sh
shred -u devid.key devid.p12 cert.b64 key.b64 pwd.txt identity.txt \
        keyid.txt issuer.txt AuthKey_*.p8
```

The `.p8` cannot be re-downloaded. If it is lost, revoke that key in App Store
Connect and generate another; unlike the certificate, notary keys are cheap.

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

## If the key leaks

Assume it leaked if the `.p12` or its password appeared anywhere in the "not
allowed" list above, or if a release was signed that nobody approved — the
environment's reviewer requirement exists so that second one is answerable.

1. **Revoke the certificate** at developer.apple.com. This invalidates
   signatures made with it, including on binaries already installed.
2. **Delete the environment secrets** so no further release can use it:
   `gh secret delete MACOS_CERTIFICATE --repo Reachpad/reachpad-cli --env release-signing`
   and the other five.
3. **Check what was signed with it**: every `cli-v*` release since the key was
   installed, and whether each has an approval in the environment's deployment
   history. GitHub records who approved each one.
4. **Issue a new certificate, re-sign, re-release** every version still being
   downloaded. Publish what happened — a revoked signature makes existing
   installs fail to pass Gatekeeper, and users deserve to know why before
   they hit it.

Notarization tickets are Apple's record, not ours; Apple can revoke those
separately if the binary is found to be malicious.

## Letting users check us

Once signing is live, publish the expected authority so anyone can verify a
download came from us rather than from whoever else might have the key:

```sh
codesign -dv --verbose=4 $(which reachpad) 2>&1 | grep Authority
# Authority=Developer ID Application: <name> (<TEAMID>)
# Authority=Developer ID Certification Authority
# Authority=Apple Root CA
```

A team ID printed in the README is a check a user can actually perform, and it
is what makes a stolen-certificate build detectable by someone other than us.
