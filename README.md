# OpenPGP card initializer tool

**This tool is for demonstration purposes only, DO NOT USE IN PRODUCTION.**

Automatically initialize an OpenPGP card as follows:

- Generate a set of Curve25519 private keys (SIG, DEC, AUT) on-card.
- Generate Attestation Statements for each slot that the key material was
  generated on-card.
- Create an OpenPGP certificate (public key) that:
  - uses the SIG key as the primary key (certification and signing capable),
  - binds the DEC and AUT key slots to the certificate as subkeys,
  - binds a User ID (composed of the user `name` and `email`) to the
    certificate.
- Generates one hard and one soft revocation for the user certificate.
- Optionally sets an expiration date on the certificate.
- Exports the following artifacts as a zip file:
  - The OpenPGP certificate (public key),
  - the Attestation Statements and
  - the card's Attestation Certificate,
  - and a pair of revocation certificates (one hard and one soft revocation).

## Only runs against blank (or factory reset) cards

The tool will *only* attempt to initialize cards that have *no* key material
on them. This limitation is a safeguard against accidentally overwriting a
card that contains (possibly important) key material.

(Absence of key material is detected via the Fingerprint DOs on the card.)

The tool also assumes that the card accepts default User and Admin PINs
(this should be the case for cards that are new or factory reset).
If the PINs are set to different values, the tool will fail.

## Compatible card models

The tool makes assumptions about the features of the card. It is designed to
work with the Yubikey 5. Other card types may not have all required features.

Attempting to run this tool on other card models will probably fail.
However, such a failure is no big deal, it will just result in a
half-initialized card. You'll probably want to factory-reset the card,
in that case.

Not all Yubikey 5 support the "cached" touch policies. The touch cache feature
was added in
[firmware version 5.2](https://support.yubico.com/hc/en-us/articles/360016649139-YubiKey-5-2-Enhancements-to-OpenPGP-3-4-Support).
You can check the firmware version of Yubikey cards with `ykman`, or with the
[opgpcard](https://crates.io/crates/openpgp-card-tools) tool.

## Help

```
An example tool that initializes OpenPGP cards.

Usage: openpgp-card-init [OPTIONS] --name <NAME> --email <EMAIL> --touch <TOUCH_POLICY> --output <OUTPUT>

Options:
      --name <NAME>
          Name of the card's user

      --email <EMAIL>
          Email of the card's user

      --touch <TOUCH_POLICY>
          Touch policy for the regular key slots.

          This policy will be set for the SIG, DEC, AUT key slots. The ATT key slot touch policy is always set to `On`.

          [possible values: Off, On, Cached, Fixed, CachedFixed]

      --output <OUTPUT>
          Filename of the output zip archive

      --card <CARD>
          Card ident.

          Optional, if unset any blank card that is found will be initialized.

      --expiration <EXPIRATION_DAYS>
          Expiration of certificate in days.

          Optional, if unset the certificate has no expiration date.

  -h, --help
          Print help information (use `-h` for a summary)

  -V, --version
          Print version information
```

## Example run

```
$ openpgp-card-init --name "Alice" --email "alice@example.org" --touch On --output alice.zip

Found card 0006:01234567 .. empty -> initializing!
- Generating keys ...
- Constructing OpenPGP certificate ...
- Temporarily disabling touch confirmation for attestation ...
- Generating attestations ...
- Retrieving attestations and attestation certificate ...
- Configuring touch confirmation for key slots to 'On' ...
  Touch confirmation for attestation key slot set to 'On'

Setting PINs for OpenPGP on your card:

User PIN:    700838
Admin PIN: 54266954

***         Make sure you don't lose the PINs above!          ***
*** Without them you cannot use the OpenPGP keys on this card ***
```

The output file `alice.zip` contains the certificate (public key),
the attestation certificate of the card, one attestation per key slot,
and two revocation certificates (one hard, one soft) that can be used to
revoke the newly created certificate:

```
Archive:  alice.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     2039  12-25-2022 20:18   0006_01234567.pub
     1200  12-25-2022 20:18   0006_01234567-attestation.cert
      998  12-25-2022 20:18   0006_01234567-sig.attestation
      972  12-25-2022 20:18   0006_01234567-aut.attestation
     1038  12-25-2022 20:18   0006_01234567-dec.attestation
      432  12-25-2022 20:18   0006_01234567.revocation.soft
      452  12-25-2022 20:18   0006_01234567.revocation.hard
---------                     -------
     7131                     7 files
```

Note that the User and Admin PIN are only shown in the output of the script
run, they are not persisted anywhere.

## Optional parameters

You can specify a particular card to initialize with the `--card <CARD>` parameter.
Like above, the card must be blank (or factory reset) before use.

An expiration for the certificate can be set via `--expiration <EXPIRATION_DAYS>` (specified in days), e.g.:

```
$ openpgp-card-init --name "Alice" --email "alice@example.org" --touch On --output alice.zip --card 0006:01234567 --expiration 365
```

## Build Dependencies

Build dependencies for current Debian:

`# apt install rustc cargo clang pkg-config nettle-dev libpcsclite-dev`

Build dependencies for current Fedora:

`# dnf install rustc cargo clang nettle-devel pcsc-lite-devel`
