// SPDX-FileCopyrightText: 2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This tool is for demonstration purposes only, DO NOT USE IN PRODUCTION.
//!
//! This is an example tool that initializes an OpenPGP card in a specific way:
//! It generates private keys on card, and exports information about the
//! resulting key material as a zip file.
//!
//! We make assumptions about the features of the card that currently require
//! a Yubikey 5 to work. Attempting to run this tool on other cards will fail.
//! (Such failure is not terrible, you'll probably just want to factory-reset
//! the card, in that case).
//!
//! The tool will only attempt to initialize a card if it has *no* key material
//! on it (absence of keys is detected via the Fingerprint DOs on the card).
//! The tool also assumes that the card is configured with default User and
//! Admin PINs.

use std::collections::HashMap;
use std::io::Write;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::{Parser, ValueEnum};
use openpgp_card::algorithm::AlgoSimple;
use openpgp_card::{card_do::TouchPolicy, Error, KeyType, StatusBytes};
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::{state::Open, state::Transaction, util, Card, PublicKey};
use rand::Rng;
use sequoia_openpgp::cert::CertRevocationBuilder;
use sequoia_openpgp::packet::{Signature, UserID};
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::Serialize;
use sequoia_openpgp::types::ReasonForRevocation;
use sequoia_openpgp::{armor, Cert, Packet};

#[derive(Parser, Debug)]
#[clap(
    name = "openpgp-card-init",
    author = "Heiko Schäfer <heiko@schaefer.name>",
    version,
    about = "An example tool that initializes OpenPGP cards."
)]
pub struct Cli {
    /// Name of the card's user.
    #[clap(long = "name")]
    pub name: String,

    /// Email of the card's user.
    #[clap(long = "email")]
    pub email: String,

    /// Touch policy for the regular key slots.
    ///
    /// This policy will be set for the SIG, DEC, AUT key slots.
    /// The ATT key slot touch policy is always set to `On`.
    #[clap(long = "touch")]
    pub touch_policy: Pol,

    /// Filename of the output zip archive.
    #[clap(long = "output")]
    pub output: String,

    /// Card ident.
    ///
    /// Optional, if unset any blank card that is found will be initialized.
    #[clap(long = "card")]
    pub card: Option<String>,

    /// Expiration of certificate in days.
    ///
    /// Optional, if unset the certificate has no expiration date.
    #[clap(long = "expiration")]
    pub expiration_days: Option<u32>,
}

#[derive(ValueEnum, Debug, Clone)]
#[clap(rename_all = "verbatim")]
pub enum Pol {
    Off,
    On,
    Cached,
    Fixed,
    CachedFixed,
}

impl From<Pol> for TouchPolicy {
    fn from(pol: Pol) -> Self {
        match pol {
            Pol::Off => TouchPolicy::Off,
            Pol::On => TouchPolicy::On,
            Pol::Cached => TouchPolicy::Cached,
            Pol::Fixed => TouchPolicy::Fixed,
            Pol::CachedFixed => TouchPolicy::CachedFixed,
        }
    }
}

// We expect a blank/reset card. These are the default PINs we expect.
const PW1: &[u8] = "123456".as_bytes();
const PW3: &[u8] = "12345678".as_bytes();

fn export(zip_name: &str, files: HashMap<String, Vec<u8>>) -> zip::result::ZipResult<()> {
    let path = std::path::Path::new(zip_name);
    let file = std::fs::File::create(path).unwrap();

    let mut zip = zip::ZipWriter::new(file);

    for (name, data) in files {
        zip.start_file(name, Default::default())?;
        zip.write_all(&data)?;
    }

    zip.finish()?;

    Ok(())
}

fn pem_encode(data: Vec<u8>) -> String {
    const PEM_TAG: &str = "CERTIFICATE";

    let pem = pem::Pem {
        tag: String::from(PEM_TAG),
        contents: data,
    };

    pem::encode(&pem)
}

fn card_empty(open: &Card<Transaction>) -> Result<()> {
    let fp = open.fingerprints()?;
    if fp.signature().is_some() || fp.decryption().is_some() || fp.authentication().is_some() {
        Err(anyhow::anyhow!("Card contains key material"))
    } else {
        Ok(())
    }
}

// Generate one hard and one soft revocation (with the current timestamp)
fn revocations(
    cert: &Cert,
    key_sig: PublicKey,
    open: &mut Card<Transaction>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    fn revoc_to_armored(
        sig: &Signature,
        headers: Option<Vec<(String, String)>>,
    ) -> Result<Vec<u8>> {
        let mut buf = vec![];

        let rev = Packet::Signature(sig.clone());

        let mut writer = armor::Writer::with_headers(
            &mut buf,
            armor::Kind::PublicKey,
            headers.unwrap_or_default(),
        )?;
        rev.export(&mut writer)?;
        writer.finalize()?;

        Ok(buf)
    }

    // helper: use the card to perform a signing operation
    let mut sign_on_card =
        |op: &mut dyn Fn(&mut dyn sequoia_openpgp::crypto::Signer) -> Result<Signature>| {
            // Allow signing on the card
            open.verify_user_for_signing(PW1)?;
            if let Some(mut sign) = open.signing_card() {
                // Card-backed signer for bindings
                let mut card_signer = sign.signer_from_public(key_sig.clone(), &|| {});

                // Make signature, return it
                let s = op(&mut card_signer)?;
                Ok(s)
            } else {
                Err(anyhow::anyhow!("Failed to open card for signing"))
            }
        };

    let now = SystemTime::now();

    let dt: DateTime<Utc> = now.into();
    let date = dt.format("%Y-%m-%d");

    // hard revocation
    let s = sign_on_card(&mut |signer| {
        CertRevocationBuilder::new()
            .set_signature_creation_time(now)?
            .set_reason_for_revocation(
                ReasonForRevocation::KeyCompromised,
                b"Certificate has been compromised",
            )?
            .build(signer, cert, None)
    })?;
    let header = vec![(
        "Comment".to_string(),
        format!("Hard revocation (certificate compromised) ({})", date),
    )];
    let hard = revoc_to_armored(&s, Some(header))?;

    // soft revocation
    let s = sign_on_card(&mut |signer| {
        CertRevocationBuilder::new()
            .set_signature_creation_time(now)?
            .set_reason_for_revocation(ReasonForRevocation::KeyRetired, b"Certificate retired")?
            .build(signer, cert, None)
    })?;
    let header = vec![(
        "Comment".to_string(),
        format!("Soft revocation (certificate retired) ({})", date),
    )];
    let soft = revoc_to_armored(&s, Some(header))?;

    Ok((hard, soft))
}

fn init(
    open: &mut Card<Transaction>,
    name: &str,
    email: &str,
    expiration_days: Option<u32>,
    touch_policy: TouchPolicy,
) -> Result<HashMap<String, Vec<u8>>> {
    // We know that there is no key material on the card
    // -> reset it to a known default state
    open.factory_reset()?;

    // Get card identifier for use in output filenames
    let ident = open.application_identifier()?.ident();
    let file_ident = ident.replace(':', "_");

    println!("- Generating keys ...");
    // Generate key in each slot, set name on card
    open.verify_admin(PW3)?;
    {
        let mut admin = open
            .admin_card()
            .ok_or_else(|| anyhow::anyhow!("couldn't get admin access"))?;

        // generate keys on card
        admin.generate_key_simple(KeyType::Signing, Some(AlgoSimple::RSA4k))?;
        admin.generate_key_simple(KeyType::Decryption, Some(AlgoSimple::RSA4k))?;
        admin.generate_key_simple(KeyType::Authentication, Some(AlgoSimple::RSA4k))?;

        admin.set_name(name)?;
    }

    println!("- Constructing OpenPGP certificate ...");

    // Re-read ARD (to get access to information about the newly generated keys)
    open.reload_ard()?;

    // Export each key slot as PublicKey
    let sig = open.public_key(KeyType::Signing)?;
    let dec = open.public_key(KeyType::Decryption)?;
    let aut = open.public_key(KeyType::Authentication)?;

    // Generate a public key "Cert" representation of the key material

    // make a traditional "combined" User ID from name/email parameters
    let uid = UserID::from_address(name.into(), None, email)?;

    let mut cert = util::make_cert(
        open,
        sig.clone().expect("Signature key missing on card"),
        dec,
        aut,
        Some(PW1),
        &|| {},
        &|| {},
        &[uid.to_string()],
    )?;

    // Set expiration in days (if no expiration parameter is given, cert doesn't expire)
    if let Some(expiration) = expiration_days {
        // Allow signing on the card
        open.verify_user_for_signing(PW1)?;
        if let Some(mut sign) = open.signing_card() {
            // now + expiration days
            let day = Duration::new(24 * 60 * 60, 0);

            // 'expiration' days from now
            let exp: SystemTime = SystemTime::now() + expiration * day;

            // Card-backed signer for bindings
            let mut card_signer = sign
                .signer_from_public(sig.clone().expect("Signature key missing on card"), &|| {});

            // Make signature
            let p = StandardPolicy::new();
            let s = cert.set_expiration_time(&p, None, &mut card_signer, Some(exp))?;

            cert = cert.insert_packets(s)?;

            Ok(())
        } else {
            Err(anyhow::anyhow!("Failed to open card for signing"))
        }?;
    }

    let mut pubkey: Vec<u8> = vec![];
    cert.armored().serialize(&mut pubkey)?;

    // Generate one hard and one soft revocation certificate for this Cert
    let (hard, soft) = revocations(&cert, sig.expect("Signature key missing on card"), open)?;

    println!("- Temporarily disabling touch confirmation for attestation ...");

    {
        // Disable touch confirmation for attestation
        // (to allow non-interactive attestation generation)
        let mut admin = open
            .admin_card()
            .ok_or_else(|| anyhow::anyhow!("couldn't get admin access"))?;
        let res = admin.set_uif(KeyType::Attestation, TouchPolicy::Off);
        if let Err(e) = res {
            if matches!(e, Error::CardStatus(StatusBytes::SecurityRelatedIssues)) {
                println!("  Failed to disable UIF for attestation, touch confirmation needed.")
            } else {
                return Err(e.into());
            }
        }
    }

    println!("- Generating attestations ...");

    {
        // Generate attestations for each key slot, on the card
        open.verify_user_for_signing(PW1)?;
        let mut sign = open
            .signing_card()
            .ok_or_else(|| anyhow::anyhow!("couldn't get sign access"))?;

        sign.generate_attestation(KeyType::Signing, &|| {
            println!("Touch confirmation needed to attest SIG key")
        })?;
        sign.generate_attestation(KeyType::Decryption, &|| {
            println!("Touch confirmation needed to attest DEC key")
        })?;
        sign.generate_attestation(KeyType::Authentication, &|| {
            println!("Touch confirmation needed to attest AUT key")
        })?;
    }

    println!("- Retrieving attestations and attestation certificate ...");

    // Get attestations and attestation certificate from the card
    let att_aut = open.cardholder_certificate()?;
    let att_dec = open.next_cardholder_certificate()?;
    let att_sig = open.next_cardholder_certificate()?;

    let att_cert = open.attestation_certificate()?;

    // Collect data to save as files: pubkey, attestations, attestation cert
    let files = HashMap::from([
        (format!("{}.pub", file_ident), pubkey),
        (format!("{}.revocation.soft", file_ident), soft),
        (format!("{}.revocation.hard", file_ident), hard),
        (
            format!("{}-sig.attestation", file_ident),
            pem_encode(att_sig).as_bytes().to_vec(),
        ),
        (
            format!("{}-dec.attestation", file_ident),
            pem_encode(att_dec).as_bytes().to_vec(),
        ),
        (
            format!("{}-aut.attestation", file_ident),
            pem_encode(att_aut).as_bytes().to_vec(),
        ),
        (
            format!("{}-attestation.cert", file_ident),
            pem_encode(att_cert).as_bytes().to_vec(),
        ),
    ]);

    println!(
        "- Configuring touch confirmation for key slots to '{}' ...",
        touch_policy
    );

    {
        // Set touch confirmation for all key slots to "Fixed"
        // (to allow non-interactive attestation generation)
        let mut admin = open
            .admin_card()
            .ok_or_else(|| anyhow::anyhow!("couldn't get admin access"))?;
        for kt in [
            KeyType::Signing,
            KeyType::Decryption,
            KeyType::Authentication,
        ] {
            admin.set_uif(kt, touch_policy)?;
        }

        // Set touch confirmation for ATT key slot only to "On".
        // (Apparently a "Fixed" UIF setting for ATT can never be changed
        // again, not even with a factory reset, so we ignore resulting errors
        // and just print a warning)
        let res = admin.set_uif(KeyType::Attestation, TouchPolicy::On);
        if let Err(e) = res {
            if matches!(e, Error::CardStatus(StatusBytes::SecurityRelatedIssues)) {
                println!("  Couldn't set UIF for attestation to 'On' (ignoring).")
            } else {
                return Err(e.into());
            }
        } else {
            println!("  Touch confirmation for attestation key slot set to 'On'",);
        }
    }

    println!();
    println!("Setting PINs for OpenPGP on your card:");
    println!();

    // generate and set new PW3/PW1 PINs; print them to stdout
    let mut rng = rand::thread_rng();

    // FIXME: make PIN length/policy configurable?
    let pw1: u64 = rng.gen_range(0..=999_999); // 6 digits, like default
    let pw1 = format!("{:06}", pw1);
    open.change_user_pin(PW1, pw1.as_bytes())?;
    println!("User PIN:    {}", pw1);

    let pw3: u64 = rng.gen_range(0..=99_999_999); // 8 digits, like default
    let pw3 = format!("{:08}", pw3);
    open.change_admin_pin(PW3, pw3.as_bytes())?;
    println!("Admin PIN: {}", pw3);

    // FIXME: we could send an encrypted copy of the PINs to in-house admin,
    // and/or not show the Admin PIN to the user at all?

    println!();
    println!("***         Make sure you don't lose the PINs above!          ***");
    println!("*** Without them you cannot use the OpenPGP keys on this card ***");

    Ok(files)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let backends: Vec<_> = match cli.card {
        None => PcscBackend::cards(None).map(|cards| cards.into_iter().collect())?,
        Some(ident) => vec![PcscBackend::open_by_ident(&ident, None)?],
    };

    if backends.is_empty() {
        return Err(anyhow::anyhow!("No cards found"));
    } else {
        for backend in backends {
            let mut card: Card<Open> = backend.into();
            let mut transaction = card.transaction()?;
            print!(
                "Found card {} .. ",
                transaction.application_identifier()?.ident()
            );

            if card_empty(&transaction).is_ok() {
                // ok, we'll initialize this card
                println!("empty -> initializing!");

                let files = init(
                    &mut transaction,
                    &cli.name,
                    &cli.email,
                    cli.expiration_days,
                    cli.touch_policy.into(),
                )?;

                export(&cli.output, files)?;

                return Ok(()); // stop after initializing one card
            } else {
                println!("NOT empty -> skipping!");
            }
        }
    }

    Ok(())
}
