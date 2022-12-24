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
use anyhow::Result;
use openpgp_card::{KeyType, OpenPgp, card_do::TouchPolicy, Error, StatusBytes};
use openpgp_card::algorithm::AlgoSimple;
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::card::Open;
use openpgp_card_sequoia::util;
use rand::Rng;
use sequoia_openpgp::serialize::Serialize;

const PW1: &[u8] = "123456".as_bytes();
const PW3: &[u8] = "12345678".as_bytes();

fn export(zip_name: &str, files: HashMap<String, Vec<u8>>) -> zip::result::ZipResult<()> {
    let path = std::path::Path::new(zip_name);
    let file = std::fs::File::create(&path).unwrap();

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

fn card_empty(open: &Open) -> Result<()> {
    let fp = open.fingerprints()?;
    if fp.signature().is_some() ||
        fp.decryption().is_some() ||
        fp.authentication().is_some() {
        Err(anyhow::anyhow!("Card contains key material"))
    } else {
        Ok(())
    }
}

fn init(open: &mut Open, name: &str, email: &str, touch_policy: TouchPolicy) -> Result<HashMap<String, Vec<u8>>> {
    // We know that there is no key material on the card
    // -> reset it to a known default state
    open.factory_reset()?;

    // Get card identifier for use in output filenames
    let ident = open.application_identifier()?.ident();
    let file_ident = ident.replace(":", "_");

    println!("- Generating keys ...");
    // Generate key in each slot, set name on card
    open.verify_admin(PW3)?;
    {
        let mut admin = open.admin_card().ok_or(anyhow::anyhow!("couldn't get admin access"))?;

        // generate keys on card
        admin.generate_key_simple(KeyType::Signing, Some(AlgoSimple::Curve25519))?;
        admin.generate_key_simple(KeyType::Decryption, Some(AlgoSimple::Curve25519))?;
        admin.generate_key_simple(KeyType::Authentication, Some(AlgoSimple::Curve25519))?;

        admin.set_name(name)?;
    }

    println!("- Constructing OpenPGP certificate ...");

    // Re-read ARD (to get access to information about the newly generated keys)
    open.reload_ard()?;

    // Export each key slot as PublicKey
    let sig = util::key_slot(open, KeyType::Signing)?;
    let dec = util::key_slot(open, KeyType::Decryption)?;
    let aut = util::key_slot(open, KeyType::Authentication)?;

    // Generate a public key "Cert" representation of the key material
    // FIXME: pass User IDs (split and combined) as parameters
    // FIXME: set expiration?
    let cert = util::make_cert(open, sig.expect("Signature key missing on card"), dec, aut, Some(PW1), &|| {}, &|| {})?;

    let mut pubkey: Vec<u8> = vec![];
    cert.armored().serialize(&mut pubkey)?;

    // FIXME: generate (and export) revocation certificate(s) for this Cert?

    println!("- Temporarily disabling touch confirmation for attestation ...");

    {
        // Disable touch confirmation for attestation
        // (to allow non-interactive attestation generation)
        let mut admin = open.admin_card().ok_or(anyhow::anyhow!("couldn't get admin access"))?;
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
        let mut sign = open.signing_card().ok_or(anyhow::anyhow!("couldn't get sign access"))?;

        sign.generate_attestation(KeyType::Signing, &|| { println!("Touch confirmation needed to attest SIG key") })?;
        sign.generate_attestation(KeyType::Decryption, &|| { println!("Touch confirmation needed to attest DEC key") })?;
        sign.generate_attestation(KeyType::Authentication, &|| { println!("Touch confirmation needed to attest AUT key") })?;
    }

    println!("- Retrieving attestations and attestation certificate ...");

    // Get attestations and attestation certificate from the card
    let att_aut = open.cardholder_certificate()?;
    let att_dec = open.next_cardholder_certificate()?;
    let att_sig = open.next_cardholder_certificate()?;

    let att_cert = open.attestation_certificate()?;

    // Collect data to save as files: pubkey, attestations, attestation cert
    let files =
        HashMap::from([
            (format!("{}.pub", file_ident), pubkey),
            (format!("{}-sig.attestation", file_ident), pem_encode(att_sig).as_bytes().to_vec()),
            (format!("{}-dec.attestation", file_ident), pem_encode(att_dec).as_bytes().to_vec()),
            (format!("{}-aut.attestation", file_ident), pem_encode(att_aut).as_bytes().to_vec()),
            (format!("{}-attestation.cert", file_ident), pem_encode(att_cert).as_bytes().to_vec()),
        ]);

    println!("- Configuring touch confirmation for all key slots ...");
    {
        // Set touch confirmation for all key slots to "Fixed"
        // (to allow non-interactive attestation generation)
        let mut admin = open.admin_card().ok_or(anyhow::anyhow!("couldn't get admin access"))?;
        for kt in [KeyType::Signing, KeyType::Decryption, KeyType::Authentication] {
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
    println!("***          Make sure you don't lose the PINs above!          ***");
    println!("*** Without them you cannot use your OpenPGP keys on this card ***");

    Ok(files)
}

fn main() -> Result<()> {
    let name = "Foo Bar"; // FIXME: clap param
    let email = "foo@example.org"; // FIXME: clap param
    let output = "/tmp/foo.zip"; // FIXME: clap param
    let touch_policy = TouchPolicy::Fixed; // FIXME: clap param

    let cards: Vec<_> = PcscBackend::cards(None).map(|cards| cards.into_iter().collect())?;

    if cards.is_empty() {
        return Err(anyhow::anyhow!("No cards found"));
    } else {
        for mut card in cards {
            let mut pgp = OpenPgp::new(&mut card);
            let mut open = Open::new(pgp.transaction()?)?;
            print!("Found card {} .. ", open.application_identifier()?.ident());

            if card_empty(&open).is_ok() {
                // ok, we'll initialize this card
                println!("empty -> initializing!");

                let files = init(&mut open, name, email, touch_policy)?;

                export(output, files)?;

                return Ok(()); // stop after initializing one card
            } else {
                println!("NOT empty -> skipping!");
            }
        }
    }

    Ok(())
}
