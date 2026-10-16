use anyhow::Context;
use clap::{Arg, ArgAction, ArgMatches, CommandFactory, Parser, Subcommand};
use doctor_kit::{ExtCommand, Extensions, Meta};
use kit::AndroidDoctor;
use reporting::{Emit, ReportArgs, emit};
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;

use crate::detect::refuse_blocking_file;

mod amlogic;
mod apk;
mod archive;
mod audit;
mod avb;
mod avbcert;
mod avbwrite;
mod bootimg;
mod bsdiff;
mod ci;
mod content;
mod detect;
mod dex;
mod doctor;
mod dt;
mod elf;
mod engine;
mod erofsfs;
mod ext4fs;
mod extract;
mod f2fsfs;
mod fec;
mod findings;
mod fix;
mod fstab;
mod fwdiff;
mod hashtree;
mod huawei;
mod imgdiff;
mod info;
mod initrc;
mod kit;
mod lgkdz;
mod libbrotli;
mod lp;
mod manifest;
mod mcp;
mod nokianb0;
mod oem;
mod otameta;
mod otaverify;
mod ozip;
mod pac;
mod payload;
mod permissions;
mod ramdisk;
mod report;
mod reporting;
mod rockchip;
mod sdat;
mod sepolicy;
mod skill;
mod sonysin;
mod sparse;
mod sqliteinfo;
mod term;
#[cfg(test)]
mod testutil;
mod trackers;
mod transfer_list;
mod tree;
mod treeout;
mod vbkernel;

#[derive(Parser)]
#[command(version, about = "Extract and audit Android OTA/ROM images")]
struct Cli {
    /// Never emit colour, even on a terminal (also honours the NO_COLOR environment variable)
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Extract partition images from an OTA zip or directory
    Extract {
        input: PathBuf,
        #[arg(short, long, default_value = "out")]
        output: PathBuf,
        /// Replace existing output files instead of refusing
        #[arg(long)]
        force: bool,
        /// Extract only these partitions or images, comma-separated (e.g. system,boot)
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        /// List what would be extracted, with sizes, and write nothing
        #[arg(long)]
        list: bool,
        /// Also extract the files of every ext2/3/4, erofs or f2fs image into <out>/files/<image>/ (with manifests)
        #[arg(long)]
        files: bool,
        /// Base partition images for an incremental OTA, applied over these to rebuild
        /// partitions. Required for SOURCE_COPY and SOURCE_BSDIFF operations.
        #[arg(long, value_name = "DIR")]
        base: Option<PathBuf>,
        /// Do not fail when some inputs are skipped; report and exit 0
        #[arg(long)]
        allow_partial: bool,
        /// Fail on any file that cannot be classified at all
        #[arg(long)]
        strict: bool,
        /// Suppress progress bars and summary output
        #[arg(short = 'q', long)]
        quiet: bool,
        /// Print debug traces to stderr
        #[arg(short, long)]
        verbose: bool,
        /// Never emit colour
        #[arg(long)]
        no_color: bool,
    },
    /// Print build info from an OTA without extracting
    Info {
        input: PathBuf,
        /// Print all metadata as JSON
        #[arg(long)]
        json: bool,
        /// Also summarise the updater-script and read the signing certificate
        #[arg(long)]
        details: bool,
    },
    /// Describe an Amlogic image container (dt.img, dtbo.img, aml_upgrade_package.img)
    Amlogic {
        /// The Amlogic container to describe
        input: PathBuf,
    },
    /// Show a device tree, dtbo table, or an opaque container header
    Dt {
        /// dt.img, dtbo.img, logo.img, bootloader.img or a boot image
        input: PathBuf,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// dm-verity forward error correction: generate Reed-Solomon parity for a file, verify a file against it, repair a damaged file
    Fec {
        #[command(subcommand)]
        action: FecAction,
    },
    /// Verify an OTA's signatures: the zip's whole-file (signapk) signature and the payload's metadata and payload signatures
    VerifyOta {
        /// An OTA zip, a payload.bin, or a directory holding payload.bin
        input: PathBuf,
        /// Trusted certificate or public key (PEM/DER); without it the package's own otacert is used (integrity only)
        #[arg(long, value_name = "FILE")]
        cert: Option<PathBuf>,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Show the DEX files of an APK (or one .dex): header, tables, classes, methods, fields, strings, references, code
    Dex {
        /// An APK/zip (all classes*.dex) or a .dex file
        input: PathBuf,
        /// List the classes
        #[arg(long)]
        classes: bool,
        /// List the defined methods
        #[arg(long)]
        methods: bool,
        /// List the defined fields
        #[arg(long)]
        fields: bool,
        /// List the strings
        #[arg(long)]
        strings: bool,
        /// For each method, the methods, fields, strings and types its code references
        #[arg(long)]
        refs: bool,
        /// Disassemble the methods of classes whose name contains TEXT
        #[arg(long, value_name = "TEXT")]
        code: Option<String>,
        /// Keep only entries containing TEXT
        #[arg(long, value_name = "TEXT")]
        grep: Option<String>,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Audit one APK file: manifest, package, version, signers, code, issues
    Apk {
        /// An APK file
        input: PathBuf,
        /// Print the doctor/1 JSON envelope instead of text
        #[arg(long)]
        json: bool,
        /// List the archive entries (name, size, compressed size, method) instead of auditing
        #[arg(long, conflicts_with = "cat")]
        files: bool,
        /// Print one archive entry's decompressed bytes to standard output (exit 2 if missing)
        #[arg(long, value_name = "ENTRY", conflicts_with_all = ["json", "files"])]
        cat: Option<String>,
    },
    /// Show a flash manifest (Qualcomm rawprogram*.xml or MediaTek scatter.txt) and check it
    /// against the image files actually present
    Partitions {
        /// Directory holding rawprogram*.xml or scatter.txt, plus the images it references
        input: PathBuf,
        /// Bytes per sector (Qualcomm uses 4096; MediaTek varies by device)
        #[arg(long, default_value = "4096")]
        sector_size: u64,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Show a boot or vendor_boot image's header, and with -o write its kernel, ramdisk, dtb, ...
    Unpack {
        input: PathBuf,
        /// Write the sections (kernel, ramdisk, second, dtb, ...) into this directory
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Print the header as JSON
        #[arg(long)]
        json: bool,
        /// Replace existing files instead of refusing
        #[arg(long)]
        force: bool,
    },
    /// List a directory (or show one file) inside an ext2/3/4, erofs or f2fs image, without extracting it
    Ls {
        image: PathBuf,
        /// Path inside the image (default: the root)
        #[arg(default_value = "/")]
        path: String,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Print one regular file from an ext2/3/4, erofs or f2fs image to standard output
    Cat { image: PathBuf, path: String },
    /// Security posture of firmware images: ADB properties, setuid files, su binaries, init services
    Audit {
        /// Image files (ext2/3/4, erofs or f2fs), or a directory of them (such as an `extract` output)
        #[arg(required = true)]
        images: Vec<PathBuf>,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        report: ReportArgs,
    },
    /// Compare two firmware builds file by file: added, removed and modified files (by SHA-256), mode, owner, capability and SELinux-label changes, property and init-service changes; what got worse becomes findings
    Diff {
        /// The old image, or a directory of images (such as an `extract` output)
        old: PathBuf,
        /// The new image, or a directory of images
        new: PathBuf,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
        /// List only these file changes (comma-separated: added, removed, modified, metadata); findings are unaffected
        #[arg(long, value_delimiter = ',', value_name = "STATUS")]
        only: Vec<String>,
        #[command(flatten)]
        report: ReportArgs,
    },
    /// Write a new vbmeta image (avbtool make_vbmeta_image without descriptors): header, SHA-256 digest and RSA signature
    Avbmake {
        /// The new image; written to <OUTPUT>.part and renamed on success, never in place
        #[arg(short, long)]
        output: PathBuf,
        /// NONE, SHA256_RSA2048, SHA256_RSA4096 or SHA256_RSA8192
        #[arg(long, default_value = "NONE")]
        algorithm: String,
        /// PEM RSA private key (PKCS#8 or PKCS#1); required for the SHA256_RSA algorithms
        #[arg(long)]
        key: Option<PathBuf>,
        /// Rollback index stored in the header
        #[arg(long, default_value_t = 0)]
        rollback_index: u64,
        /// Header flags (avbtool --flags)
        #[arg(long, default_value_t = 0)]
        flags: u32,
        /// Rollback index location (0 for the main vbmeta)
        #[arg(long, default_value_t = 0)]
        rollback_index_location: u32,
        /// Zero-pad the image to a multiple of this many bytes (0 = no padding)
        #[arg(long, default_value_t = 0)]
        padding_size: u64,
        /// Release string in the header (at most 47 bytes); defaults to android-doctor and its version
        #[arg(long)]
        release_string: Option<String>,
        /// Replace the output if it exists
        #[arg(long)]
        force: bool,
        /// Print JSON (the doctor/1 envelope) instead of text
        #[arg(long)]
        json: bool,
    },
    /// Write a copy of a partition image with an AVB hash footer (avbtool add_hash_footer): the image, a vbmeta with one SHA-256 hash descriptor and the footer, padded to --partition-size. The input is never modified
    Avbfooter {
        /// The partition image to read (never modified)
        image: PathBuf,
        /// The new image; written to <OUTPUT>.part and renamed on success
        #[arg(short, long)]
        output: PathBuf,
        /// Partition name in the hash descriptor (avbtool --partition_name)
        #[arg(long)]
        partition_name: String,
        /// Partition size in bytes, a multiple of --block-size; the output is exactly this long
        #[arg(long)]
        partition_size: u64,
        /// Block size the image and the metadata are padded to
        #[arg(long, default_value_t = 4096)]
        block_size: u64,
        /// Salt in hex (avbtool --salt); required, no random salt is drawn
        #[arg(long)]
        salt: String,
        /// NONE, SHA256_RSA2048, SHA256_RSA4096 or SHA256_RSA8192
        #[arg(long, default_value = "NONE")]
        algorithm: String,
        /// PEM RSA private key; required for the SHA256_RSA algorithms
        #[arg(long)]
        key: Option<PathBuf>,
        /// Rollback index stored in the vbmeta header
        #[arg(long, default_value_t = 0)]
        rollback_index: u64,
        /// Header flags
        #[arg(long, default_value_t = 0)]
        flags: u32,
        /// Write a dm-verity hash tree instead of one hash descriptor (avbtool add_hashtree_footer, no FEC)
        #[arg(long)]
        hashtree: bool,
        /// Release string in the header (at most 47 bytes); defaults to android-doctor and its version
        #[arg(long)]
        release_string: Option<String>,
        /// Replace the output if it exists
        #[arg(long)]
        force: bool,
        /// Print JSON (the doctor/1 envelope) instead of text
        #[arg(long)]
        json: bool,
    },
    /// Write a copy of a partition image without its AVB footer and vbmeta (avbtool erase_footer)
    Avberase {
        /// The image to read (never modified)
        image: PathBuf,
        /// The new image; written to <OUTPUT>.part and renamed on success
        #[arg(short, long)]
        output: PathBuf,
        /// Replace the output if it exists
        #[arg(long)]
        force: bool,
        /// Print JSON (the doctor/1 envelope) instead of text
        #[arg(long)]
        json: bool,
    },
    /// Write the AVB public key blob of a PEM RSA key (avbtool extract_public_key) and print its SHA-256 digest
    Avbkey {
        /// A PEM-encoded RSA key file (public or private)
        key: PathBuf,
        /// Write the blob here instead of just printing the digest
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Verify a ChromeOS kernel partition (vboot 2.x): keyblock, kernel preamble and body signatures
    Vbkernel {
        /// A kernel partition image (the CHROMEOS keyblock at offset 0)
        image: PathBuf,
        /// Root public key (PEM) that signed the keyblock; without it the keyblock is not checked
        #[arg(long, value_name = "FILE")]
        key: Option<PathBuf>,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Build AVB certificate files (avb_cert): avbtool make_certificate, make_cert_permanent_attributes, make_cert_metadata, make_cert_unlock_credential
    Avbcert {
        #[command(subcommand)]
        action: AvbcertAction,
    },
    /// Show an AVB vbmeta image (or a partition with an AVB footer): header, key, signature, descriptors, hashes
    Vbmeta {
        image: PathBuf,
        /// Also hash each hashed partition found as <DIR>/<partition>.img and compare
        #[arg(long)]
        images: Option<PathBuf>,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
        /// Verify the RSA signature against this PEM-encoded public key (overrides the key embedded in the image)
        #[arg(short, long)]
        key: Option<PathBuf>,
        /// Check this partition against the signed top-level vbmeta that should cover it
        #[arg(long, value_name = "TOP_LEVEL")]
        vbmeta: Option<PathBuf>,
    },
    /// List a boot image's ramdisk (or a ramdisk file), report its ADB properties, and with -o extract it
    Ramdisk {
        input: PathBuf,
        /// Extract the files into this new directory (symlinks and devices are recorded, not created)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Print the result as JSON
        #[arg(long)]
        json: bool,
        /// Also list every entry
        #[arg(long)]
        list: bool,
    },
    /// List or extract the files of an ext2/3/4, erofs or f2fs image (with SELinux labels), no root needed
    Files {
        image: PathBuf,
        /// Extract into this new directory (files/ plus manifest.json); without it, list only
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Turn a raw image into an Android sparse image
    Sparse {
        /// Raw image to convert
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Block size in bytes, a multiple of 4
        #[arg(long, default_value_t = sparse::DEFAULT_BLOCK_SIZE)]
        block_size: u32,
        /// Replace an existing output file instead of refusing
        #[arg(long)]
        force: bool,
    },
    /// Turn Android sparse image(s) into a raw image
    Unsparse {
        /// Sparse file(s); several files that describe the same image are applied in the order given
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
        /// Replace an existing output file instead of refusing
        #[arg(long)]
        force: bool,
    },
    /// Say what each file is, by its magic bytes (never by name)
    Identify {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Print the result as JSON
        #[arg(long)]
        json: bool,
    },
    /// Staleness verdict from the OTA's build metadata
    Report {
        input: PathBuf,
        /// Print the report as JSON
        #[arg(long)]
        json: bool,
    },
    /// Regenerate the dm-verity hash tree for a partition image rebuilt from a payload
    HashTree {
        /// The partition image
        input: PathBuf,
        /// Write the tree here instead of only verifying it
        #[arg(long, value_name = "OUT")]
        output: Option<PathBuf>,
    },
    /// Run a deterministic health scan on an unpacked firmware directory
    Doctor {
        #[command(subcommand)]
        action: DoctorAction,
    },
    /// Scan, then hand the findings to a coding agent as one fix prompt
    Fix {
        /// Directory to scan (same input as `doctor scan`)
        input: PathBuf,
        /// Agent to launch if its binary is on PATH
        #[arg(long, value_parser = ["claude", "codex", "cursor"], default_value = "claude")]
        agent: String,
        /// Only print the prompt; launch nothing
        #[arg(long)]
        print: bool,
        /// Keep the agent's approval prompts (already the default)
        #[arg(long, conflicts_with = "yolo")]
        safe: bool,
        /// Launch the agent with its approval prompts skipped (unsafe: the firmware is untrusted)
        #[arg(long)]
        yolo: bool,
    },
    /// CI integration: write a GitHub Actions workflow that runs the android-doctor action
    Ci {
        #[command(subcommand)]
        action: CiAction,
    },
    /// Expose android-doctor over the Model Context Protocol (JSON-RPC on stdio)
    Mcp {
        /// Log each request to stderr; stdout stays pure JSON-RPC
        #[arg(long)]
        verbose: bool,
    },
}

/// What `fec` should do.
#[derive(Subcommand)]
enum FecAction {
    /// Write the FEC file (parity + AOSP header) for a file whose size is a multiple of 4096
    Generate {
        input: PathBuf,
        /// Where to write the FEC data
        #[arg(short, long)]
        output: PathBuf,
        /// Parity bytes per RS block (2 to 24; AOSP uses 2)
        #[arg(long, default_value = "2")]
        roots: usize,
        /// Replace an existing output file instead of refusing
        #[arg(long)]
        force: bool,
    },
    /// Check a file against its FEC data; exit 1 if anything differs
    Verify {
        input: PathBuf,
        /// The FEC data made by `fec generate` (or avbroot / AOSP `fec`)
        fec: PathBuf,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Write a corrected copy of a damaged file (up to roots/2 wrong bytes per RS block); exit 1 if some blocks cannot be fixed
    Repair {
        input: PathBuf,
        fec: PathBuf,
        /// Where to write the repaired copy
        #[arg(short, long)]
        output: PathBuf,
        /// Replace an existing output file instead of refusing
        #[arg(long)]
        force: bool,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum AvbcertAction {
    /// Sign a subject public key into a certificate (avbtool make_certificate; the authority key must be RSA-4096)
    Make {
        /// PEM RSA-4096 private key of the authority
        #[arg(long)]
        authority_key: PathBuf,
        /// PEM RSA public key (or private key) of the subject
        #[arg(long)]
        subject_key: PathBuf,
        /// Subject identifier file, hashed into the certificate (a product id for product keys)
        #[arg(long)]
        subject: PathBuf,
        /// Version of the subject key (default: seconds since the epoch, as avbtool)
        #[arg(long)]
        subject_key_version: Option<u64>,
        /// Certificate usage (avbtool's CERT_USAGE_* strings)
        #[arg(long, value_enum, default_value_t = AvbcertUsage::Signing)]
        usage: AvbcertUsage,
        /// Where to write the certificate
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Pack the root authority public key and a 16-byte product id (avbtool make_cert_permanent_attributes)
    PermanentAttributes {
        /// PEM RSA public key of the root authority
        #[arg(long)]
        root_authority_key: PathBuf,
        /// File holding the 16-byte product id
        #[arg(long)]
        product_id: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Pack an intermediate and a product key certificate for a vbmeta (avbtool make_cert_metadata)
    Metadata {
        #[arg(long)]
        intermediate_key_certificate: PathBuf,
        #[arg(long)]
        product_key_certificate: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Pack an unlock credential, signing the 16-byte challenge when given a key (avbtool make_cert_unlock_credential)
    UnlockCredential {
        #[arg(long)]
        intermediate_key_certificate: PathBuf,
        #[arg(long)]
        unlock_key_certificate: PathBuf,
        /// The 16-byte challenge to sign (needs --unlock-key)
        #[arg(long, requires = "unlock_key")]
        challenge: Option<PathBuf>,
        /// PEM RSA-4096 private key that signs the challenge (needs --challenge)
        #[arg(long, requires = "challenge")]
        unlock_key: Option<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum AvbcertUsage {
    Signing,
    Intermediate,
    Unlock,
}

/// What `ci` should do.
#[derive(Subcommand)]
enum CiAction {
    /// Write .github/workflows/android-doctor.yml, pinned to this version, running on pull requests
    Install {
        /// Project root to write into
        #[arg(long, value_name = "DIR", default_value = ".")]
        dir: PathBuf,
        /// Print the workflow and write nothing
        #[arg(long)]
        print: bool,
        /// Replace an existing workflow file instead of refusing
        #[arg(long)]
        force: bool,
        /// Firmware directory to scan, relative to the repository root
        #[arg(long, value_name = "FIRMWARE_DIR", default_value = "firmware")]
        path: String,
        /// Minimum severity that fails the job
        #[arg(long, value_name = "LEVEL", default_value = "critical", value_parser = ci::FAIL_ON)]
        fail_on: String,
    },
}

/// A new output file next to `target`, renamed into place on success; refuses to replace an
/// existing file unless `force`, and never writes through a symlink.
fn write_atomically(
    target: &std::path::Path,
    force: bool,
    write: impl FnOnce(&mut std::fs::File) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    if !force && target.symlink_metadata().is_ok() {
        anyhow::bail!(
            "{} already exists; pass --force to replace it",
            target.display()
        );
    }
    let mut part = target.as_os_str().to_owned();
    part.push(".part");
    let part = PathBuf::from(part);
    let mut f = extract::create_part(&part)?;
    if let Err(e) = write(&mut f) {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    drop(f);
    if let Err(e) = std::fs::rename(&part, target) {
        let _ = std::fs::remove_file(&part);
        return Err(e.into());
    }
    Ok(())
}

fn fec_report(r: &fec::Report) -> (String, serde_json::Value) {
    let text = format!(
        "{} blocks, {} rounds, {} parity bytes per RS block: FEC data {}; {} damaged RS block(s), {} byte(s) corrected, {} uncorrectable",
        r.blocks,
        r.rounds,
        r.roots,
        if r.fec_intact {
            "intact"
        } else {
            "DAMAGED (its hash does not match)"
        },
        r.bad_codewords,
        r.corrected_bytes,
        r.uncorrectable
    );
    let json = serde_json::json!({
        "roots": r.roots, "blocks": r.blocks, "rounds": r.rounds, "fec_intact": r.fec_intact,
        "bad_codewords": r.bad_codewords, "corrected_bytes": r.corrected_bytes, "uncorrectable": r.uncorrectable,
        "ok": r.clean(),
    });
    (text, json)
}

fn fec_command(action: FecAction) -> anyhow::Result<()> {
    let gate = |msg: &str| -> anyhow::Error {
        reporting::Gate {
            code: doctor_core::ExitCode::Findings,
            message: msg.into(),
        }
        .into()
    };
    match action {
        FecAction::Generate {
            input,
            output,
            roots,
            force,
        } => {
            let mut shape = None;
            write_atomically(&output, force, |f| {
                let mut w = std::io::BufWriter::new(f);
                shape = Some(fec::generate(&input, &mut w, roots)?);
                w.flush()?;
                Ok(())
            })?;
            let s = shape.expect("generated");
            print_out(&format!(
                "wrote {} ({} bytes): {} blocks in {} rounds, {} parity bytes per RS block",
                output.display(),
                s.file_len(),
                s.blocks,
                s.rounds,
                s.roots
            ))
        }
        FecAction::Verify {
            input,
            fec: fec_file,
            json,
        } => {
            let r = fec::verify(&input, &fec_file)?;
            let (text, j) = fec_report(&r);
            print_out(&if json {
                serde_json::to_string_pretty(&j)?
            } else {
                text
            })?;
            if r.clean() {
                Ok(())
            } else {
                Err(gate("the file does not match its FEC data"))
            }
        }
        FecAction::Repair {
            input,
            fec: fec_file,
            output,
            force,
            json,
        } => {
            let mut report = None;
            write_atomically(&output, force, |f| {
                report = Some(fec::repair(&input, &fec_file, f)?);
                Ok(())
            })?;
            let r = report.expect("repaired");
            let (text, j) = fec_report(&r);
            print_out(&if json {
                serde_json::to_string_pretty(&j)?
            } else {
                text
            })?;
            if r.uncorrectable > 0 {
                Err(gate("some blocks could not be repaired"))
            } else {
                Ok(())
            }
        }
    }
}

/// `ci install`: print or write the pinned workflow.
fn ci_install(
    dir: &std::path::Path,
    print: bool,
    force: bool,
    path: &str,
    fail_on: &str,
) -> anyhow::Result<()> {
    let text = ci::workflow(env!("CARGO_PKG_VERSION"), path, fail_on)?;
    if print {
        return print_out(text.trim_end());
    }
    let dest = ci::write(dir, &text, force)?;
    print_out(&format!("wrote {}", dest.display()))
}

/// What `doctor` should do.
#[derive(Subcommand)]
enum DoctorAction {
    /// Scan a directory and report findings
    Scan {
        /// Directory to scan
        input: PathBuf,
        /// Print findings as JSON
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        report: ReportArgs,
    },
    /// Write the agent skill into an agent config dir so a coding agent can use this tool
    Install {
        /// Which agent to install for; omit to print where each one would go
        #[arg(long)]
        agent: Option<String>,
        /// Print the skill instead of writing it
        #[arg(long)]
        print_only: bool,
    },
}

/// `doctor scan`: report findings for a directory, as text or JSON.
fn doctor_scan(
    input: &std::path::Path,
    json: bool,
    report: &ReportArgs,
    no_color: bool,
) -> anyhow::Result<()> {
    let all = findings::from_doctor(doctor::scan_scoped(input)?);
    emit(
        Emit {
            json,
            fail_default: Some(findings::Severity::Critical),
            no_color,
            domain_replaces_face: false,
        },
        report,
        all,
        || serde_json::json!({}),
        || None,
    )
}
/// `doctor install`: write the agent skill, or show where it would go.
fn doctor_install(agent: Option<String>, print_only: bool) -> anyhow::Result<()> {
    if print_only {
        return print_out(&skill::content());
    }
    match agent {
        None => {
            for a in skill::Agent::all() {
                println!("{}: {}", a.name(), a.skill_dir().display());
            }
            println!("\npass --agent <name> to write, or --print to see the skill");
            Ok(())
        }
        Some(name) => {
            let all = skill::Agent::all();
            let name = if name == "claude" {
                "claude-code".into()
            } else {
                name
            };
            let Some(a) = all.iter().find(|a| a.name() == name) else {
                anyhow::bail!(
                    "unknown agent {name:?}; expected one of {}",
                    skill::Agent::all()
                        .iter()
                        .map(|a| a.name())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            };
            let dest = skill::install_in(*a, &a.skill_dir())?;
            let mut out = format!("wrote {}", dest.display());
            if let Some(extra) = skill::install_project(*a, &std::env::current_dir()?)? {
                out.push_str(&format!("\nwrote {}", extra.display()));
            }
            print_out(&out)
        }
    }
}
/// Regenerate a dm-verity hash tree from a partition image's own AVB hashtree descriptor.
fn hash_tree_command(
    input: &std::path::Path,
    output: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let data = std::fs::read(input)?;
    // Reuse the same parse path the vbmeta command uses, so there is one reader, not two.
    let vbmeta = avb::read_input(input, None)?;
    let Some(desc) = vbmeta.descriptors.iter().find_map(|d| match d {
        avb::Descriptor::Hashtree(h) => Some(h),
        _ => None,
    }) else {
        anyhow::bail!(
            "{} has no hash tree descriptor to rebuild from",
            input.display()
        );
    };
    let end = (desc.image_size as usize).min(data.len());
    let tree = hashtree::hash_tree(&data[..end], desc)?;
    match output {
        Some(p) => {
            std::fs::write(p, &tree)?;
            print_out(&format!(
                "wrote {} bytes of hash tree to {}",
                tree.len(),
                p.display()
            ))
        }
        None => print_out(&format!(
            "hash tree recomputed and verified against the descriptor root ({} bytes)",
            tree.len()
        )),
    }
}
fn identify(paths: &[PathBuf], json: bool) -> anyhow::Result<()> {
    let mut failed = 0;
    let mut rows = Vec::new();
    for path in paths {
        match detect::identify_path(path) {
            Ok(i) => rows.push(serde_json::json!({
                "path": path.display().to_string(),
                "id": i.id,
                "description": i.description,
            })),
            Err(e) => {
                failed += 1;
                rows.push(serde_json::json!({
                    "path": path.display().to_string(),
                    "error": format!("{e:#}"),
                }));
            }
        }
    }
    let text = if json {
        serde_json::to_string_pretty(&rows)?
    } else {
        rows.iter()
            .map(|r| match r["error"].as_str() {
                Some(e) => format!("{}: error: {e}", r["path"].as_str().unwrap_or("")),
                None => format!(
                    "{}: {}",
                    r["path"].as_str().unwrap_or(""),
                    r["description"].as_str().unwrap_or("")
                ),
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    print_out(&text)?;
    if failed > 0 {
        anyhow::bail!("{failed} of {} paths could not be read", paths.len());
    }
    Ok(())
}

fn ramdisk_command(
    input: &std::path::Path,
    output: Option<&std::path::Path>,
    json: bool,
    list: bool,
) -> anyhow::Result<()> {
    let found = ramdisk::read_input(input, output)?;
    let mut failed = 0;
    let text = if json {
        let rows: Vec<_> = found
            .iter()
            .map(|f| match &f.report {
                Ok(r) => serde_json::json!({"ramdisk": f.name, "result": r.to_json()}),
                Err(e) => {
                    failed += 1;
                    serde_json::json!({"ramdisk": f.name, "error": format!("{e:#}")})
                }
            })
            .collect();
        serde_json::to_string_pretty(&rows)?
    } else {
        found
            .iter()
            .map(|f| match &f.report {
                Ok(r) => format!("{}:\n{}", f.name, r.to_text(list)),
                Err(e) => {
                    failed += 1;
                    format!("{}: error: {e:#}", f.name)
                }
            })
            .collect::<Vec<_>>()
            .join("\n\n")
    };
    print_out(&text)?;
    anyhow::ensure!(
        failed == 0,
        "{failed} of {} ramdisks could not be read",
        found.len()
    );
    Ok(())
}

pub fn print_out(text: &str) -> anyhow::Result<()> {
    match writeln!(std::io::stdout(), "{text}") {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()), // e.g. `| head`
        other => Ok(other?),
    }
}

/// Run one parsed command. The error path (below, in `dispatch`) renders it once and picks the exit code.
fn run_command(cli: Cli) -> anyhow::Result<()> {
    let no_color = cli.no_color;
    match cli.command {
        Command::HashTree { input, output } => hash_tree_command(&input, output.as_deref()),
        Command::Extract {
            input,
            output,
            force,
            only,
            list,
            files,
            allow_partial,
            base,
            strict,
            quiet,
            verbose,
            no_color,
        } => {
            let opts = extract::ExtractOptions {
                base,
                force,
                only: (!only.is_empty()).then_some(only),
                list,
                files,
                allow_partial,
                strict,
                quiet,
                verbose,
                no_color,
            };
            extract::run(&input, &output, &opts)
        }
        Command::Info {
            input,
            json,
            details,
        } => info_command(&input, json, details),
        Command::Unpack {
            input,
            output,
            json,
            force,
        } => {
            // A 32-bit ARM zImage is not a boot image, but it has a header the bootloader reads,
            // so `unpack` reports it rather than refusing it as "not a boot image".
            if let Some(info) = bootimg::zimage_info(&input)? {
                let text = if json {
                    serde_json::to_string_pretty(&bootimg::zimage_to_json(&info))?
                } else {
                    bootimg::zimage_to_text(&info)
                };
                print_out(&text)
            } else {
                let image = bootimg::read(&input)?;
                if let Some(dir) = &output {
                    bootimg::write_sections(&input, &image, dir, force)?;
                }
                let text = if json {
                    serde_json::to_string_pretty(&bootimg::to_json(&image))?
                } else {
                    bootimg::to_text(&image)
                };
                print_out(&text)
            }
        }
        Command::Ramdisk {
            input,
            output,
            json,
            list,
        } => ramdisk_command(&input, output.as_deref(), json, list),
        Command::Ls { image, path, json } => ls_command(&image, &path, json),
        Command::Cat { image, path } => cat_command(&image, &path),
        Command::Audit {
            images,
            json,
            report,
        } => audit_command(&images, json, &report, no_color),
        Command::Diff {
            old,
            new,
            json,
            only,
            report,
        } => diff_command(&old, &new, json, &only, &report, no_color),
        Command::Avbmake {
            output,
            algorithm,
            key,
            rollback_index,
            flags,
            rollback_index_location,
            padding_size,
            release_string,
            force,
            json,
        } => {
            let release = release_string
                .unwrap_or_else(|| format!("android-doctor {}", env!("CARGO_PKG_VERSION")));
            let opts = avbwrite::Options {
                algorithm: &algorithm,
                rollback_index,
                flags,
                rollback_index_location,
                padding_size,
                release_string: &release,
            };
            make_vbmeta_command(&output, key.as_deref(), &opts, force, json)
        }
        Command::Avbfooter {
            image,
            output,
            partition_name,
            partition_size,
            block_size,
            salt,
            algorithm,
            key,
            rollback_index,
            flags,
            hashtree,
            release_string,
            force,
            json,
        } => {
            let release = release_string
                .unwrap_or_else(|| format!("android-doctor {}", env!("CARGO_PKG_VERSION")));
            let salt = avbwrite::unhex(&salt)?;
            let fo = avbwrite::FooterOptions {
                partition: &partition_name,
                partition_size,
                block_size,
                salt: &salt,
                hashtree,
            };
            let opts = avbwrite::Options {
                algorithm: &algorithm,
                rollback_index,
                flags,
                rollback_index_location: 0,
                padding_size: 0,
                release_string: &release,
            };
            avbfooter_command(&image, &output, &fo, &opts, key.as_deref(), force, json)
        }
        Command::Avberase {
            image,
            output,
            force,
            json,
        } => avberase_command(&image, &output, force, json),
        Command::Avbkey { key, output, json } => avbkey_command(&key, output.as_deref(), json),
        Command::Vbkernel { image, key, json } => {
            let root = match key {
                Some(k) => Some(avb::read_key(&k)?),
                None => None,
            };
            let r = vbkernel::verify(&image, root.as_ref())?;
            print_out(&if json {
                serde_json::to_string_pretty(&r.to_json())?
            } else {
                r.to_text()
            })?;
            if r.any_invalid() {
                return Err(reporting::Gate {
                    code: doctor_core::ExitCode::Findings,
                    message: "a kernel signature does not verify".into(),
                }
                .into());
            }
            Ok(())
        }
        Command::Avbcert { action } => avbcert_command(action),
        Command::Vbmeta {
            image,
            images,
            json,
            key,
            vbmeta,
        } => vbmeta_command(
            &image,
            images.as_deref(),
            json,
            key.as_deref(),
            vbmeta.as_deref(),
        ),
        Command::Files {
            image,
            output,
            json,
        } => files_command(&image, output.as_deref(), json),
        Command::Sparse {
            input,
            output,
            block_size,
            force,
        } => sparse::pack_run(&input, &output, block_size, force),
        Command::Unsparse {
            inputs,
            output,
            force,
        } => sparse::run(&inputs, &output, force),
        Command::Identify { paths, json } => identify(&paths, json),
        Command::Partitions {
            input,
            sector_size,
            json,
        } => partitions_command(&input, sector_size, json),
        Command::Dt { input, json } => dt_command(&input, json),
        Command::Fec { action } => fec_command(action),
        Command::VerifyOta { input, cert, json } => {
            let r = otaverify::verify(&input, cert.as_deref())?;
            print_out(&if json {
                serde_json::to_string_pretty(&r.to_json())?
            } else {
                r.to_text()
            })?;
            if r.any_invalid() {
                return Err(reporting::Gate {
                    code: doctor_core::ExitCode::Findings,
                    message: "an OTA signature does not verify".into(),
                }
                .into());
            }
            Ok(())
        }
        Command::Dex {
            input,
            classes,
            methods,
            fields,
            strings,
            refs,
            code,
            grep,
            json,
        } => {
            let sel = dex::Select {
                classes,
                methods,
                fields,
                strings,
                refs,
                code,
                grep,
            };
            let files = dex::read_input(&input)?;
            let dexes = files
                .iter()
                .map(|(n, b)| anyhow::Context::context(dex::parse(n, b), n.clone()))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let datas: Vec<Vec<u8>> = files.into_iter().map(|f| f.1).collect();
            print_out(&if json {
                serde_json::to_string_pretty(&dex::to_json(&dexes, &datas, &sel))?
            } else {
                dex::to_text(&dexes, &datas, &sel)
            })
        }
        Command::Apk {
            input,
            json,
            files,
            cat,
        } => apk_command(&input, json, files, cat.as_deref()),
        Command::Amlogic { input } => {
            let img = amlogic::describe_file(&input)?;
            print_out(&amlogic::to_text(&img, &display_name(&input)))
        }
        Command::Report { input, json } => {
            let meta = info::read(&input)?;
            let parts = extract::partition_names(&input)?;
            let report = report::analyze(&meta, parts, report::today_days())?;
            print_out(&report::render(&report, json)?)
        }
        Command::Doctor { action } => match action {
            DoctorAction::Scan {
                input,
                json,
                report,
            } => doctor_scan(&input, json, &report, no_color),
            DoctorAction::Install { agent, print_only } => doctor_install(agent, print_only),
        },
        Command::Fix {
            input,
            agent,
            print,
            safe: _,
            yolo,
        } => fix::run(&input, &agent, print, yolo),
        Command::Ci { action } => match action {
            CiAction::Install {
                dir,
                print,
                force,
                path,
                fail_on,
            } => ci_install(&dir, print, force, &path, &fail_on),
        },
        Command::Mcp { verbose } => {
            doctor_kit::mcp::serve_verbose(&kit::AndroidDoctor::default(), verbose)
                .map_err(Into::into)
        }
    }
}

/// Run a parsed command line and turn its outcome into the process exit code.
fn dispatch(cli: Cli) -> u8 {
    let no_color = cli.no_color;
    // Unified error rendering (issue #77): a one-line headline, then the indented cause
    // chain. Printed once, here.
    match run_command(cli) {
        Ok(()) => 0,
        Err(e) => match e.downcast_ref::<reporting::Gate>() {
            Some(g) => {
                // an empty message: the kit already said what went wrong
                if !g.message.is_empty() {
                    eprintln!("{e}");
                }
                g.code.code()
            }
            None => {
                eprintln!(
                    "{}",
                    term::Renderer::new(term::Style::detect(no_color)).error(&e)
                );
                // doctor/1: the tool could not run (bad input, unreadable file) is 2.
                doctor_core::ExitCode::Error.code()
            }
        },
    }
}

type Ext = ExtCommand<AndroidDoctor>;

fn run_cli(_: &AndroidDoctor, _: &ArgMatches) -> Result<u8, String> {
    Ok(dispatch(Cli::parse()))
}

/// `scan` and `install` are doctor-kit's names for `doctor scan` / `doctor install`; they stay
/// hidden aliases so the kit's commands exist but nothing new is advertised.
fn run_alias(_: &AndroidDoctor, _: &ArgMatches) -> Result<u8, String> {
    let mut argv: Vec<String> = std::env::args().collect();
    if let Some(i) = argv
        .iter()
        .skip(1)
        .position(|a| a == "scan" || a == "install")
    {
        argv.insert(i + 1, "doctor".into());
    }
    Ok(dispatch(Cli::parse_from(argv)))
}

#[cfg(feature = "shell")]
fn shell_command() -> clap::Command {
    clap::Command::new("shell")
        .about("Browse the findings of a firmware directory or image in an interactive shell")
        .arg(
            Arg::new("input")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf))
                .help("Firmware directory or image"),
        )
        .arg(
            Arg::new("command")
                .short('c')
                .help("Run these `;`-separated commands and exit"),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .action(ArgAction::SetTrue)
                .help("Print every reply as one JSON record (for agents)"),
        )
}

#[cfg(feature = "explore")]
fn explore_command() -> clap::Command {
    clap::Command::new("explore")
        .about("Browse the findings of a firmware directory or image in a full-screen explorer")
        .arg(
            Arg::new("input")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf))
                .help("Firmware directory or image"),
        )
}

/// `shell` and `explore` need something to look at; say so instead of showing an empty tree.
#[cfg(any(feature = "shell", feature = "explore"))]
fn subject_exists(d: &AndroidDoctor) -> Result<(), String> {
    match &d.subject {
        Some(p) if !p.exists() => Err(format!("{}: no such file or directory", p.display())),
        _ => Ok(()),
    }
}

fn extensions() -> Extensions<AndroidDoctor> {
    // Built, so the global --no-color sits in each subcommand where clap always put it.
    let mut root = Cli::command();
    root.build();
    let hidden = |path: &[&str], name: &'static str| {
        let mut c = root.clone();
        for p in path {
            c = c.find_subcommand(p).expect("subcommand exists").clone();
        }
        c.name(name).hide(true)
    };
    let mut commands: Vec<Ext> = root
        .get_subcommands()
        .filter(|c| c.get_name() != "help")
        .cloned()
        .enumerate()
        .map(|(i, c)| Ext {
            command: c.display_order(i),
            run: run_cli,
        })
        .collect();
    commands.push(Ext {
        command: hidden(&["doctor", "scan"], "scan"),
        run: run_alias,
    });
    commands.push(Ext {
        command: hidden(&["doctor", "install"], "install"),
        run: run_alias,
    });
    #[cfg(feature = "shell")]
    commands.push(Ext {
        command: shell_command().display_order(100),
        run: |d, m| {
            subject_exists(d)?;
            doctor_kit::repl::run(
                d,
                d.ctx(),
                m.get_one::<String>("command").map(String::as_str),
                m.get_flag("json"),
            )
        },
    });
    #[cfg(feature = "explore")]
    commands.push(Ext {
        command: explore_command().display_order(101),
        run: |d, _| {
            subject_exists(d)?;
            doctor_kit::tui::run(d, d.ctx()).map(|_| 0)
        },
    });
    Extensions {
        commands,
        global_args: vec![
            Arg::new("no_color")
                .long("no-color")
                .action(ArgAction::SetTrue)
                .help("Never emit colour, even on a terminal (also honours the NO_COLOR environment variable)"),
        ],
        ..Extensions::default()
    }
}

fn main() -> std::process::ExitCode {
    doctor_kit::run_with(Meta::of(&AndroidDoctor::default()), extensions(), |m| {
        let mut d = AndroidDoctor::default();
        if let Some((name, sm)) = m.subcommand()
            && matches!(name, "shell" | "explore")
        {
            d.subject = sm.get_one::<PathBuf>("input").cloned();
        }
        Ok(d)
    })
}

/// `partitions`: show a flash manifest and cross-check it against the images present.
fn partitions_command(input: &std::path::Path, sector_size: u64, json: bool) -> anyhow::Result<()> {
    let m = manifest::read(input, sector_size)?;
    let text = if json {
        serde_json::to_string_pretty(&manifest_json(&m))?
    } else {
        manifest::to_text(&m)
    };
    print_out(&text)?;
    // A manifest that references a missing image is not a usable firmware set.
    if !m.missing_images.is_empty() {
        return Err(reporting::Gate {
            code: doctor_core::ExitCode::Findings,
            message: format!(
                "{} manifest image(s) are missing from {}",
                m.missing_images.len(),
                input.display()
            ),
        }
        .into());
    }
    Ok(())
}

/// One manifest as JSON.
fn manifest_json(m: &manifest::Manifest) -> serde_json::Value {
    serde_json::json!({
        "format": m.kind.name(),
        "sector_size": m.sector_size,
        "partitions": m.partitions.iter().map(|p| serde_json::json!({
            "label": p.label,
            "filename": p.filename,
            "start_sector": p.start_sector,
            "num_sectors": p.num_sectors,
            "size_bytes": p.num_sectors * m.sector_size,
            "sparse": p.sparse,
        })).collect::<Vec<_>>(),
        "missing_images": m.missing_images,
        "unreferenced_images": m.unreferenced_images,
    })
}

/// `dt`: device tree, dtbo table, or a bounded description of a container we do not parse.
fn dt_command(input: &std::path::Path, json: bool) -> anyhow::Result<()> {
    let text = if json {
        serde_json::to_string_pretty(&dt::to_json(input)?)?
    } else {
        dt::describe_file(input)?
    };
    print_out(&text)
}

/// File name of a path, for messages.
fn display_name(p: &std::path::Path) -> String {
    p.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

fn files_command(
    image: &std::path::Path,
    output: Option<&std::path::Path>,
    json: bool,
) -> anyhow::Result<()> {
    let fs = tree::Tree::open(image)?;
    let entries = match output {
        Some(out) => fs.extract(out, None)?,
        None => fs.entries()?,
    };
    let text = if json {
        serde_json::to_string_pretty(&tree::manifest(&entries))?
    } else {
        entries
            .iter()
            .map(entry_line)
            .collect::<Vec<_>>()
            .join("\n")
    };
    print_out(&text)
}

/// `avbmake`: write a new vbmeta image to a new path. With `--json` it prints the doctor/1
/// envelope; this command produces no findings, so `score` is always 100 ("good").
fn make_vbmeta_command(
    output: &std::path::Path,
    key: Option<&std::path::Path>,
    opts: &avbwrite::Options,
    force: bool,
    json: bool,
) -> anyhow::Result<()> {
    use std::io::Read;

    let private = match key {
        Some(k) => {
            refuse_blocking_file(k)?;
            if k.is_dir() {
                anyhow::bail!("{} is a directory, not a key file", k.display());
            }
            let mut pem = String::new();
            std::fs::File::open(k)
                .with_context(|| format!("opening {}", k.display()))?
                .read_to_string(&mut pem)?;
            Some(avbwrite::parse_private_key(&pem)?)
        }
        None => None,
    };
    let image = avbwrite::make_vbmeta(opts, private.as_ref())?;
    write_atomically(output, force, |f| {
        f.write_all(&image)?;
        Ok(())
    })?;
    let text = if json {
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "doctor/1",
            "tool": "android-doctor",
            "version": env!("CARGO_PKG_VERSION"),
            "exit_code": 0,
            "score": {"value": 100, "label": "good", "model": "android-doctor/1", "coverage_gaps": 0},
            "findings": [],
            "data": {
                "output": output.display().to_string(),
                "algorithm": opts.algorithm,
                "size": image.len(),
                "sha256": avb::hex(&Sha256::digest(&image)),
                "rollback_index": opts.rollback_index,
                "flags": opts.flags,
                "rollback_index_location": opts.rollback_index_location,
                "padding_size": opts.padding_size,
                "release_string": opts.release_string,
            },
        }))?
    } else {
        format!(
            "wrote {} bytes ({}) to {}",
            image.len(),
            opts.algorithm,
            output.display()
        )
    };
    print_out(&text)
}

/// Read a PEM RSA private key for signing, if one was given.
fn load_key(key: Option<&std::path::Path>) -> anyhow::Result<Option<rsa::RsaPrivateKey>> {
    use std::io::Read;
    let Some(k) = key else {
        return Ok(None);
    };
    refuse_blocking_file(k)?;
    if k.is_dir() {
        anyhow::bail!("{} is a directory, not a key file", k.display());
    }
    let mut pem = String::new();
    std::fs::File::open(k)
        .with_context(|| format!("opening {}", k.display()))?
        .read_to_string(&mut pem)?;
    Ok(Some(avbwrite::parse_private_key(&pem)?))
}

/// `avbfooter`: write a partition image with an AVB hash footer to a new path.
fn avbfooter_command(
    image: &std::path::Path,
    output: &std::path::Path,
    fo: &avbwrite::FooterOptions,
    opts: &avbwrite::Options,
    key: Option<&std::path::Path>,
    force: bool,
    json: bool,
) -> anyhow::Result<()> {
    refuse_blocking_file(image)?;
    let data = std::fs::read(image).with_context(|| format!("reading {}", image.display()))?;
    let private = load_key(key)?;
    let out = avbwrite::hash_footer(&data, fo, opts, private.as_ref())?;
    write_atomically(output, force, |f| {
        f.write_all(&out)?;
        Ok(())
    })?;
    let text = if json {
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "doctor/1",
            "tool": "android-doctor",
            "version": env!("CARGO_PKG_VERSION"),
            "exit_code": 0,
            "score": {"value": 100, "label": "good", "model": "android-doctor/1", "coverage_gaps": 0},
            "findings": [],
            "data": {
                "output": output.display().to_string(),
                "partition": fo.partition,
                "partition_size": fo.partition_size,
                "original_size": data.len(),
                "algorithm": opts.algorithm,
                "sha256": avb::hex(&Sha256::digest(&out)),
            },
        }))?
    } else {
        format!(
            "wrote {} bytes ({}) to {}",
            out.len(),
            opts.algorithm,
            output.display()
        )
    };
    print_out(&text)
}

/// `avberase`: write a partition image without its AVB footer and vbmeta to a new path.
fn avberase_command(
    image: &std::path::Path,
    output: &std::path::Path,
    force: bool,
    json: bool,
) -> anyhow::Result<()> {
    refuse_blocking_file(image)?;
    let data = std::fs::read(image).with_context(|| format!("reading {}", image.display()))?;
    let out = avbwrite::erase_footer(&data)?;
    write_atomically(output, force, |f| {
        f.write_all(&out)?;
        Ok(())
    })?;
    let text = if json {
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "doctor/1",
            "tool": "android-doctor",
            "version": env!("CARGO_PKG_VERSION"),
            "exit_code": 0,
            "score": {"value": 100, "label": "good", "model": "android-doctor/1", "coverage_gaps": 0},
            "findings": [],
            "data": {
                "output": output.display().to_string(),
                "original_size": data.len(),
                "size": out.len(),
                "sha256": avb::hex(&Sha256::digest(&out)),
            },
        }))?
    } else {
        format!("wrote {} bytes to {}", out.len(), output.display())
    };
    print_out(&text)
}

/// `avbkey`: write the AVB public key blob of a PEM RSA key and print its SHA-256.
fn avbkey_command(
    key: &std::path::Path,
    output: Option<&std::path::Path>,
    json: bool,
) -> anyhow::Result<()> {
    use std::io::Read;

    refuse_blocking_file(key)?;
    if key.is_dir() {
        anyhow::bail!("{} is a directory, not a key file", key.display());
    }
    let mut pem = String::new();
    let mut f = std::fs::File::open(key).with_context(|| format!("opening {}", key.display()))?;
    f.read_to_string(&mut pem)?;
    let pubkey = avb::load_rsa_public_key(&pem)?;
    let bits = pubkey.n().bits() as u32;
    let blob = avb::public_key_blob(pubkey.n());
    let sha = avb::hex(&Sha256::digest(&blob));
    if let Some(out) = output {
        write_atomically(out, false, |f| {
            f.write_all(&blob)?;
            Ok(())
        })?;
    }
    let key_str = key.display().to_string();
    let text = if json {
        serde_json::to_string_pretty(&serde_json::json!({
            "key": key_str,
            "bits": bits,
            "sha256": sha,
            "output": output.map(|p| p.display().to_string()),
        }))?
    } else {
        format!("{sha}  {key_str}")
    };
    print_out(&text)?;
    Ok(())
}

/// `avbcert`: write one avb_cert structure (see `avbcert.rs` for the layouts). Issue #185.
fn avbcert_command(action: AvbcertAction) -> anyhow::Result<()> {
    use avbcert as ac;
    let (output, bytes) = match action {
        AvbcertAction::Make {
            authority_key,
            subject_key,
            subject,
            subject_key_version,
            usage,
            output,
        } => {
            let authority = ac::load_private_key(&authority_key)?;
            let subject_pub = ac::load_public_key(&subject_key)?;
            let id = ac::read_input(&subject)?;
            let usage = match usage {
                AvbcertUsage::Signing => ac::USAGE_SIGNING,
                AvbcertUsage::Intermediate => ac::USAGE_INTERMEDIATE,
                AvbcertUsage::Unlock => ac::USAGE_UNLOCK,
            };
            let version = match subject_key_version {
                Some(v) => v,
                None => std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
            };
            let cert = ac::make_certificate(&authority, &subject_pub, &id, usage, version)?;
            (output, cert)
        }
        AvbcertAction::PermanentAttributes {
            root_authority_key,
            product_id,
            output,
        } => {
            let root = ac::load_public_key(&root_authority_key)?;
            let id = ac::read_input(&product_id)?;
            (output, ac::permanent_attributes(&root, &id)?)
        }
        AvbcertAction::Metadata {
            intermediate_key_certificate,
            product_key_certificate,
            output,
        } => {
            let intermediate = ac::read_input(&intermediate_key_certificate)?;
            let product = ac::read_input(&product_key_certificate)?;
            (output, ac::metadata(&intermediate, &product)?)
        }
        AvbcertAction::UnlockCredential {
            intermediate_key_certificate,
            unlock_key_certificate,
            challenge,
            unlock_key,
            output,
        } => {
            let intermediate = ac::read_input(&intermediate_key_certificate)?;
            let unlock = ac::read_input(&unlock_key_certificate)?;
            let challenge = challenge.as_deref().map(ac::read_input).transpose()?;
            let key = unlock_key
                .as_deref()
                .map(ac::load_private_key)
                .transpose()?;
            let cred =
                ac::unlock_credential(&intermediate, &unlock, challenge.as_deref(), key.as_ref())?;
            (output, cred)
        }
    };
    write_atomically(&output, false, |f| {
        f.write_all(&bytes)?;
        Ok(())
    })?;
    print_out(&format!("{} bytes  {}", bytes.len(), output.display()))
}

fn vbmeta_command(
    image: &std::path::Path,
    images: Option<&std::path::Path>,
    json: bool,
    key: Option<&std::path::Path>,
    top_level: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let external_key = if let Some(k) = key {
        Some(avb::read_key(k)?)
    } else {
        None
    };
    let mut meta = avb::read_input(image, external_key.as_ref())?;
    if let Some(top) = top_level {
        let top_meta = anyhow::Context::with_context(avb::read_input(top, None), || {
            format!("reading the top-level vbmeta {}", top.display())
        })?;
        meta.coverage = Some(avb::check_coverage(&top_meta, &meta, image)?);
    }
    let checks = match images {
        Some(dir) => avb::verify_images(&meta, dir)?,
        None => Vec::new(),
    };
    let chained_findings: Vec<_> = images
        .map(|d| meta.cross_check_chained(d))
        .unwrap_or_default();
    let text = if json {
        let mut v = meta.to_json(&checks);
        v["findings"] = serde_json::json!(
            meta.findings()
                .into_iter()
                .chain(chained_findings.into_iter())
                .map(|f| serde_json::json!({
                    "severity": f.severity.name(),
                    "rule": f.rule,
                    "detail": f.detail,
                }))
                .collect::<Vec<_>>()
        );
        serde_json::to_string_pretty(&v)?
    } else {
        let mut t = meta.to_text(&checks);
        for f in &chained_findings {
            t.push_str(&format!(
                "\n  [{}] {}: {}\n",
                f.severity.name(),
                f.rule,
                f.detail
            ));
        }
        t
    };
    print_out(&text)?;
    if meta.any_failure(&checks) {
        return Err(reporting::Gate {
            code: doctor_core::ExitCode::Findings,
            message: "the digest, signature, or a partition hash does not match".into(),
        }
        .into());
    }
    Ok(())
}

fn entry_line(e: &tree::Entry) -> String {
    let label = e
        .xattrs
        .iter()
        .find(|(k, _)| k == "security.selinux")
        .map_or("", |(_, v)| v.as_str());
    let link = e
        .link
        .as_deref()
        .map(|l| format!(" -> {l}"))
        .unwrap_or_default();
    let name = if e.path.is_empty() {
        "/"
    } else {
        e.path.as_str()
    };
    format!(
        "{:7} {:04o} {:>5} {:>5} {:>11} {}{} {}",
        e.kind.name(),
        e.mode,
        e.uid,
        e.gid,
        e.size,
        name,
        link,
        label
    )
}

fn ls_command(image: &std::path::Path, path: &str, json: bool) -> anyhow::Result<()> {
    let entries = tree::Tree::open(image)?.list_dir(path)?;
    let text = if json {
        serde_json::to_string_pretty(&entries.iter().map(tree::entry_json).collect::<Vec<_>>())?
    } else {
        entries
            .iter()
            .map(entry_line)
            .collect::<Vec<_>>()
            .join("\n")
    };
    print_out(&text)
}

fn cat_command(image: &std::path::Path, path: &str) -> anyhow::Result<()> {
    let fs = tree::Tree::open(image)?;
    let mut out = std::io::stdout().lock();
    match fs.cat_path(path, &mut out) {
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe) =>
        {
            Ok(())
        }
        r => r,
    }
}

fn apk_command(
    input: &std::path::Path,
    json: bool,
    files: bool,
    cat: Option<&str>,
) -> anyhow::Result<()> {
    use std::fs::File;
    use std::io::{Read, Write};

    // Refuse directories, FIFOs and devices: opening a FIFO would block forever
    if input.is_dir() {
        anyhow::bail!("{} is a directory, not an APK file", input.display());
    }
    if !input.is_file() {
        anyhow::bail!("{} is not a regular file", input.display());
    }

    // Read the APK bytes, bounded (hostile input)
    let mut bytes = Vec::new();
    let f = File::open(input).with_context(|| format!("reading {}", input.display()))?;
    f.take(apk::MAX_APK_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", input.display()))?;
    if bytes.len() as u64 > apk::MAX_APK_BYTES {
        anyhow::bail!(
            "{} is larger than {} MB, the APK audit limit",
            input.display(),
            apk::MAX_APK_BYTES / (1024 * 1024)
        );
    }

    if let Some(entry) = cat {
        let data = apk::entry_bytes(&bytes, entry)?;
        let mut out = std::io::stdout().lock();
        return match out.write_all(&data).and_then(|()| out.flush()) {
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
            r => r.map_err(Into::into),
        };
    }
    if files {
        return apk_files(&bytes, json);
    }

    // Audit the APK
    let audit = apk::audit_apk_bytes(input, &bytes);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);

    // A file that is not an APK could not be audited: exit 2 (doctor/1), text and JSON alike.
    let failed = audit.info.is_none();
    if failed && !json {
        anyhow::bail!(
            "{}: {}",
            input.display(),
            audit.error.as_deref().unwrap_or("not an APK")
        );
    }
    if !json {
        return print_out(&apk::to_text(&audit, now));
    }
    // doctor/1 envelope, built with the same core type as `audit --json` (reporting::emit).
    // The apk object lives under `data` only.
    let exit = if failed {
        doctor_core::ExitCode::Error.code()
    } else {
        0
    };
    let all = findings::from_apk(&audit, now);
    print_envelope(&all, exit, apk::to_json(&audit, now))
}

/// Print one doctor/1 envelope with `findings` and `data`. A nonzero `exit` is returned as a
/// silent Gate, so the process exits with that code after the envelope is on stdout.
fn print_envelope(
    all: &[findings::Finding],
    exit: u8,
    data: serde_json::Value,
) -> anyhow::Result<()> {
    let mut rows: Vec<doctor_core::Finding> = all.iter().map(findings::Finding::to_core).collect();
    doctor_core::Finding::sort(&mut rows);
    let env = doctor_core::Envelope::new(
        "android-doctor",
        env!("CARGO_PKG_VERSION"),
        exit,
        findings::score(all),
        rows,
        data,
    );
    print_out(&serde_json::to_string_pretty(&env.to_value())?)?;
    if exit != 0 {
        return Err(reporting::Gate {
            code: doctor_core::ExitCode::Error,
            message: String::new(),
        }
        .into());
    }
    Ok(())
}

/// `apk --files`: the archive entries, as text lines or in the doctor/1 envelope `data`.
fn apk_files(bytes: &[u8], json: bool) -> anyhow::Result<()> {
    let entries = match apk::list_entries(bytes) {
        Ok(e) => e,
        Err(e) if json => {
            return print_envelope(
                &[],
                doctor_core::ExitCode::Error.code(),
                serde_json::json!({ "error": format!("{e:#}") }),
            );
        }
        Err(e) => return Err(e),
    };
    if json {
        let data = serde_json::json!({
            "count": entries.len(),
            "entries": entries.iter().map(|e| serde_json::json!({
                "name": e.name,
                "size": e.size,
                "compressed_size": e.compressed_size,
                "method": e.method,
            })).collect::<Vec<_>>(),
        });
        return print_envelope(&[], 0, data);
    }
    let text = entries
        .iter()
        .map(|e| {
            format!(
                "{:<12} {:>10} {:>10}  {}",
                e.method,
                e.size,
                e.compressed_size,
                term::sanitize(&e.name)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    print_out(&text)
}

fn audit_command(
    images: &[PathBuf],
    json: bool,
    report: &ReportArgs,
    no_color: bool,
) -> anyhow::Result<()> {
    let audits = audit::image_list(images)?
        .iter()
        .map(|p| audit::audit_image(p))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let all = findings::from_audit(&audits);
    let baselined = report.baseline.is_some();
    emit(
        Emit {
            json,
            fail_default: None,
            no_color,
            domain_replaces_face: true,
        },
        report,
        all,
        // The per-image detail (adb summary, properties, services, APKs, ELF...) lives under `data`.
        || audit::to_json(&audits),
        // Without a baseline the familiar per-image report; with one, only what is new.
        || (!baselined).then(|| audit::to_text(&audits, no_color)),
    )
}

fn diff_command(
    old: &std::path::Path,
    new: &std::path::Path,
    json: bool,
    only: &[String],
    report: &ReportArgs,
    no_color: bool,
) -> anyhow::Result<()> {
    if let Some(bad) = only
        .iter()
        .find(|o| !fwdiff::STATUSES.contains(&o.as_str()))
    {
        anyhow::bail!(
            "unknown --only status {bad:?}: use {}",
            fwdiff::STATUSES.join(", ")
        );
    }
    let r = fwdiff::run(old, new)?;
    emit(
        Emit {
            json,
            // A diff lists only what the new build introduced, so gating on high is safe.
            fail_default: Some(findings::Severity::High),
            no_color,
            domain_replaces_face: false,
        },
        report,
        r.findings,
        || fwdiff::to_json(&r.images, only),
        || Some(fwdiff::to_text(&r.images, only)),
    )
}

fn info_command(input: &std::path::Path, json: bool, details: bool) -> anyhow::Result<()> {
    let meta = info::read(input)?;
    if !details {
        return print_out(&info::render(&meta, json)?);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let d = otameta::read_details(input)?;
    if json {
        let mut v = d.to_json(now);
        v["metadata"] = serde_json::to_value(&meta)?;
        return print_out(&serde_json::to_string_pretty(&v)?);
    }
    print_out(&format!(
        "{}\n\n{}",
        info::render(&meta, false)?,
        d.to_text(now)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
