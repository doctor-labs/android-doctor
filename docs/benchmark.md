# Benchmark and parity gaps

Evidence-based comparison of `android-doctor` with reference firmware/OTA tools on the
same images (issue #167). Each row states the tool, version, image and what the tool
saw that `android-doctor` did or did not. "Gap" means a capability a reference tool
provides on that input that `android-doctor` does not yet match or reports less
precisely; "parity"/"stronger" means equal or better coverage.

## Environment

Benchmarks run on the Instabox sandbox (`/data/workspace/doctor-labs`).

| Tool | Version / source | Notes |
| --- | --- | --- |
| android-doctor | 0.5.1 (`.audit/target-android-doctor-coolpad/debug/android-doctor`, pre-change baseline) and HEAD of `agent/android-bench` | |
| avbtool | 1.3.0 (`tools/avbtool.py`, AOSP external/avb main) | |
| magiskboot | v31.1 (`lib/x86_64/libmagiskboot.so` from Magisk-v31.1.apk) | |
| avbroot | source present at `tools/avbroot` (not built in this run) | Rust; needs `cargo build --release` |
| payload_dumper | `tools/payload_dumper/payload_dumper.py` (vm03/payload_dumper) | A/B payload.bin OTAs; deps (bsdiff4, protobuf) not installed in this run |
| binwalk / unblob | directories present under `tools/` but binaries not installed in this run | |
| pysim / simtester | present under `tools/` | SIM-focused; not applicable to Android firmware images |
| suricata | system-installed | network IDS; not applicable to offline firmware analysis |
| java / mkfs.erofs | system-installed | supporting tools |
| avbtool.py (AOSP), magiskboot binary | fetched and staged under `tools/` during this run | |
| MobSF behaviour rules | `tools/mobsf_behaviour_rules.yaml` (818 lines) staged for comparison | full MobSF not installed |
| fwtool.py (OpenWrt), Zeek, NetworkMiner | not fetched/installed in this run | out of scope for Android OTA/firmware images here |

## Corpus

Real samples on the sandbox (not committed; referenced by path):

| Image | Path (sandbox) | Notes |
| --- | --- | --- |
| STB-JHSD200-5.7.1.zip | `/data/workspace/doctor-labs/.audit/samples/STB-JHSD200-5.7.1.zip` (509 MB, sha256 TBD on sandbox) | Amlogic/Jio STB legacy block OTA (SignApk, `*.new.dat.br` + `*.transfer.list`, boot/recovery/vbmeta/dt/dtbo/logo/bootloader) |
| JCOW414_SRCMTF1_JCOW414_R2.59.1.img | `/data/workspace/doctor-labs/.audit/samples/JCOW414_SRCMTF1_JCOW414_R2.59.1.img` (39 MB) | Franklin S002C line firmware image (format per `identify`) |
| JCOW414_R2.58.2.img | `/data/workspace/doctor-labs/.audit/samples/JCOW414_R2.58.2.img` (39 MB) | Franklin S002C line |
| JCOW411_ARCNTF1_JCOW411_R2.3.img | `/data/workspace/doctor-labs/.audit/samples/JCOW411_ARCNTF1_JCOW411_R2.3.img` (67 MB) | Franklin line |
| JCOW404_SRCMTF1_JCOW404_R2.3.img | `/data/workspace/doctor-labs/.audit/samples/JCOW404_SRCMTF1_JCOW404_R2.3.img` (66 MB) | Franklin line |
| JCOW401_ARCTF1_JCOW401_R1.34.img | `/data/workspace/doctor-labs/.audit/samples/JCOW401_ARCTF1_JCOW401_R1.34.img` (61 MB) | Franklin line |
| JCO110_ARCTF1_JCO110_R1.130.img | `/data/workspace/doctor-labs/.audit/samples/JCO110_ARCTF1_JCO110_R1.130.img` (53 MB) | Franklin/Jio line |
| ChromeOS kernel sample | `/data/workspace/doctor-labs/samples/chromeos/` (directory present, empty in this run) | public ChromeOS kernel partition to be fetched on Mac and copied over for #176 |

## Evidence

### 1. Legacy block OTA (`STB-JHSD200-5.7.1.zip`, SignApk, 23 entries)

**android-doctor 0.5.1**
- `identify --json`: `[{"id":"block-ota-zip","description":"zip: block OTA (*.transfer.list)", ...}]`
- `extract --list`: lists reconstructed partitions with sizes (`odm/product/system/vendor` as GiB/MiB images plus `boot.img`, `bootloader.img`, `dt.img`, `dtbo.img`, `logo.img`, `recovery.img`, `vbmeta.img`).
- `extract -o out`: wrote 11 partitions, reported ext4 for `odm/product/system/vendor`, `ignored 4 known OTA file(s)`.
- `verify-ota --json`: `zip-signature` verdict `not-checked` (detail "signature without signed attributes"), overall `ok:false`, message "an OTA signature is absent or not checked".

**payload_dumper (`payload_dumper.py`)**
- Not applicable: this OTA contains legacy `*.new.dat.br`/`*.transfer.list` pairs, not an A/B `payload.bin`. payload_dumper targets payload.bin extraction.

**avbroot**
- Not built in this run (`tools/avbroot/target/release/avbroot` absent). avbroot primarily verifies/patches A/B payload-based OTAs; applicability to legacy block OTAs is a follow-up comparison once built.

**Gap/notes:** android-doctor handles legacy block OTA identification, listing and full reconstruction on this sample where payload_dumper does not apply. OTA signature verification reports `not-checked` for this SignApk form ("signature without signed attributes"); mapping this to avbroot's verification depth on comparable signed OTAs remains a gap to evidence with a built avbroot and a payload-based signed OTA.

### 2. vbmeta (`vbmeta.img` from STB-JHSD200-5.7.1.zip)

**avbtool 1.3.0** `info_image --image vbmeta.img`:
- Minimum libavb 1.0, Header 256, Auth 0, Aux 0, Algorithm NONE, Rollback Index 0, Flags 2, Rollback Index Location 0, Release `avbtool 1.1.0`, Descriptors: (none).

**android-doctor 0.5.1** `vbmeta vbmeta.img --json`:
- Reports algorithm NONE, flags 2/`VERIFICATION_DISABLED`, rollback 0/location 0, release `avbtool 1.1.0`, no descriptors, `signature_verified: absent`, plus security findings `avb-security-state` (high) and `avb-unsigned-image` (high), rollback interpretation, kernel_cmdline_hashtree_disabled.

**Gap/notes:** parity on core header fields vs avbtool 1.3.0 for this unsigned/verification-disabled image; android-doctor additionally emits security findings and derived interpretations (stronger for audit use). Signed vbmeta verification parity against `avbtool verify_image` on images with signatures/keys is partially covered by existing tests but should be evidenced against avbtool on a real signed sample in a follow-up benchmark pass.

### 3. Boot image (`boot.img` and `recovery.img` from STB-JHSD200-5.7.1.zip)

**magiskboot v31.1** `unpack boot.img`:
- Parsed header v1 (kernel 9333472, ramdisk 0, second 80896, page 2048, OS 9.0.0/2020-12, cmdline, checksum) and wrote `kernel`, `second`.

**android-doctor 0.5.1** `unpack boot.img -o bootad`:
- Reported same key header fields and sizes, wrote `kernel`, `second`; additionally classified kernel as `[aml-container]` ("Amlogic container (@AML); secure-boot images are encrypted") and second as `[unknown-high-entropy]` with entropy note.

**magiskboot v31.1** `unpack recovery.img` (from same OTA):
- Header v1, kernel 9333472, ramdisk 5545616 (raw), second 80896, recovery_dtbo 438; wrote kernel/ramdisk.cpio/second/recovery_dtbo.

**Gap/notes:** section extraction parity with magiskboot on this Amlogic header-v1 image; android-doctor adds content classification of extracted sections (stronger). Gaps to re-check: full ramdisk content decode/unpack parity against magiskboot on compressed ramdisks (lz4/gzip/xz/lzma/zstd/lzo/lz4_legacy/lg) and vendor_boot v3/v4 edge cases across real samples; magiskboot's repack/patch flows are not android-doctor goals except where documented.

### 4. ChromeOS kernel (`vbkernel`/`vbsign`, #176)

**magiskboot `futility.rs`** (reference, `topjohnwu/Magisk` master, read during this work):
- Packs a kernel into a ChromeOS-signed image with a fixed layout: 64 KiB vblock (pre-existing keyblock + kernel preamble padded to fill the vblock) followed by a kernel blob (kernel padded to 4 KiB alignment, 4 KiB config, 4 KiB params, 4 KiB-aligned bootloader stub containing `\n`). The body signature covers the entire blob (hashed in chunks without materializing padding+trailer as one buffer). Preamble 2.2, version 1, flags 0x1, body load 0x100000, RSA2048-SHA256 with embedded Magisk keys; keyblock is not regenerated.

**android-doctor (HEAD, this branch)** `vbkernel`/`vbsign`:
- Verifies vboot 2.x keyblock (`CHROMEOS`), data key, preamble 2.2 and body signatures (RSA 1024–8192, exp 3/65537, SHA-1/256/512) and reports `valid`/`invalid`/`unverified` with `--key`. Re-signs an existing image in its recorded layout (`vbsign`) replacing the data key and re-signing preamble/body and keyblock (root signs keyblock with SHA-256), verified before write. Does not build a new kernel image from a raw kernel (`vbutil_kernel --pack` / magiskboot pack) and does not accept preamble 2.0/2.1 or check unsigned keyblock hashes (documented).

**Hardening added (this branch, #176):** regression test `magiskboot_futility_layout_verifies` constructs and verifies an image in magiskboot futility.rs's layout (64 KiB vblock, 4 KiB-aligned kernel blob with config/params/bootloader trailer, body offset 65536) to lock in verify compatibility with that reference layout.

**Gap/notes:** creating/packing a ChromeOS kernel image from a raw kernel + config/bootloader/keyblock (vbutil_kernel/futility pack equivalent) is not implemented; magiskboot futility.rs's fixed-recipe pack remains a reference for that workflow. Full integration with vboot key hierarchy tooling remains limited to the recorded-layout re-sign path (see issue comment on #176).

### 5. APK / behavior rules (MobSF comparison)

**MobSF** `android_rules.yaml` (818 lines, staged): extensive regex/API pattern rules across malware/behavior categories (SMS, telephony IDs, location, dynamic code loading, etc.).

**android-doctor:** `apk`, `dex`, manifest/component/signing checks and `apk-code-*` behavior findings (method-level co-occurrence for e.g. device-id+SMS; category rules like `apk-code-behaviour-*`, `apk-code-sms-send`) as documented in README/CHANGELOG; tracker SDK prefix set.

**Gap/notes:** MobSF's rule breadth and data-flow depth exceed android-doctor's current method-level/pattern checks. A full side-by-side run over identical APKs with MobSF installed would quantify per-rule gaps; this pass records the rule-source comparison only (MobSF not installed). Follow-ups should add high-value missing behavior/manifest checks evidenced against specific APKs.

## Coverage matrix (summary)

| Area | avbtool / avbroot | magiskboot / boot tools | payload_dumper | MobSF / apksigner | android-doctor (HEAD) |
| --- | --- | --- | --- | --- | --- |
| vbmeta info/fields | reference | — | — | — | parity (unsigned case evidenced); signed verify evidenced in tests, real-sample parity TBD |
| OTA payload.bin (A/B) extract/verify | avbroot/payload_dumper strong | — | extract | — | extract/verify-ota supported per README; not benchmarked here (no payload.bin sample in corpus) |
| Legacy block OTA (*.new.dat.br) | — | — | n/a | — | identify/list/extract evidenced on STB sample |
| Boot/vendor_boot unpack | — | reference | — | — | header+sections parity evidenced; adds section classification; ramdisk decode breadth per README |
| ChromeOS kernel verify | — | futility.rs reference | — | — | verify vboot 2.x + re-sign in-place; magiskboot-layout verify test added; pack-from-kernel not implemented |
| APK static security | — | — | — | MobSF/apksigner reference | manifest/signing/code/tracker checks implemented; rule breadth below MobSF |
| Container formats (super, sparse, erofs/ext4/f2fs, OEM) | varies | — | payload/super | — | per README format table; Coolpad .cpb refused by design |

## Follow-up gaps (candidates for issues)

1. **avbroot/payload_dumper parity on A/B payload OTAs:** build avbroot, install payload_dumper deps, and benchmark `extract`/`verify-ota` on a payload.bin-based OTA (extraction completeness, verification depth, patch semantics). Evidence: none in this run (no payload.bin sample; tools not runnable).
2. **OTA zip signature forms:** `verify-ota` reported `not-checked` ("signature without signed attributes") on STB-JHSD200-5.7.1.zip; compare with avbroot/apksign-style expectations on signed legacy/A-B OTAs and harden parsing/verification where spec allows.
3. **ChromeOS kernel pack:** implement vbutil_kernel/futility-style packing from raw kernel+config+bootloader with supplied keyblock/keys (magiskboot futility.rs layout as reference) so `vbsign`/pack can create images, not only re-sign existing ones.
4. **MobSF rule breadth:** quantify missing APK/DEX behavior checks against MobSF's `android_rules.yaml` on identical APKs and add high-value missing rules (evidence-driven).
5. **binwalk/unblob container coverage:** install and run over the same firmware images to find containers/segments android-doctor does not identify or extract.

## Hardening applied in this change

- **#176:** added `tests/vbkernel.rs` case `magiskboot_futility_layout_verifies` asserting verify correctness on the magiskboot `futility.rs` ChromeOS kernel image layout (64 KiB vblock, blob body at offset 65536).
- **#167:** added this evidence-based benchmark/gap document (`docs/benchmark.md`).
