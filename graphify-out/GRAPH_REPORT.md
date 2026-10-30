# Graph Report - Keymaker-v2  (2026-10-30)

## Corpus Check
- Large corpus: 284 files · ~537,611 words. Semantic extraction will be expensive (many Claude tokens). Consider running on a subfolder.

## Summary
- 3322 nodes · 7143 edges · 160 communities (156 shown, 4 thin omitted)
- Extraction: 97% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 173 edges (avg confidence: 0.84)
- Token cost: 1,335,397 input · 0 output

## Community Hubs (Navigation)
- Shamir Secret Sharing TS
- keym2.py Reference Core
- KEYM v2 TS Container
- Python Slot Builders
- npm Dependencies
- Python Container Assembly
- Shared App Constants
- v1 Crypto and Regression
- Test Vector Generator
- Build and Deploy Scripts
- npm Scripts
- Browser Test Helpers
- Python/TS Parity Crosstest
- Python Decode and Armor
- keym.py v1 Reference
- Shamir and Paper UI Tests
- Crypto Worker Client
- KDF Calibration
- Release Notes and Next Config
- Passkey and Calibration Tests
- Browser CI Workflow
- App Shell and Dialogs
- Shared UI Components
- KEYM2 Dispatch Tests
- Audio Stego Carrier
- Slot Transaction Tests
- KEYM2 Fuzzing and Bridge
- Self-Extract Export
- Nightpaper Design Releases
- Backup Workflow Steps
- Executable Recovery Docs
- Conformance CI Workflow
- Python Property Tests
- Toast and Root Layout
- Decrypt and Generator Screens
- In-App Docs Guide
- Changelog and Review Bets
- esbuild Bridge Bundling
- Python KDF Inputs
- Secret Erase Core Tests
- Walkthrough Protection Screens
- Access Policy
- v2.3 Features and Printouts
- V2 Spec Payload and Findings
- KDF and Advanced Screens
- Sealed Status Audio Tests
- Service Worker Transport
- Security Audits
- Icon Audit and SW Tests
- Container Inspector UI
- Paper Parts Encoding
- Format V3/V4 Review Briefs
- Roadmap Cut Features
- Palette Contrast Audit
- TypeScript Config
- Seed and Audio Screens
- Conformance Dep Pinning
- Dice and Passphrase Tests
- QR Decoding
- Build ID Precache
- KEYM v3 Fuzzing
- QR and Recovery Tests
- shadcn Components Config
- Crypto Regression CI
- v1 Crypto Regression
- Recovery Envelope Tests
- Dependabot Config
- Python Pinned Requirements
- WAV Bit Depth Tests
- SW Precache Tests
- UAT Findings
- Brand Assets and Hero
- Share Record Encoding
- Malformed Audio Tests
- Repo House Rules
- CI Reproducible Jobs
- Camera Progress Tests
- Deploy Verify Jobs
- Wordlist Generation
- CI Build Env
- Release Concurrency
- Password Policy Tests
- Python Audio Carrier
- Printout Check Tests
- Secret Erase Worker Tests
- Manifest Verification
- Sealed Status UI
- BIP39 Wordlist
- Trust Claims and Verify
- Roadmap Phase 2
- Landing Page Screens
- Spline Sans Font License
- Passkey Binding Tests
- Seed Grid UI
- Verify Confinement Tests
- v2.4 Usability Changes
- KEYM v1 Format Spec
- KAUD1 Audio Format
- V2 Header and Bounds
- Release Workflow Setup
- PWA Manifest
- Worker Protocol Tests
- pip-audit Requirements
- WAV Bounds Tests
- Dearmor Whitespace Tests
- README Scripts Test
- Release Recipe Test
- WebAuthn PRF Passkeys
- Outreach and Trust Boundary
- CI Node Setup
- Deploy Concurrency
- Deploy Build Env
- Release Signing Env
- Release Verify Gates
- v1 Crosstest
- CSP Hash Injection
- Build Manifest
- Reproducible Build Check
- Rehearsal Tests
- V2 Passphrase KDF Slot
- V2 Armor and Share Text
- CI Node Matrix
- Deploy Node Setup
- Release Preflight
- Argon2 Blob Check
- Self-Extract Decryptor
- Release Gate Test
- Seed Mode Tests
- Screenshot Capture
- CI Triggers
- Deploy Signing
- Self-Extract Fixture
- Reproduced Manifest Test
- Encrypt Input Erase Test
- Wordlist Verification
- Async Guard Tests
- Deploy Environment
- Release Attestations
- Sigstore Signing
- CycloneDX SBOM Deps
- Reference Impl README
- CSP Egress Gate
- Screenshot Audit
- Failure Reporting Tests
- Owned Buffer Tests
- Release Tag Input
- Release Verify CI
- release (small)
- audit-requirements (small)
- page (small)
- deploy (small)
- release (small)
- release (small)
- art-cipher-field (small)
- audit-requirements (small)
- build-recovery-kit (small)
- postcss.config (small)
- keym2 (small)

## God Nodes (most connected - your core abstractions)
1. `visible()` - 126 edges
2. `_selftest()` - 123 edges
3. `main()` - 96 edges
4. `useTextMode()` - 74 edges
5. `useEncryptorState()` - 73 edges
6. `@playwright/test` - 69 edges
7. `secureErase()` - 55 edges
8. `scripts` - 54 edges
9. `cn()` - 48 edges
10. `UsageError` - 43 edges

## Surprising Connections (you probably didn't know these)
- `Language-neutral JSON vector pack` --semantically_similar_to--> `Format change order: design, Python, TypeScript, fixtures`  [INFERRED] [semantically similar]
  docs/vectors/README.md → CLAUDE.md
- `Plus Jakarta Sans Variable font` --semantically_similar_to--> `Spline Sans font (SorkinType)`  [AMBIGUOUS] [semantically similar]
  scripts/og-card-template.html → public/licenses/spline-sans-OFL.txt
- `PBKDF2 iteration bounds 1..10,000,000 (6)` --semantically_similar_to--> `KDF cost parameter bounds (FORMAT.md 3.1)`  [INFERRED] [semantically similar]
  scripts/fixtures/keymaker/v2-selfextract.html → reference/README.md
- `Container preview and recovery honesty rules` --semantically_similar_to--> `Backup creation steps (status, not wizard)`  [INFERRED] [semantically similar]
  docs/design/DESIGN-SYSTEM.md → CHANGELOG.md
- `U1 UI freezes during KDF` --semantically_similar_to--> `KM-27 Argon2id froze the tab (Web Worker crypto)`  [INFERRED] [semantically similar]
  docs/reports/UAT-2026-08-14.md → SECURITY-AUDIT.md

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Envelope key hierarchy: slot secret to slot key to wrapped master key to payload** — docs_format_v2_design_slot_key, docs_format_v2_design_key_wrap, docs_format_v2_design_master_key, docs_format_v2_design_chunked_aead_payload, docs_format_v2_design_seal_construction [EXTRACTED 1.00]
- **Four slot types sharing one fixed slot record shape** — docs_format_v2_design_passphrase_slot, docs_format_v2_design_passkey_prf_slot, docs_format_v2_design_shamir_slot, docs_format_v2_design_passphrase_and_shares_slot, docs_format_v2_design_slot_record [EXTRACTED 1.00]
- **Prefix-disjoint text encodings (ke/KM family)** — docs_format_v2_design_keym2_text_armor, docs_format_v2_design_kmshare1, docs_format_v2_design_kmshare2, docs_format_v2_design_kmpart1, docs_format_v2_design_kmpart2, docs_format_v2_design_ignorable_characters [EXTRACTED 1.00]
- **KEYM Format Version Lineage (v1 to v4)** — docs_format, docs_format_v3_design, docs_format_v4_design, docs_recovery [EXTRACTED 1.00]
- **Build Verification Chain** — docs_verifying_signed_manifest, docs_verifying_sigstore_keyless, docs_verifying_certificate_identity_trust_root, docs_verifying_reproducible_build, docs_verifying_build_attestation, docs_roadmap_verify_this_build_page [EXTRACTED 1.00]
- **Inheritance Wizard Composition** — docs_roadmap_inheritance_wizard, docs_roadmap_shamir_k_of_n, docs_roadmap_paper_vault, docs_roadmap_self_extracting_page, docs_roadmap_in_app_recovery_kit [EXTRACTED 1.00]
- **Rendered-page and byte-level verification gates with negative controls** — claude_negative_controls, claude_byte_parity_gate, changelog_test_palette, docs_design_status_icon_audit, docs_design_status_screenshot_audit, changelog_design_gates, readme_test_readme [INFERRED 0.85]
- **Checkable trust in the served bundle** — readme_trust_anchor, readme_reproducible_build, security_audit_km_28, changelog_github_build_attestation, docs_design_ten_x_plan_bet_5_sealed_status, docs_reports_review_2026_10_22_bet_1_release_bytes [INFERRED 0.85]
- **Heir recovery flow (shares, paper vault, rehearsal, scanning)** — readme_shamir_shares, docs_design_ten_x_plan_bet_4_paper_vault, docs_design_ten_x_plan_bet_2_rehearsal, docs_design_ten_x_plan_bet_1_heir_mode, changelog_camera_scanning, changelog_printout_check, readme_keym2_py [INFERRED 0.85]
- **Three-file Python dependency pinning strategy (heir runtime vs CI oracle vs audit toolchain)** — reference_requirements_requirements_txt, reference_conformance_requirements_conformance_requirements_txt, reference_audit_requirements_audit_requirements_txt, reference_conformance_requirements_pin_conformance_deps_py [EXTRACTED 1.00]
- **WebCrypto-only KEYM v2 decrypt flow** — scripts_fixtures_keymaker_v2_selfextract_dearmor, scripts_fixtures_keymaker_v2_selfextract_decrypt, scripts_fixtures_keymaker_v2_selfextract_slotkeyfor, scripts_fixtures_keymaker_v2_selfextract_lp, scripts_fixtures_keymaker_v2_selfextract_openaesgcm, scripts_fixtures_keymaker_v2_selfextract_chunklayout, scripts_fixtures_keymaker_v2_selfextract_noncefor [EXTRACTED 1.00]
- **Spec-derived reference oracle validating TypeScript via fixtures and bridge** — reference_readme_keym_v1_reference_implementation, reference_readme_format_md, reference_readme_frozen_fixtures, reference_readme_bridge_mts, reference_readme_test_conformance [EXTRACTED 1.00]
- **Keyhole squircle icon set rendered at multiple sizes** — public_logo_logo, public_apple_touch_icon_icon, public_icon_192x192_icon, public_icon_512x512_icon [INFERRED 0.95]
- **Client-side zero-trust privacy messaging** — public_og_card_tagline, public_og_card_client_side_offline_open_source, public_og_card_no_accounts_no_servers, docs_hero_hero_image [INFERRED 0.85]
- **Keymaker dark blue/orange marketing art set** — public_art_cipher_field_image, public_art_container_blueprint_image, public_art_key_shards_image, public_hero_cipher_field_image [INFERRED 0.85]
- **Cipher choices in the container panel** — docs_screenshots_03_kdf_argon2id_aes_256_gcm, docs_screenshots_03_kdf_argon2id_chacha20_poly1305, docs_screenshots_04_cipher_chained_aes_chacha_chained [EXTRACTED 1.00]
- **Optional container features (advanced toggles)** — docs_screenshots_05_advanced_panel_key_file_toggle, docs_screenshots_05_advanced_panel_obscure_filename, docs_screenshots_05_advanced_panel_passkey_quick_access, docs_screenshots_05_advanced_panel_hide_size_padding, docs_screenshots_05_advanced_panel_recovery_shares [EXTRACTED 1.00]
- **UI surfaces that quantify secret entropy in bits** — docs_screenshots_09_dice_entropy_dice_entropy_calculator, docs_screenshots_09_dice_entropy_entropy_targets, docs_screenshots_10_passphrase_generator_eff_passphrase [INFERRED 0.75]
- **Container transparency panel: header, slots, cipher, offline opener** — docs_screenshots_07_decrypt_detection_keym_v3_header, docs_screenshots_07_decrypt_detection_passphrase_slot_argon2id, docs_screenshots_07_decrypt_detection_cascade_cipher, docs_screenshots_07_decrypt_detection_keym2_py [EXTRACTED 1.00]
- **Recovery verification flow (test, track, invalidate on change)** — docs_screenshots_13_recovery_tested_verify_with_password, docs_screenshots_13_recovery_tested_verify_with_recovery_shares, docs_screenshots_14_verify_stale_stale_verification_notice, docs_screenshots_11_seed_mode_progress_checklist [INFERRED 0.75]
- **Encrypt, save and verify walkthrough sequence** — docs_screenshots_walkthrough_5_steps_six_step_checklist, docs_screenshots_walkthrough_1_protection_image, docs_screenshots_walkthrough_3_container_image, docs_screenshots_walkthrough_4_verified_image [INFERRED 0.85]
- **Saved-copy outputs and their check paths** — docs_screenshots_walkthrough_3_container_print_paper_vault, docs_screenshots_walkthrough_3_container_download_keym, docs_screenshots_walkthrough_4_verified_verify_only_toggle, docs_screenshots_walkthrough_5_steps_recovery_tab [INFERRED 0.85]

## Communities (160 total, 4 thin omitted)

### Community 0 - "Shamir Secret Sharing TS"
Cohesion: 0.06
Nodes (75): check(), COEFFS, main(), refuses(), SECRET, check(), CIPHERS, each() (+67 more)

### Community 1 - "keym2.py Reference Core"
Cohesion: 0.04
Nodes (42): Review Checklist, py_verdict(), armor(), _ascii_upper(), _b32_decode(), CarrierError, check_selfextract_policy(), combine_shares() (+34 more)

### Community 2 - "KEYM v2 TS Container"
Cohesion: 0.06
Nodes (82): main(), addPasskeySlotKeym2(), addShamirSlotKeym2(), AeadKeys, armorKeym2Compact(), buildKdfInput(), buildPasskeyInput(), buildShamirInput() (+74 more)

### Community 3 - "Python Slot Builders"
Cohesion: 0.05
Nodes (33): build_both_slot(), build_passkey_slot(), build_passphrase_slot(), build_shamir_slot(), check_writable_params(), check_write_policy(), CoreHeader, derive_slot_key() (+25 more)

### Community 4 - "npm Dependencies"
Cohesion: 0.04
Nodes (70): dependencies, class-variance-authority@^0.7.0, clsx@^2.1.1, @fontsource-variable/jetbrains-mono@5.3.0, @fontsource-variable/plus-jakarta-sans@^5.3.0, @fontsource-variable/spline-sans@5.3.0, hash-wasm@4.12.0, jsqr@1.4.0 (+62 more)

### Community 5 - "Python Container Assembly"
Cohesion: 0.07
Nodes (42): add_both_slot(), add_passkey_slot(), add_shamir_slot(), add_slot(), assemble(), _chunk_layout(), compute_slot_table_mac(), core_header_len() (+34 more)

### Community 6 - "Shared App Constants"
Cohesion: 0.06
Nodes (63): RFC-9106, CommandBarItem, APP_VERSION, AUTO_LOCK_MS, bip39Module, CIPHER_OPTIONS, cipherLabelOf(), clickDownloadLink() (+55 more)

### Community 7 - "v1 Crypto and Regression"
Cohesion: 0.06
Nodes (54): check(), KEYM, main(), makeRng(), probe(), ARGON_FAST, b64ToArrayBuffer(), check() (+46 more)

### Community 8 - "Test Vector Generator"
Cohesion: 0.06
Nodes (29): encode_parts(), pad_stream(), padded_len(), accept(), container(), _argon2id_with_secret(), build(), check() (+21 more)

### Community 9 - "Build and Deploy Scripts"
Cohesion: 0.04
Nodes (33): BASE_PATH, ENGINES, output, [buildPath, dir], legs, reference, DEPLOY, { join } (+25 more)

### Community 10 - "npm Scripts"
Cohesion: 0.04
Nodes (54): scripts, analyze, build, build:worker, dev, test:access-policy, test:audio-decode-scale, test:audio-malformed (+46 more)

### Community 11 - "Browser Test Helpers"
Cohesion: 0.07
Nodes (20): @playwright/test, slotCountByte(), CIPHERS, KDFS, CHAPTERS, Cipher, CIPHER_LABEL, decryptText() (+12 more)

### Community 12 - "Python/TS Parity Crosstest"
Cohesion: 0.06
Nodes (32): bridge(), bridge_stdout(), BridgeError, check(), check_call(), kdf_flags(), main(), carrier_signal() (+24 more)

### Community 13 - "Python Decode and Armor"
Cohesion: 0.05
Nodes (25): py_extract(), _b64url_bytes(), _b64url_nopad(), _container_fingerprint(), decode_parts_v2(), embed_audio(), encode_parts_v2(), extract_audio() (+17 more)

### Community 14 - "keym.py v1 Reference"
Cohesion: 0.09
Nodes (20): Argon2idParams, _base_material(), build_header(), decrypt(), _derive_master_key(), encrypt(), Header, _inspect() (+12 more)

### Community 15 - "Shamir and Paper UI Tests"
Cohesion: 0.08
Nodes (30): KEYM2_VERSION_V3, OUT, runEncryption(), BASE_PATH, capturePrintedSymbols(), composePhoto(), selectCrypto(), useTextMode() (+22 more)

### Community 16 - "Crypto Worker Client"
Cohesion: 0.10
Nodes (37): calibrateViaWorker(), cancelAllCryptoWork(), CryptoCancelled, DecryptOutcome, decryptViaWorker(), EncryptOutcome, encryptViaWorkerInner(), failAllPending() (+29 more)

### Community 17 - "KDF Calibration"
Cohesion: 0.07
Nodes (35): failures, ARGON_PARAMS, CIPHERS, Combo, combos, DIR, HERE, hexToArrayBuffer() (+27 more)

### Community 18 - "Release Notes and Next Config"
Cohesion: 0.06
Nodes (30): basePath, nextConfig, verifyCommands, version, flag(), composeNotes(), HERE, readSources() (+22 more)

### Community 19 - "Passkey and Calibration Tests"
Cohesion: 0.08
Nodes (25): calibrate(), memoryMiB(), openArgon2Settings(), enableShares(), visible(), openRollLog(), typePassword(), output() (+17 more)

### Community 20 - "Browser CI Workflow"
Cohesion: 0.06
Nodes (37): if, needs, permissions, runs-on, steps, name, permissions, runs-on (+29 more)

### Community 21 - "App Shell and Dialogs"
Cohesion: 0.17
Nodes (23): lucide-react, Home(), CameraScanDialog(), CommandBar(), optionDomId(), EncryptorContext, EncryptorContextValue, useEncryptorContext() (+15 more)

### Community 22 - "Shared UI Components"
Cohesion: 0.16
Nodes (25): qrcode.react, react, PasswordField(), DiceEntropyTool(), Verdict, SecretForm(), formatBytes(), OFFSCREEN_STYLE (+17 more)

### Community 23 - "KEYM2 Dispatch Tests"
Cohesion: 0.06
Nodes (33): appPadded, appPlain, armored, bodyA, bodyB, check(), costOne, dec (+25 more)

### Community 24 - "Audio Stego Carrier"
Cohesion: 0.11
Nodes (33): AudioStegoTool(), decodeCarrier(), download(), formatBytes(), looksLikeWav(), OPTIONS, SecretType, Sub (+25 more)

### Community 25 - "Slot Transaction Tests"
Cohesion: 0.06
Nodes (26): ARGON2, CID, COEFFS, countArgon2, CREATIONS, dec, enc, HERE (+18 more)

### Community 26 - "KEYM2 Fuzzing and Bridge"
Cohesion: 0.10
Nodes (32): CIPHERS, inputBuf, keyfileHex, check(), FAST, FIXED_MASTER_KEY, FIXED_SALT, laidOut() (+24 more)

### Community 27 - "Self-Extract Export"
Cohesion: 0.12
Nodes (33): withRepeatedSlots(), cipherLabelOf(), parsePeek(), SelfExtractExport(), triggerDownload(), inspectKeym2(), kdfIsLegalForSlotType(), KEYM2_ARMOR_PREFIX (+25 more)

### Community 28 - "Nightpaper Design Releases"
Cohesion: 0.09
Nodes (31): Container inspector pane, Design gates in CI (icons, hero plate, precache), Keymaker v2.1.0, Keymaker v2.2.0 (design release), Nightpaper visual identity, npm run test:palette, BAR: Linear reference, Graphite palette, Workspace review criteria (+23 more)

### Community 29 - "Backup Workflow Steps"
Cohesion: 0.10
Nodes (29): run(), SETTINGS, InspectorPlan, describedSteps(), STATE_WORD, WorkflowSteps(), WayIn, CoverageFinding (+21 more)

### Community 30 - "Executable Recovery Docs"
Cohesion: 0.12
Nodes (14): bash_blocks(), check(), claimed_versions(), cli(), error_paths(), fenced_after(), inspect_lines(), js_encrypt() (+6 more)

### Community 31 - "Conformance CI Workflow"
Cohesion: 0.09
Nodes (29): permissions, runs-on, steps, permissions, runs-on, steps, jobs, audit (+21 more)

### Community 32 - "Python Property Tests"
Cohesion: 0.12
Nodes (12): brief(), build(), pasted(), Cases, digest(), encoder(), main(), random_share() (+4 more)

### Community 33 - "Toast and Root Layout"
Cohesion: 0.12
Nodes (24): metadata, RootLayout(), Toast, ToastClose, ToastDescription, ToastProps, ToastTitle, toastVariants (+16 more)

### Community 34 - "Decrypt and Generator Screens"
Cohesion: 0.07
Nodes (25): Decrypt Detection Screenshot, AES-256-GCM + ChaCha20-Poly1305 Cascade, Container Details Panel (format detection), Header Layout Byte Map, keym2.py (opens without the app), KEYM v3 Header (magic, version, slot count), Passphrase Slot (Argon2id 64 MiB t=3 p=4), Scan a QR Image / Camera Input (+17 more)

### Community 35 - "In-App Docs Guide"
Cohesion: 0.17
Nodes (28): Arrow(), AudioDiagram(), Box(), Bullets(), Callout(), CALLOUT_LABEL, CalloutKind, ch() (+20 more)

### Community 36 - "Changelog and Review Bets"
Cohesion: 0.10
Nodes (27): Keymaker Changelog, Fork of IttyBitz v2.8.0, Keymaker v1.0.0 (KEYM v1), Bet 3: Intent doors and Seed Phrase mode, P1: audio carrier has no reader outside the app, Bet 1: live site serves release bytes, not main, Bet 3: file residue, get one outside reader, Bet 5: property-based tests over spec invariants (+19 more)

### Community 37 - "esbuild Bridge Bundling"
Cohesion: 0.08
Nodes (17): esbuild, HERE, outfile, HERE, out, src, ENTRY, HERE (+9 more)

### Community 38 - "Python KDF Inputs"
Cohesion: 0.08
Nodes (16): _attemptable(), BothSecret, build_both_input(), build_kdf_input(), build_passkey_input(), build_shamir_input(), _describe_slot(), keyfile_digest() (+8 more)

### Community 39 - "Secret Erase Core Tests"
Cohesion: 0.07
Nodes (12): FIXTURES, HERE, KEY_FILE, KEY_FILE_DIGEST, LIB, meta, note(), OPTIONS (+4 more)

### Community 40 - "Walkthrough Protection Screens"
Cohesion: 0.09
Nodes (26): AES-256-GCM then ChaCha20-Poly1305 chained cipher, Argon2id cost sliders (time, memory, parallelism), Argon2id KDF (recommended default), Calibrate for this device button, Effective configuration summary line, Hide the size of what is inside (padding option), Walkthrough 1: Protection settings screen, Optional protections toggles (key file, obscure filename, passkey, recovery shares) (+18 more)

### Community 41 - "Access Policy"
Cohesion: 0.11
Nodes (21): ALL, Attempt, cases, KEY_FILE, OPTIONS, posted, PRF, PRF_SALT (+13 more)

### Community 42 - "v2.3 Features and Printouts"
Cohesion: 0.09
Nodes (22): Camera and multi-QR scanning, GitHub build attestation on releases, KEYM v4 padded payload (Padme buckets), Keymaker v2.3.0, Check a printout, Re-seal an old backup, KMSHARE2 set code, Password-and-strips slot type 0x03 (+14 more)

### Community 43 - "V2 Spec Payload and Findings"
Cohesion: 0.10
Nodes (21): Parameter Bounds (normative), Chained Mode (AES-GCM inside ChaCha20-Poly1305), Chunked AEAD Payload (1 MiB chunks), Finding F1: Chunk Count Ambiguity, Finding F5: Salt/Master-Key Freshness, Finding F8: Re-password Destroys Share Slot, GF(2^8) AES Field (0x11B), no log tables, HKDF-SHA-256 (+13 more)

### Community 44 - "KDF and Advanced Screens"
Cohesion: 0.11
Nodes (25): Screenshot: Seed Detection, Access rule (password policy, shares or passkey), Backup progress checklist (Create, Saved copy, Recovery test), Secret text field (blurred, reveal toggle), Seed phrase detection, Screenshot: KDF Argon2id, AES-256-GCM cipher, Argon2 sliders (time cost 3, memory 64 MiB, parallelism 4) (+17 more)

### Community 45 - "Sealed Status Audio Tests"
Cohesion: 0.09
Nodes (12): CORPUS, corpusMeta, gotoReveal(), revealFrom(), weak, gotoAudio(), appPath(), OUT (+4 more)

### Community 46 - "Service Worker Transport"
Cohesion: 0.08
Nodes (17): APP_SHELL, BASE, Case, cases, CORPUS, enc, ERROR_FIELDS, failures (+9 more)

### Community 47 - "Security Audits"
Cohesion: 0.11
Nodes (22): Diceware passphrase generator (EFF Long Wordlist), Service-worker updates wait for user (KM-25), Bet 2: generated passphrase gets page-compatible PBKDF2 profile, P2: SECURITY-AUDIT.md stale as review of record, Dice entropy calculator, Random and Passphrase generators, IBTZ magic collision with v0 salt (accepted), IttyBitz v2.2.0 (+14 more)

### Community 48 - "Icon Audit and SW Tests"
Cohesion: 0.10
Nodes (16): badSize, badStroke, HERE, histogram, icons, ROOT, server, SIZES (+8 more)

### Community 49 - "Container Inspector UI"
Cohesion: 0.15
Nodes (19): ByteMap(), byteMapSpans(), ByteSpan, Check(), ContainerInspector(), ParsedPeek, SlotList(), SlotRow (+11 more)

### Community 50 - "Paper Parts Encoding"
Cohesion: 0.18
Nodes (21): containerSetCodes(), preparePaperParts(), dropIgnorable(), b64urlDecode(), b64urlEncode(), containerFingerprint(), decodePaperParts(), decodePaperPartsAny() (+13 more)

### Community 51 - "Format V3/V4 Review Briefs"
Cohesion: 0.12
Nodes (17): Review Brief for the Current Format, Adversary Positions, Questions for the Reviewer, KEYM v2 Container Format Specification, FORMAT-V3-DESIGN.md, container_id, Slot Strip Attack, slot_table_mac (+9 more)

### Community 52 - "Roadmap Cut Features"
Cohesion: 0.15
Nodes (18): ROADMAP.md, Cut Features, Finding F8 rewrap_slot Share-set Conversion, Inheritance Wizard (4.5), Multi-slot Envelope Key, Owner-only Register, Paper Vault Print Kit (4.2), Passkey / WebAuthn PRF Slot (4.4) (+10 more)

### Community 53 - "Palette Contrast Audit"
Cohesion: 0.10
Nodes (15): ABSOLUTES, ALLOWED, channels(), contrast(), GROUND_TOKENS, HERE, offenders, PROPS (+7 more)

### Community 54 - "TypeScript Config"
Cohesion: 0.10
Nodes (20): compilerOptions, allowJs, esModuleInterop, exactOptionalPropertyTypes, incremental, isolatedModules, jsx, lib (+12 more)

### Community 55 - "Seed and Audio Screens"
Cohesion: 0.11
Nodes (17): Seed Mode Screenshot, Container Preview (KEYM v3), Encrypt Progress Checklist (Create, Saved copy, Recovery test), Seed Phrase Input (12/15/18/21/24 words), Wordlist Validation with Did-You-Mean Suggestion, Audio Carrier Screenshot, Argon2id + AES-256-GCM, Encrypted Audio Carrier (+9 more)

### Community 56 - "Conformance Dep Pinning"
Cohesion: 0.15
Nodes (9): _canon(), check(), closure(), closure_for(), direct_pins(), hashes(), main(), pinned_versions() (+1 more)

### Community 57 - "Dice and Passphrase Tests"
Cohesion: 0.12
Nodes (13): openDiceTool(), EXPECTED_BITS, generatePassphrase(), armor(), CORPUS, fixture(), meta, openFixture() (+5 more)

### Community 58 - "QR Decoding"
Cohesion: 0.22
Nodes (16): bitmapToImageData(), decodeAllQrImage(), decodeAllQrInFrame(), decodeAttemptEdges(), decodeQrImage(), decodeQrImages(), findAndMask(), findAndMaskTiled() (+8 more)

### Community 59 - "Build ID Precache"
Cohesion: 0.11
Nodes (18): BASE, buildId, FONT_PRECACHE, hash, isPrecachedFont(), listed, missing, OUT_DIR (+10 more)

### Community 60 - "KEYM v3 Fuzzing"
Cohesion: 0.15
Nodes (18): check(), enrolmentIsRefused(), FAST, FIXED_CONTAINER_ID, FIXED_MASTER_KEY, FIXED_SALT, laidOut(), main() (+10 more)

### Community 61 - "QR and Recovery Tests"
Cohesion: 0.15
Nodes (13): encryptText(), encryptAndCaptureQr(), seal(), tab(), verifyOnDecrypt(), box(), ok(), passwordField() (+5 more)

### Community 62 - "shadcn Components Config"
Cohesion: 0.11
Nodes (17): aliases, components, hooks, lib, ui, utils, iconLibrary, rsc (+9 more)

### Community 63 - "Crypto Regression CI"
Cohesion: 0.11
Nodes (17): permissions, runs-on, steps, jobs, crypto-regression, name, on, pull_request (+9 more)

### Community 64 - "v1 Crypto Regression"
Cohesion: 0.22
Nodes (16): b64ToArrayBuffer(), check(), dec, enc, FIXTURES, HERE, hexToArrayBuffer(), main() (+8 more)

### Community 65 - "Recovery Envelope Tests"
Cohesion: 0.12
Nodes (14): big, container, corrupt, CTX, d, f, forged, HERE (+6 more)

### Community 66 - "Dependabot Config"
Cohesion: 0.12
Nodes (16): patterns, github-actions, npm-minor-and-patch, dependency-name, update-types, versions, exclude-patterns, update-types (+8 more)

### Community 67 - "Python Pinned Requirements"
Cohesion: 0.16
Nodes (15): reference/audit-requirements.txt (pinned pip-audit toolchain), typing_extensions==4.16.0, argon2-cffi==25.1.0, argon2-cffi-bindings==26.1.0, cffi==2.1.1, reference/conformance-requirements.txt (hash-pinned CI oracle deps), cryptography==50.0.2, pip hash-checking mode (+7 more)

### Community 68 - "WAV Bit Depth Tests"
Cohesion: 0.18
Nodes (14): ascii(), CASES, cat(), HERE, ok(), out, parses(), rejectsAudioStego() (+6 more)

### Community 69 - "SW Precache Tests"
Cohesion: 0.12
Nodes (13): added, asUrl(), context, handlers, HERE, openedNames, owned, scope (+5 more)

### Community 70 - "UAT Findings"
Cohesion: 0.13
Nodes (15): KEYM v3 slot_table_mac, Verify-only worker transport (no plaintext), P1: no visible text-field focus indicator, U10 Info tooltip focus outline removed, U1 UI freezes during KDF, U20 eval() ungated by wasm-unsafe-eval, U3 Stale-op toast and data loss (B1), U8 Touch targets below minimum (+7 more)

### Community 71 - "Brand Assets and Hero"
Cohesion: 0.15
Nodes (16): Embedded base64 PNG raster in SVG wrapper, Hero Image (phone mockup), IttyBitz branding in mockup, Mobile Encrypt UI (File/Text tabs, password, key file, Encrypt File), Apple Touch Icon, PWA Icon 192x192, PWA Icon 512x512, Keyhole Motif (+8 more)

### Community 72 - "Share Record Encoding"
Cohesion: 0.17
Nodes (9): _b32_encode(), encode_share(), _pack_share_v2(), _forge_share(), Share, _share_checksum(), damaged_copies(), v1_share() (+1 more)

### Community 73 - "Malformed Audio Tests"
Cohesion: 0.23
Nodes (14): ascii(), cat(), dataChunk(), fmtChunk(), HERE, KAUD, kaudHeader(), ok() (+6 more)

### Community 74 - "Repo House Rules"
Cohesion: 0.15
Nodes (13): Base-path build trap before Playwright, reference/bridge.mjs esbuild bridge, Executable documentation gates, House rules (commit identity, PR flow), window.status trap in self-extracting decryptor, CLAUDE.md: Working in this repository, Bet 5: Trust you can test (sealed status), PR pipeline (sabotage, audits, screenshots) (+5 more)

### Community 75 - "CI Reproducible Jobs"
Cohesion: 0.16
Nodes (15): permissions, runs-on, jobs, ci, reproducible, reproducible-elsewhere, reproducible-elsewhere-compare, contents (+7 more)

### Community 76 - "Camera Progress Tests"
Cohesion: 0.15
Nodes (13): again, b32(), dir, entry, forgedStrip(), HERE, LIB, opts (+5 more)

### Community 77 - "Deploy Verify Jobs"
Cohesion: 0.18
Nodes (14): jobs, verify-browser, verify-ci, verify-conformance, verify-crypto, contents, permissions, uses (+6 more)

### Community 78 - "Wordlist Generation"
Cohesion: 0.14
Nodes (10): badChars, byteIdentical, canonical, canonicalSha256, fetched, lines, OUT, problems (+2 more)

### Community 79 - "CI Build Env"
Cohesion: 0.24
Nodes (13): steps, KEYMAKER_BASE_PATH, KEYMAKER_BUILD_ID, KEYMAKER_RELEASE_TAG, steps, steps, steps, env (+5 more)

### Community 80 - "Release Concurrency"
Cohesion: 0.15
Nodes (12): concurrency, cancel-in-progress, group, env, NEXT_TELEMETRY_DISABLED, jobs, name, on (+4 more)

### Community 81 - "Password Policy Tests"
Cohesion: 0.15
Nodes (7): HERE, out, src, block, ROOT, server, work

### Community 82 - "Python Audio Carrier"
Cohesion: 0.17
Nodes (7): _carrier_bytes(), _lsb_bytes(), _round_half_up(), _first_samples(), _r(), _wav_samples16(), _WavLayout

### Community 83 - "Printout Check Tests"
Cohesion: 0.15
Nodes (7): dir, entry, HERE, LIB, nothing, opts, out

### Community 84 - "Secret Erase Worker Tests"
Cohesion: 0.15
Nodes (5): FakeWorker, HERE, OPTIONS, out, src

### Community 85 - "Manifest Verification"
Cohesion: 0.15
Nodes (11): altered, BUNDLE, DEPLOY_CONTROL, expected, FILES_ONLY, MANIFEST, missing, present (+3 more)

### Community 86 - "Sealed Status UI"
Cohesion: 0.29
Nodes (11): BASE_PATH, controllingCacheName(), readCsp(), SealedStatus(), sha256Hex(), verifyCachedBuild(), VerifyOutcome, isSealed() (+3 more)

### Community 87 - "BIP39 Wordlist"
Cohesion: 0.18
Nodes (8): BIP39_WORDLIST, Bip39FailureReason, Bip39ValidationResult, commonPrefix(), osaDistance(), suggestBip39Word(), VALID_WORD_COUNTS, WORD_INDEX

### Community 88 - "Trust Claims and Verify"
Cohesion: 0.24
Nodes (11): Claim Register, Phase 6 Make Trust Claims Checkable, Secret Buffer Ownership (9.4), Tagged Release with Verification Path (6.2), Verify This Build Page (6.3), Version Coherence (6.1), Verifying a Keymaker Deployment, GitHub Build Attestation (SLSA) (+3 more)

### Community 89 - "Roadmap Phase 2"
Cohesion: 0.18
Nodes (12): Accessibility Pass (2.7), Creation Workflow Section 06 (9.6), Crypto in a Web Worker (2.1), In-app Recovery Kit (2.4), KDF Auto-calibration (2.5), Phase 2 Unfreeze and Prove, Phase 9 Assurance Work, Session Auto-lock and Clipboard Hardening (2.6) (+4 more)

### Community 90 - "Landing Page Screens"
Cohesion: 0.17
Nodes (10): Container preview pane (KEYM v3, magic+ver, header fields, 1 slot, AES-256-GCM), Encrypt page (File / Text / Seed phrase content), 01-landing screenshot (Encrypt page), Protection panel (password, Random, Passphrase, Advanced KDF/cipher/key file), Six-step stepper (Content, Access rule, Review, Create, Saved copy, Recovery test), Workspace sidebar (Workspace, Encrypt, Decrypt, Recovery, Audio, Tools, Docs), Container layout: header module, key slots (one highlighted), payload blocks, art-container-blueprint (container cutaway art) (+2 more)

### Community 91 - "Spline Sans Font License"
Cohesion: 0.17
Nodes (12): Spline Sans OFL License File, Reserved Font Name restriction, SIL Open Font License 1.1, Spline Sans font (SorkinType), docs/design/DESIGN-SYSTEM.md, globals.css font stack, Deep Field hero plate (hero-cipher-field.webp), JetBrains Mono Variable font (+4 more)

### Community 92 - "Passkey Binding Tests"
Cohesion: 0.18
Nodes (6): HERE, ok(), out, rejects(), salt, src

### Community 93 - "Seed Grid UI"
Cohesion: 0.27
Nodes (11): Bip39Module, cleanSeedWord(), listOf(), resizeSeedWords(), SEED_WORD_COUNTS, seedCountFor(), SeedGrid(), SeedGridProps (+3 more)

### Community 94 - "Verify Confinement Tests"
Cohesion: 0.17
Nodes (5): BlockedWorker, Record_, seal(), stageVerify(), verifyButton()

### Community 95 - "v2.4 Usability Changes"
Cohesion: 0.22
Nodes (9): Single access policy (test:access-policy), Backup creation steps (status, not wizard), Format detail switch, Keymaker v2.4.0, Single-derivation slot enrolment, S1 Recovery tab reported a change nobody made, S2 Container pane copy promised header bytes, S5 'credentials' wording (+1 more)

### Community 96 - "KEYM v1 Format Spec"
Cohesion: 0.29
Nodes (9): FORMAT.md (KEYM v1 spec), Chained AES-256-GCM then ChaCha20-Poly1305, Legacy IttyBitz Formats (IBTZ v1, headerless v0), NFC Password Normalization, Append-only Fixture Corpus, How Keymaker Works, Frozen Legacy Core (crypto.ts), KDF Downgrade Attack (+1 more)

### Community 97 - "KAUD1 Audio Format"
Cohesion: 0.18
Nodes (7): KAUD1 Audio Carrier Layout, KAUD1 Header, WAV Carrier Reading Procedure, RECOVERY.md, Offline Wheels for Recovery, Share Set Code, Recovery with KMSHARE Strips

### Community 98 - "V2 Header and Bounds"
Cohesion: 0.20
Nodes (8): Aggregate Unlock Cost (keym2UnlockCost), Core Header (8 bytes), Findings F6/F7: Slot-Scoped Rejection Gaps, Migration and Format Freeze, slot_count (1..8), Slot Record (96/112 bytes), Slot Table, Two AADs (payload_aad and slot_aad)

### Community 99 - "Release Workflow Setup"
Cohesion: 0.18
Nodes (11): with, cache, fetch-depth, include-hidden-files, name, node-version, path, pattern (+3 more)

### Community 100 - "PWA Manifest"
Cohesion: 0.18
Nodes (10): background_color, description, display, icons, name, orientation, scope, short_name (+2 more)

### Community 101 - "Worker Protocol Tests"
Cohesion: 0.18
Nodes (7): cases, ENTRY, HERE, listeners, out, posted, scope

### Community 102 - "pip-audit Requirements"
Cohesion: 0.18
Nodes (11): CacheControl==0.14.4, filelock==4.2.3, msgpack==1.2.3, packaging==26.3, pip-api==0.0.35, pip_audit==2.10.1, pip-requirements-parser==32.0.1, platformdirs==4.13.4 (+3 more)

### Community 103 - "WAV Bounds Tests"
Cohesion: 0.24
Nodes (10): ascii(), HERE, ok(), out, rejectsAudioStego(), riff(), round, src (+2 more)

### Community 104 - "Dearmor Whitespace Tests"
Cohesion: 0.20
Nodes (7): clean, HERE, ok(), out, rejects(), secret, src

### Community 105 - "README Scripts Test"
Cohesion: 0.20
Nodes (10): audit, disclaims, escape(), formatSubjects, missing, nowCovered, pkg, readme (+2 more)

### Community 106 - "Release Recipe Test"
Cohesion: 0.18
Nodes (7): blocks, deploy, deploymentBlocks, doc, nextConfig, releaseBlocks, ROOT

### Community 107 - "WebAuthn PRF Passkeys"
Cohesion: 0.33
Nodes (8): assertPasskeyPrf(), enrolPasskey(), PasskeyError, PrfExtensionResults, PrfSupport, readPrfOutput(), sameRawId(), toPasskeyError()

### Community 108 - "Outreach and Trust Boundary"
Cohesion: 0.22
Nodes (7): Self-reviewed Status, What the CSP Does Not Do, Browser Tab Trust Boundary, Phase 8 Outreach Drafts, r/privacy, Show HN and r/crypto Drafts, KM-07 connect-src none, Phase 8 Outreach

### Community 109 - "CI Node Setup"
Cohesion: 0.20
Nodes (10): with, cache, cache-dependency-path, if-no-files-found, name, node-version, path, pattern (+2 more)

### Community 110 - "Deploy Concurrency"
Cohesion: 0.20
Nodes (9): concurrency, cancel-in-progress, group, name, on, push, workflow_dispatch, permissions (+1 more)

### Community 111 - "Deploy Build Env"
Cohesion: 0.22
Nodes (10): steps, steps, KEYMAKER_BASE_PATH, NEXT_TELEMETRY_DISABLED, steps, env, id, name (+2 more)

### Community 112 - "Release Signing Env"
Cohesion: 0.20
Nodes (10): GH_TOKEN, IDENTITY, KEYMAKER_BASE_PATH, KEYMAKER_CERT_IDENTITY, KEYMAKER_RELEASE_TAG, REF, REF_TYPE, REPO (+2 more)

### Community 113 - "Release Verify Gates"
Cohesion: 0.20
Nodes (10): verify-conformance, verify-crypto, contents, permissions, needs, permissions, uses, needs (+2 more)

### Community 114 - "v1 Crosstest"
Cohesion: 0.33
Nodes (5): check(), js(), js_decrypt(), js_encrypt(), main()

### Community 115 - "CSP Hash Injection"
Cohesion: 0.20
Nodes (7): ALLOWED_SCRIPT_SRC, htmlFiles(), leaked, leaky, OUT_DIR, uncovered, wasmless

### Community 116 - "Build Manifest"
Cohesion: 0.20
Nodes (9): DEPLOY_CONTROL, entries, lines, MANIFEST, manifestDigest, OUT_DIR, SELF, totalBytes (+1 more)

### Community 117 - "Reproducible Build Check"
Cohesion: 0.22
Nodes (7): alternate, digestTree(), first, OUT, ROOT, second, walk()

### Community 118 - "Rehearsal Tests"
Cohesion: 0.36
Nodes (7): dialog(), enableShares(), openButton(), printedRehearsalBox(), rehearsalInput(), result(), sealWithShares()

### Community 119 - "V2 Passphrase KDF Slot"
Cohesion: 0.25
Nodes (8): Argon2id, kdf_input Length-Prefixed Encoding (LP), Key File Digest (hashed first), KM-05 Ambiguous Password||Keyfile Encoding, NFC_UTF8 Password Normalization, Passphrase Slot (slot_type 0x00), PBKDF2-HMAC-SHA-256, WebCrypto-Only Subset (self-extracting page)

### Community 120 - "V2 Armor and Share Text"
Cohesion: 0.31
Nodes (9): Crockford Base32 Share Encoding, IGNORABLE Character Set, keym2: Text Armor (base64url, 64-col wrap), KMPART1 Paper Parts, KMPART2 Paper Parts (cid, length, part_checksum), KMSHARE1 Share Record (42 bytes), KMSHARE2 Share Record (66 bytes), Set Code (XXXX-XXXX) (+1 more)

### Community 121 - "CI Node Matrix"
Cohesion: 0.25
Nodes (9): dir, id, node, channel, include, strategy, strategy, fail-fast (+1 more)

### Community 122 - "Deploy Node Setup"
Cohesion: 0.22
Nodes (9): with, cache, include-hidden-files, name, node-version, path, pattern, persist-credentials (+1 more)

### Community 123 - "Release Preflight"
Cohesion: 0.36
Nodes (9): steps, preflight, runs-on, steps, steps, steps, name, run (+1 more)

### Community 124 - "Argon2 Blob Check"
Cohesion: 0.22
Nodes (7): actual, chunksDir, dist, HERE, m, ROOT, worker

### Community 125 - "Self-Extract Decryptor"
Cohesion: 0.22
Nodes (7): chunkLayout() payload chunk sizes (5.1), decrypt() KEYM v2 container, PBKDF2 iteration bounds 1..10,000,000 (6), lp() length-prefix encoding (4.1), nonceFor() uint88_be(i)||final_flag (5.2), openAesGcm() WebCrypto AES-256-GCM decrypt, slotKeyFor() PBKDF2-HMAC-SHA-256 slot key

### Community 126 - "Release Gate Test"
Cohesion: 0.28
Nodes (6): ancestors(), jobBlock(), needsOf(), ROOT, SUITES, WF

### Community 127 - "Seed Mode Tests"
Cohesion: 0.31
Nodes (7): ARMOR_PREFIXES, cell(), encryptButton(), enterSeedMode(), fillGrid(), sealGrid(), status()

### Community 128 - "Screenshot Capture"
Cohesion: 0.29
Nodes (5): HERE, settle(), shotRegion(), SHOTS, VIEWPORT

### Community 129 - "CI Triggers"
Cohesion: 0.25
Nodes (7): env, NEXT_TELEMETRY_DISABLED, name, on, pull_request, workflow_dispatch, permissions

### Community 130 - "Deploy Signing"
Cohesion: 0.25
Nodes (8): permissions, sign, id-token, pages, if, needs, permissions, runs-on

### Community 131 - "Self-Extract Fixture"
Cohesion: 0.29
Nodes (6): Cross-implementation tamper rejection with untampered control, dearmor() keym2: base64url decoding, FORMAT-V2-DESIGN.md 7.2 WebCrypto-only subset, Embedded KEYM2 armored container (KEYM2-BEGIN/END sentinel), keym2.py decrypt --in backup.html fallback, v2 self-extracting backup fixture page

### Community 132 - "Reproduced Manifest Test"
Cohesion: 0.29
Nodes (5): BASE, CHECKER, manifest(), root, run()

### Community 133 - "Encrypt Input Erase Test"
Cohesion: 0.25
Nodes (5): HERE, OPTIONS, out, plaintext, src

### Community 134 - "Wordlist Verification"
Cohesion: 0.25
Nodes (6): canonical, digest, duplicates, lengths, malformed, unique

### Community 135 - "Async Guard Tests"
Cohesion: 0.36
Nodes (6): announcements(), confirmRaceOpened(), measureOperation(), prepareEncrypt(), SLOW_KDF, startOperation()

### Community 136 - "Deploy Environment"
Cohesion: 0.29
Nodes (7): environment, if, needs, runs-on, name, url, deploy

### Community 137 - "Release Attestations"
Cohesion: 0.29
Nodes (7): sign, attestations, id-token, if, needs, permissions, runs-on

### Community 138 - "Sigstore Signing"
Cohesion: 0.29
Nodes (5): sigstore@5.0.0, sigstore, BUNDLE, MANIFEST, OUT

### Community 139 - "CycloneDX SBOM Deps"
Cohesion: 0.29
Nodes (7): boolean.py==5.0, cyclonedx-python-lib==11.12.0, defusedxml==0.7.1, license-expression==30.4.4, packageurl-python==0.17.6, py-serializable==2.1.0, sortedcontainers==2.4.0

### Community 140 - "Reference Impl README"
Cohesion: 0.38
Nodes (5): bridge.mts black-box CLI, docs/FORMAT.md (KEYM v1 spec), Frozen append-only fixtures (scripts/fixtures/keymaker/), KEYM v1 Python reference implementation, npm run test:conformance (bidirectional Python vs TypeScript)

### Community 141 - "CSP Egress Gate"
Cohesion: 0.52
Nodes (4): EGRESS_DIRECTIVES, egressViolations(), pickDirective(), names()

### Community 142 - "Screenshot Audit"
Cohesion: 0.29
Nodes (5): files, heights, HERE, offenders, SHOTS

### Community 143 - "Failure Reporting Tests"
Cohesion: 0.29
Nodes (4): attemptDecrypt(), BlockedWorker, chooseOnDecrypt(), OUT

### Community 144 - "Owned Buffer Tests"
Cohesion: 0.29
Nodes (3): Caught, KEY_BYTES, SECRET_BYTES

### Community 145 - "Release Tag Input"
Cohesion: 0.33
Nodes (6): release-tag, workflow_call, default, required, type, inputs

### Community 146 - "Release Verify CI"
Cohesion: 0.33
Nodes (6): verify-ci, needs, permissions, uses, with, release-tag

### Community 147 - "release (small)"
Cohesion: 0.40
Nodes (5): publish, if, needs, permissions, runs-on

### Community 148 - "audit-requirements (small)"
Cohesion: 0.40
Nodes (5): certifi==2026.10.18, charset-normalizer==3.5.2, idna==3.20, requests==2.34.2, urllib3==2.8.0

### Community 149 - "page (small)"
Cohesion: 0.50
Nodes (4): Command(), isCommit, metadata, VerifyBuild()

### Community 150 - "deploy (small)"
Cohesion: 0.50
Nodes (4): needs, permissions, runs-on, build

### Community 151 - "release (small)"
Cohesion: 0.50
Nodes (4): needs, permissions, runs-on, build

### Community 152 - "release (small)"
Cohesion: 0.50
Nodes (4): verify-browser, needs, permissions, uses

### Community 153 - "art-cipher-field (small)"
Cohesion: 0.50
Nodes (4): art-cipher-field (data stream into keyhole art), Glowing keyhole vault fed by cube data stream, Dark background with blue/orange accent palette, hero-cipher-field (blue/orange light streak hero background)

### Community 154 - "audit-requirements (small)"
Cohesion: 0.50
Nodes (4): markdown-it-py==4.2.0, mdurl==0.1.2, Pygments==2.21.0, rich==15.0.0

### Community 155 - "build-recovery-kit (small)"
Cohesion: 0.50
Nodes (3): DEST, KIT, ROOT

## Ambiguous Edges - Review These
- `House rules (commit identity, PR flow)` → `PR pipeline (sabotage, audits, screenshots)`  [AMBIGUOUS]
  docs/design/TEN-X-PLAN.md · relation: conceptually_related_to
- `Graphite design system` → `Verdict: keep Nightpaper, extend not repaint`  [AMBIGUOUS]
  docs/design/DESIGN-SYSTEM.md · relation: conceptually_related_to
- `Spline Sans font (SorkinType)` → `Plus Jakarta Sans Variable font`  [AMBIGUOUS]
  scripts/og-card-template.html · relation: semantically_similar_to
- `IttyBitz branding in mockup` → `Keymaker Logo (keyhole squircle)`  [AMBIGUOUS]
  docs/hero.svg · relation: conceptually_related_to
- `Key split into three shards linked to central lock (threshold sharing)` → `Six-step stepper (Content, Access rule, Review, Create, Saved copy, Recovery test)`  [AMBIGUOUS]
  public/art-key-shards.webp · relation: conceptually_related_to
- `Screenshot: Seed Detection` → `Seed phrase detection`  [AMBIGUOUS]
  docs/screenshots/02-seed-detection.png · relation: references

## Knowledge Gaps
- **142 isolated node(s):** `RFC-5869`, `RFC-9106`, `RFC-5869`, `PBKDF2`, `ARGON2ID` (+137 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1480 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `KEYM v2 Container Format Specification` connect `Format V3/V4 Review Briefs` to `KEYM v1 Format Spec`, `keym2.py Reference Core`, `V2 Header and Bounds`, `v1 Crypto and Regression`, `V2 Spec Payload and Findings`, `Container Inspector UI`, `Roadmap Cut Features`?**
  _High betweenness centrality (0.171) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `main()` (e.g. with `.pack()` and `.pack_prefix()`) actually correct?**
  _`main()` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `RFC-5869`, `RFC-9106`, `RFC-5869` to the rest of the system?**
  _142 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Shamir Secret Sharing TS` be split into smaller, more focused modules?**
  _Cohesion score 0.05512016718913271 - nodes in this community are weakly interconnected._
- **Why does `@playwright/test` connect `Browser Test Helpers` to `Screenshot Capture`, `npm Dependencies`, `Async Guard Tests`, `Build and Deploy Scripts`, `Sealed Status Audio Tests`, `Shamir and Paper UI Tests`, `Icon Audit and SW Tests`, `Failure Reporting Tests`, `Owned Buffer Tests`, `Passkey and Calibration Tests`, `Palette Contrast Audit`, `Rehearsal Tests`, `Dice and Passphrase Tests`, `QR and Recovery Tests`, `Verify Confinement Tests`, `Seed Mode Tests`?**
  _High betweenness centrality (0.048) - this node is a cross-community bridge._

### Low-confidence Hints
_AMBIGUOUS edges — the extractor was unsure. Verify before acting on these._

- **What is the exact relationship between `House rules (commit identity, PR flow)` and `PR pipeline (sabotage, audits, screenshots)`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **What is the exact relationship between `Graphite design system` and `Verdict: keep Nightpaper, extend not repaint`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._