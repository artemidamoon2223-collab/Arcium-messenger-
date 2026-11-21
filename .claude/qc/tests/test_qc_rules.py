"""Risk classification of this repository's own files (qc.py RULES).

Pins the classes of the files that hold keys, wire formats, identities and
stored records, of one file under every rule, and of every file under every
directory rule, so that narrowing any rule (dropping a class, or cutting a
directory rule down to fewer paths), or renaming or removing a pinned file,
fails here instead of silently dropping a review or an owner gate. Code moved into a new file gets only its
directory's classes: the new file needs a rule in qc.py and a line in
EXPECTED. RulesTest reads the checkout
and writes nothing; GateTest runs qc.py in a throwaway repository, like the
other QC tests.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from test_qc import PASSING, PY, Repo

QC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(os.path.dirname(QC_DIR))

_spec = importlib.util.spec_from_file_location("qc_rules_under_test", os.path.join(QC_DIR, "qc.py"))
qc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(qc)

KT = "android/app/src/main/kotlin/com/arcium/messenger/"

# path -> the exact classes it must get. Every path must exist in the checkout.
EXPECTED = {
    "crates/mobile-ffi/src/lib.rs": {"FFI", "CRYPTO", "PROTOCOL", "IDENTITY", "DURABLE_STATE"},
    "crates/mobile-ffi/src/identity.rs": {"FFI", "IDENTITY", "CRYPTO", "DURABLE_STATE"},
    "crates/mobile-ffi/src/prekeys.rs": {"FFI", "CRYPTO", "PROTOCOL", "DURABLE_STATE"},
    "crates/mobile-ffi/src/handshake.rs": {"FFI", "CRYPTO", "PROTOCOL"},
    "crates/mobile-ffi/src/responder.rs": {"FFI", "CRYPTO", "PROTOCOL", "DURABLE_STATE"},
    "crates/mobile-ffi/src/messaging_api.rs": {"FFI", "PROTOCOL", "DURABLE_STATE"},
    "crates/mobile-ffi/src/contacts.rs": {"FFI", "IDENTITY", "CRYPTO", "PROTOCOL", "DURABLE_STATE"},
    "crates/mobile-ffi/src/error.rs": {"FFI"},
    "crates/mobile-ffi/src/plaintext.rs": {"FFI"},
    "crates/mobile-ffi/src/network.rs": {"FFI", "NETWORK", "PROTOCOL", "DURABLE_STATE"},
    "crates/mobile-ffi/src/network/wire.rs": {"FFI", "NETWORK", "PROTOCOL", "DURABLE_STATE"},
    "crates/mobile-ffi/src/network/inbox.rs": {"FFI", "NETWORK", "PROTOCOL", "DURABLE_STATE"},
    "crates/mobile-ffi/src/network/chat.rs": {"FFI", "NETWORK", "PROTOCOL", "DURABLE_STATE"},
    "crates/mobile-ffi/src/network/far_skip.rs": {"FFI", "NETWORK", "PROTOCOL", "DURABLE_STATE"},
    "crates/core-crypto/src/x3dh.rs": {"CRYPTO"},
    "crates/core-protocol/src/messaging.rs": {"DURABLE_STATE", "PROTOCOL"},
    "crates/core-storage/src/lib.rs": {"DURABLE_STATE", "CRYPTO"},
    "crates/relay/src/server.rs": {"NETWORK", "PROTOCOL"},
    "crates/relay/Cargo.toml": {"NETWORK", "PROTOCOL", "SUPPLY_CHAIN"},
    "crates/core-transport/src/lib.rs": {"NETWORK"},
    KT + "security/MasterKeyProvider.kt": {"ANDROID_LIFECYCLE", "IDENTITY", "CRYPTO"},
    KT + "ffi/ArciumCore.kt": {"ANDROID_LIFECYCLE", "FFI", "CRYPTO", "IDENTITY"},
    KT + "ffi/Plaintext.kt": {"ANDROID_LIFECYCLE", "FFI"},
    KT + "data/IdentityRepository.kt": {"ANDROID_LIFECYCLE", "IDENTITY"},
    KT + "data/MessageRepository.kt": {"ANDROID_LIFECYCLE", "PROTOCOL", "IDENTITY"},
    KT + "messaging/RelayRules.kt": {"ANDROID_LIFECYCLE", "NETWORK"},
    KT + "messaging/RelaySettings.kt": {"ANDROID_LIFECYCLE", "NETWORK"},
    KT + "messaging/MessengerService.kt": {"ANDROID_LIFECYCLE", "NETWORK"},
    KT + "messaging/BackgroundReceiveService.kt": {"ANDROID_LIFECYCLE", "NETWORK"},
    KT + "messaging/ContactCardText.kt": {"ANDROID_LIFECYCLE", "NETWORK", "IDENTITY", "PROTOCOL"},
    KT + "startup/StoreStartup.kt": {"ANDROID_LIFECYCLE", "CRYPTO", "DURABLE_STATE"},
    KT + "startup/AppStartup.kt": {"ANDROID_LIFECYCLE"},
    KT + "ui/contacts/AddContactViewModel.kt": {"ANDROID_LIFECYCLE", "IDENTITY"},
    KT + "ui/contacts/AddContactScreen.kt": {"ANDROID_LIFECYCLE", "IDENTITY"},
    KT + "ui/navigation/IdentityGate.kt": {"ANDROID_LIFECYCLE", "IDENTITY"},
    KT + "ui/onboarding/OnboardingViewModel.kt": {"ANDROID_LIFECYCLE", "IDENTITY"},
    KT + "ui/theme/Theme.kt": {"ANDROID_LIFECYCLE"},
    "vendor/tor-dirmgr/src/lib.rs": {"SUPPLY_CHAIN"},
    "arcium-psi/programs/arcium-psi/src/lib.rs": {"PSI"},
    "android/app/build.gradle.kts": {"ANDROID_LIFECYCLE", "SUPPLY_CHAIN"},
    ".github/workflows/arcium-ci.yml": {"CI_INTEGRITY"},
    ".cargo/audit.toml": {"SUPPLY_CHAIN"},
    ".devcontainer/setup.sh": {"SUPPLY_CHAIN"},
    "Cargo.lock": {"SUPPLY_CHAIN"},
    "CLAUDE.md": {"AGENT_CONTROL"},
    ".claude/qc/qc.py": {"AGENT_CONTROL"},
}

# directory rule -> the classes every file under it must get (at least).
EXPECTED_DIRS = {
    "crates/core-crypto/": {"CRYPTO"},
    "crates/core-storage/": {"CRYPTO", "DURABLE_STATE"},
    "crates/core-protocol/": {"DURABLE_STATE", "PROTOCOL"},
    "crates/mobile-ffi/src/network": {"FFI", "NETWORK", "PROTOCOL", "DURABLE_STATE"},
    "crates/mobile-ffi/": {"FFI"},
    "crates/relay/": {"NETWORK", "PROTOCOL"},
    "crates/core-transport/": {"NETWORK"},
    KT + "security/": {"ANDROID_LIFECYCLE", "CRYPTO", "IDENTITY"},
    KT + "ffi/": {"ANDROID_LIFECYCLE", "FFI"},
    KT + "messaging/": {"ANDROID_LIFECYCLE", "NETWORK"},
    KT + "ui/contacts/": {"ANDROID_LIFECYCLE", "IDENTITY"},
    KT + "ui/onboarding/": {"ANDROID_LIFECYCLE", "IDENTITY"},
    "android/": {"ANDROID_LIFECYCLE"},
    "vendor/": {"SUPPLY_CHAIN"},
    "arcium-psi/": {"PSI"},
    ".github/": {"CI_INTEGRITY"},
    ".cargo/": {"SUPPLY_CHAIN"},
    ".devcontainer/": {"SUPPLY_CHAIN"},
    ".claude/": {"AGENT_CONTROL"},
}

# Directories never part of the change set (qc.py TRUSTED_BUILD_DIRS and their kin).
SKIP_DIRS = {".git", "target", "build", "node_modules", ".gradle"}


def classes(path):
    return set(qc.classify_paths([path])[path])


def files_under(prefix):
    """Every file of the checkout whose path starts with `prefix` (build output skipped)."""
    out = []
    parent = prefix if prefix.endswith("/") else os.path.dirname(prefix) + "/"
    for d, subdirs, names in os.walk(os.path.join(REPO, parent)):
        subdirs[:] = [s for s in subdirs if s not in SKIP_DIRS]
        for name in names:
            rel = os.path.relpath(os.path.join(d, name), REPO).replace(os.sep, "/")
            if rel.startswith(prefix):
                out.append(rel)
    return out


class RulesTest(unittest.TestCase):
    def test_the_pinned_files_exist(self):
        missing = [p for p in EXPECTED if not os.path.isfile(os.path.join(REPO, p))]
        self.assertEqual(missing, [], "update EXPECTED with the code's new location")

    def test_security_files_get_exactly_their_classes(self):
        wrong = {p: sorted(classes(p)) for p, want in EXPECTED.items() if classes(p) != want}
        self.assertEqual(wrong, {})

    def test_every_rule_has_a_pinned_file(self):
        # So that dropping a class from any rule changes some pinned file's classes.
        unpinned = [prefix for prefix, _ in qc.RULES
                    if not any(p == prefix or p.startswith(prefix) for p in EXPECTED)]
        self.assertEqual(unpinned, [])

    def test_every_directory_rule_is_pinned(self):
        dirs = [prefix for prefix, _ in qc.RULES if not os.path.isfile(os.path.join(REPO, prefix))]
        self.assertEqual(sorted(dirs), sorted(EXPECTED_DIRS))

    def test_every_file_under_a_directory_rule_gets_its_classes(self):
        short = {}
        for prefix, want in EXPECTED_DIRS.items():
            found = files_under(prefix)
            self.assertTrue(found, prefix)
            for rel in found:
                if not want <= classes(rel):
                    short[rel] = sorted(want - classes(rel))
        self.assertEqual(short, {})

    def test_every_code_file_that_names_crypto_has_an_owner_gated_rule(self):
        # The content markers only fall back for a change; what is committed needs a path rule.
        ungated = {}
        for d, subdirs, names in os.walk(REPO):
            subdirs[:] = [s for s in subdirs if s not in SKIP_DIRS]
            for name in names:
                rel = os.path.relpath(os.path.join(d, name), REPO).replace(os.sep, "/")
                if not qc.is_scanned_code(rel):
                    continue
                with open(os.path.join(REPO, rel), encoding="utf-8", errors="replace") as f:
                    found = qc.file_marker_classes(f.read(), path=rel)
                if found and not classes(rel) & qc.OWNER_GATED:
                    ungated[rel] = sorted(found)
        self.assertEqual(ungated, {}, "give each a path rule in qc.py RULES and a line in EXPECTED")

    def test_markers_read_code_not_comments_or_strings(self):
        # One sample per marker, so dropping one from CRYPTO_CODE_RE or PROTOCOL_CODE_RE fails here.
        crypto = [
            "use core_crypto::ratchet::DoubleRatchet;", "use core_crypto::{x3dh, ratchet};", "impl KeyInit for X {}",
            "use chacha20::ChaCha20;", "use poly1305::Poly1305;", "val p = EncryptedSharedPreferences.create(a)",
            "val f = EncryptedFile.Builder(c, file, k, s)",
            "let r = DoubleRatchet::init_bob(k, s);", "use core_storage::EncryptedStore;",
            "fn open(s: &EncryptedStore) {}", "let c = RescueCipher::new(k);", "use aead::{Aead, KeyInit};",
            "impl AeadInPlace for X {}", "use zeroize::Zeroizing;", "buf.zeroize();", "#[derive(ZeroizeOnDrop)]",
            "use subtle::ConstantTimeEq;", "if a.ct_eq(&b).into() {}", "use ring::signature;",
            "let k = PrivateKeyDer::from(d);", "let k = PrivatePkcs8KeyDer::from(d);",
            "let k = StaticSecret::random_from_rng(OsRng);", "let e = EphemeralSecret::random();",
            "let r = ReusableSecret::random();", "let s: SharedSecret = a.diffie_hellman(&b);",
            "let s = SigningKey::from_bytes(&b);", "let v = VerifyingKey::from_bytes(&b);",
            "use x25519_dalek::PublicKey;", "use ed25519_dalek::Signer;", "use curve25519_dalek::edwards;",
            "use chacha20poly1305::KeyInit;", "let c = XChaCha20Poly1305::new(k);", "let c = ChaCha20Poly1305::new(k);",
            "use aes_gcm::Aes256Gcm;", "use aes_gcm_siv::Aes256GcmSiv;", "let c = Aes128Gcm::new(k);",
            "use hkdf::Hkdf;", "let h = Hkdf::<Sha256>::new(None, ikm);", "use hmac::Mac;", "type M = HmacSha256;",
            "use sha2::Digest;", "let d = Sha256::digest(x);", "let d = Sha512_256::digest(x);", "use sha3::Digest;",
            "let d = Sha3_256::digest(x);", "use ml_kem::kem::Decapsulate;", "let k = MlKem768::generate(r);",
            "use blake3::hash;", "let h = Blake2b512::new();", "use argon2::Argon2;", "use pbkdf2::pbkdf2_hmac;",
            "use scrypt::Params;", "import javax.crypto.Cipher", "val c = Cipher.getInstance(t)",
            "val g = KeyGenerator.getInstance(a)", "val g = KeyPairGenerator.getInstance(a)",
            "val ks = KeyStore.getInstance(\"AndroidKeyStore\")", "val spec = KeyGenParameterSpec.Builder(a, p)",
            "val p = GCMParameterSpec(128, iv)", "val p = IvParameterSpec(iv)", "val d = MessageDigest.getInstance(a)",
            "val k: SecretKey = g.generateKey()", "val k = SecretKeySpec(b, a)", "val mk = MasterKey.Builder(ctx)",
            "val s = Signature.getInstance(a)", "val m = Mac.getInstance(a)",
            # code after a closed block comment, a deref, a char literal, raw and Kotlin strings
            "/* x */ let k = Hkdf::new(None, ikm);", "*/ let k = Hkdf::new(None, ikm);",
            "*out = Sha256::digest(b).into();",
            # each literal form misread would swallow the code up to the next quote
            "let q = '\"'; let k = Hkdf::new(None, ikm); let s = \"y\";",
            'let r = r"x\\"; let k = Hkdf::new(None, ikm); let s = "y";',
            'val s = """a"b"""; Cipher.getInstance(x)', 'let b = br##"x"##; let k = Hkdf::new(None, i);',
            'RandomAccessFile(f, "r"); val md = MessageDigest.getInstance("SHA-256")',
        ]
        protocol = ["const PROTOCOL_VERSION: u8 = 1;", "const CIPHER_SUITE: u8 = 1;",
                    "pub(crate) const CHAT_RECORD_V2: u8 = 2;", "const X_FORMAT_V1: u8 = 1;",
                    "const OPEN_HANDSHAKE_V3: usize = 84;", "const PEER_CARD_V1: u8 = 1;",
                    "const NOTE_REFUSAL_V1: u8 = 1;", "const RELAY_PROTOCOL_V2: &str = x;"]
        neither = ["/// Derived with Hkdf over the X3DH output.", "    * the `CONTACT_CARD_V1` text form",
                   "* Hkdf in KDoc", "/* Hkdf */", "let msg = \"Hmac check failed\";", 'let s = r#"Hkdf"#;',
                   'let s = r#"a "Hkdf" b"#;', 'val s = """Cipher"""', 'val s = """a "Cipher" b"""', "let url = \"https://relay\"; // signed with SigningKey",
                   "val id = SecureRandom().nextBytes(b)", "let c = 'H';", "fn f<'a>(x: &'a str) {}",
                   "let msg = \"say \\\"Hkdf\\\" now\";", "let ciphertext = seal(x);", "val Ciphers = listOf()", "let ring_buffer = Ring::new();"]
        for line in crypto:
            self.assertEqual(qc.code_marker_classes(line), {"CRYPTO"}, line)
        for line in protocol:
            self.assertEqual(qc.code_marker_classes(line), {"PROTOCOL"}, line)
        for line in neither:
            self.assertEqual(qc.code_marker_classes(line), set(), line)

    def test_literals_and_comments_are_followed_across_lines(self):
        cases = {
            # code after the line that closes a multi-line string
            'let s = "line one\nline text"; let _ = hkdf::Hkdf::<sha2::Sha256>::new(None, i); let _ = "x";': {"CRYPTO"},
            'val s = """\n  text\n""".trimIndent() + Cipher.getInstance("AES")': {"CRYPTO"},
            'let r = r#"a\nb"#; let k = Hkdf::new(None, i);': {"CRYPTO"},
            # names inside a multi-line string or block comment
            'let s = "a\nHkdf b";\nfn f() {}': set(),
            '/*\nHkdf here\nand Cipher\n*/\nfn f() {}': set(),
            'val s = """\n Cipher.getInstance(x)\n"""': set(),
        }
        for text, want in cases.items():
            self.assertEqual(qc.file_marker_classes(text), want, text)
        by_language = [
            # a Kotlin raw string that ends in a quote, and the code of `${…}` templates with strings inside
            ('val s = """say "hi""""\nval k = KeyStore.getInstance(x)', "a.kt", {"CRYPTO"}),
            ('val p = "${glob("src/*")}"\nval c = Cipher.getInstance(t)', "a.kt", {"CRYPTO"}),
            ('val u = "${host("https://x")}"; val c = Cipher.getInstance(t)', "a.kt", {"CRYPTO"}),
            ("val q = \"${'\"'}\"; val c = Cipher.getInstance(t)", "a.kt", {"CRYPTO"}),
            ('val s = "${Cipher.getInstance(t)}"', "a.kt", {"CRYPTO"}),
            ('val s = "Cipher $x"', "a.kt", set()),
            ('val s = "${x.map { "Cipher" }}"', "a.kt", set()),
            ('val s = "${x.let { it }.also { Cipher.getInstance(t) }}"', "a.kt", {"CRYPTO"}),
            # TypeScript quotes and template literals
            ("const p = 'src/*'; const s: SigningKey = k;", "a.ts", {"CRYPTO"}),
            ('const t = `say "hi`; const s: SigningKey = k;', "a.ts", {"CRYPTO"}),
            ("const m = 'Hkdf';", "a.ts", set()),
            ("const m = `a ${'Hkdf'} b`;", "a.ts", set()),
            ("const m = `a ${new Hkdf(x)} b`;", "a.ts", {"CRYPTO"}),
            # a whole file knows its comments: a `*` line outside one is code
            ("let x = a\n    * Sha256::digest(b);", "a.rs", {"CRYPTO"}),
            ("/**\n * Hkdf here\n */\nfn f() {}", "a.rs", set()),
            ('char c = \'"\'; Cipher x = Cipher.getInstance(t);', "A.java", {"CRYPTO"}),
        ]
        for text, path, want in by_language:
            self.assertEqual(qc.file_marker_classes(text, path=path), want, (path, text))
        self.assertEqual(qc.file_marker_classes('let s = "a\nb"; use hkdf::Hkdf;\nfn f() {}', [0]), set())
        self.assertEqual(qc.file_marker_classes('let s = "a\nb"; use hkdf::Hkdf;\nfn f() {}', [1]), {"CRYPTO"})

    def test_test_files_are_not_scanned(self):
        for p in ("crates/mobile-ffi/src/tests/far_skip.rs", "crates/mobile-ffi/src/network/tests.rs",
                  "crates/relay/src/v2_tests.rs", "crates/core-crypto/tests/x3dh_vectors.rs",
                  KT.replace("src/main/", "src/test/") + "X.kt", "android/app/src/androidTest/A.kt",
                  "android/e2e/two_devices.kt", "arcium-psi/tests/src/crypto.test.ts"):
            self.assertFalse(qc.is_scanned_code(p), p)
        for p in ("crates/mobile-ffi/src/kdf.rs", KT + "ui/chat/Contest.kt", "crates/relay/src/attest.rs"):
            self.assertTrue(qc.is_scanned_code(p), p)

    def test_the_owner_gate_set_is_pinned(self):
        # The rules give the classes; this pins which of them stop a loop for the Owner.
        self.assertLessEqual({"CRYPTO", "PROTOCOL", "SUPPLY_CHAIN", "PSI", "CI_INTEGRITY", "AGENT_CONTROL"},
                             qc.OWNER_GATED)

    def test_vendored_code_is_supply_chain(self):
        for p in ("vendor/tor-dirmgr/src/storage/sqlite.rs", "vendor/tor-dirmgr/testdata/microdescs.txt",
                  "vendor/README.md"):
            self.assertIn("SUPPLY_CHAIN", classes(p), p)
            self.assertIn("SUPPLY_CHAIN", qc.OWNER_GATED)

    def test_every_source_file_has_a_security_class(self):
        exts = (".rs", ".kt", ".ts", ".py", ".sh")
        unclassified = []
        for top in ("crates", "android", "arcium-psi", "vendor"):
            for d, subdirs, files in os.walk(os.path.join(REPO, top)):
                subdirs[:] = [s for s in subdirs if s not in SKIP_DIRS]
                for name in files:
                    if name.endswith(exts):
                        rel = os.path.relpath(os.path.join(d, name), REPO).replace(os.sep, "/")
                        if not classes(rel) & qc.SECURITY_CLASSES:
                            unclassified.append(rel)
        self.assertEqual(unclassified, [])

    def test_a_new_file_beside_pinned_ones_keeps_its_directory_classes(self):
        # Exact-file rules do not reach a new file; the directory rules still do.
        self.assertLessEqual({"FFI"}, classes("crates/mobile-ffi/src/new_module.rs"))
        self.assertLessEqual({"FFI", "NETWORK", "PROTOCOL"}, classes("crates/mobile-ffi/src/network/new_part.rs"))
        self.assertLessEqual({"ANDROID_LIFECYCLE", "NETWORK"}, classes(KT + "messaging/NewThing.kt"))


class GateTest(unittest.TestCase):
    """What the classification does to a real change: reviews, skills and the owner gate."""

    FILES = ("crates/mobile-ffi/src/handshake.rs", "crates/mobile-ffi/src/prekeys.rs",
             KT + "startup/StoreStartup.kt", "vendor/tor-dirmgr/src/lib.rs")

    def setUp(self):
        self.parent = tempfile.mkdtemp(prefix="qc-parent-")
        self.r = Repo(parent=self.parent)
        for rel in self.FILES:
            self.r.write(rel, "// v1\n")
        self.r.git("add", "-A")
        self.r.git("commit", "-qm", "files")
        self.r.base = self.r.git("rev-parse", "HEAD").strip()

    def tearDown(self):
        shutil.rmtree(self.parent, ignore_errors=True)

    def classify(self, sid):
        p = subprocess.run([PY, ".claude/qc/qc.py", "classify", sid], cwd=self.r.dir, capture_output=True,
                           text=True, env=self.r.env())
        return json.loads(p.stdout)

    def test_a_handshake_change_needs_the_owner_and_both_reviews(self):
        self.r.locked("t-hs", [PASSING])
        self.r.write("crates/mobile-ffi/src/handshake.rs", "// v2\n")
        out = self.classify("t-hs")
        self.assertEqual(out["owner_gated"], ["CRYPTO", "PROTOCOL"])
        self.assertEqual(out["required_reviews"], ["engineering-code-review", "arcium-security-review"])
        self.assertEqual(out["load_with_security_review"], ["android-uniffi-bridge"])
        rc, line = self.r.qc("run", "t-hs")
        self.assertIn("ESCALATE_TO_OWNER", line)
        self.assertIn("owner-gated", line)

    def test_an_authorized_handshake_change_is_not_escalated(self):
        self.r.locked("t-hs-ok", [PASSING], owner_authorizes=["CRYPTO", "PROTOCOL"])
        self.r.write("crates/mobile-ffi/src/handshake.rs", "// v2\n")
        rc, line = self.r.qc("run", "t-hs-ok")
        # The criteria pass; what is left is the two reviews, not the Owner.
        self.assertIn("QC_STATE: NOT_VERIFIED", line)
        self.assertNotIn("ESCALATE_TO_OWNER", line)
        self.assertIn("review", line)

    def test_a_prekey_record_change_loads_the_durable_state_skill(self):
        self.r.locked("t-pk", [PASSING])
        self.r.write("crates/mobile-ffi/src/prekeys.rs", "// v2\n")
        self.assertEqual(self.classify("t-pk")["load_with_security_review"],
                         ["android-uniffi-bridge", "mbr-integration"])

    def test_store_startup_and_vendored_code_are_owner_gated(self):
        self.r.locked("t-sv", [PASSING])
        self.r.write(KT + "startup/StoreStartup.kt", "// v2\n")
        self.r.write("vendor/tor-dirmgr/src/lib.rs", "// v2\n")
        self.assertEqual(self.classify("t-sv")["owner_gated"], ["CRYPTO", "SUPPLY_CHAIN"])

    def test_crypto_code_in_a_new_file_is_owner_gated(self):
        self.r.locked("t-new", [PASSING])
        self.r.write("crates/mobile-ffi/src/kdf.rs", "//! Keys.\nuse hkdf::Hkdf;\nuse sha2::Sha256;\n")
        out = self.classify("t-new")
        self.assertEqual(out["content_classes"], {"crates/mobile-ffi/src/kdf.rs": ["CRYPTO"]})
        self.assertEqual(out["paths"]["crates/mobile-ffi/src/kdf.rs"], ["CRYPTO", "FFI"])
        self.assertEqual(out["owner_gated"], ["CRYPTO"])
        rc, line = self.r.qc("run", "t-new")
        self.assertIn("ESCALATE_TO_OWNER", line)
        self.assertIn("owner-gated", line)

    def test_a_wire_format_or_key_store_in_an_android_file_is_owner_gated(self):
        self.r.write(KT + "ui/theme/Theme.kt", "package x\n")
        self.r.git("add", "-A")
        self.r.git("commit", "-qm", "theme")
        self.r.base = self.r.git("rev-parse", "HEAD").strip()
        self.r.locked("t-kt", [PASSING])
        self.r.write(KT + "ui/theme/Theme.kt", "package x\nimport java.security.KeyStore\n")
        self.r.write(KT + "ui/chat/ChatWire.kt", "package x\nconst val CHAT_FORMAT_V1 = 1\n")
        out = self.classify("t-kt")
        self.assertEqual(out["content_classes"], {KT + "ui/chat/ChatWire.kt": ["PROTOCOL"],
                                                  KT + "ui/theme/Theme.kt": ["CRYPTO"]})
        self.assertEqual(out["owner_gated"], ["CRYPTO", "PROTOCOL"])

    def test_a_kotlin_file_is_read_as_kotlin(self):
        self.r.locked("t-ktlang", [PASSING])
        self.r.write(KT + "ui/chat/Paths.kt", 'val p = "${glob("src/*")}"\nval c = Cipher.getInstance(t)\n')
        self.assertEqual(self.classify("t-ktlang")["content_classes"], {KT + "ui/chat/Paths.kt": ["CRYPTO"]})

    def test_an_unclassified_file_with_crypto_code_loses_the_fallback_label(self):
        self.r.locked("t-uncl", [PASSING])
        self.r.write("tools/sign.rs", "use ed25519_dalek::SigningKey;\n")
        self.assertEqual(self.classify("t-uncl")["paths"]["tools/sign.rs"], ["CRYPTO"])

    def test_only_added_code_counts(self):
        self.r.write("crates/mobile-ffi/src/util.rs", "use hkdf::Hkdf;\n")
        self.r.git("add", "-A")
        self.r.git("commit", "-qm", "util")
        self.r.base = self.r.git("rev-parse", "HEAD").strip()
        self.r.locked("t-added", [PASSING])
        self.r.write("crates/mobile-ffi/src/util.rs", "use hkdf::Hkdf;\nfn plain() {}\n")
        self.assertEqual(self.classify("t-added")["content_classes"], {})
        self.r.write("crates/mobile-ffi/src/util.rs", "use hkdf::Hkdf;\nuse hmac::Hmac;\n")
        self.assertEqual(self.classify("t-added")["content_classes"], {"crates/mobile-ffi/src/util.rs": ["CRYPTO"]})

    def test_an_added_line_is_read_in_the_context_of_its_file(self):
        self.r.locked("t-ctx", [PASSING])
        self.r.write("crates/mobile-ffi/src/text.rs", 'pub const S: &str = "a\nHkdf b";\nfn f() {}\n')
        self.r.write("crates/mobile-ffi/src/text2.rs", 'pub const S: &str = "a\nb"; use hkdf::Hkdf;\n')
        self.assertEqual(self.classify("t-ctx")["content_classes"], {"crates/mobile-ffi/src/text2.rs": ["CRYPTO"]})

    def test_comments_tests_and_gated_files_add_no_content_class(self):
        self.r.locked("t-quiet", [PASSING])
        self.r.write("crates/mobile-ffi/src/notes.rs", "//! Uses Hkdf and Hmac, see x3dh.rs.\n/// StaticSecret\n")
        self.r.write("crates/mobile-ffi/src/tests/k.rs", "let k = StaticSecret::random_from_rng(OsRng);\n")
        self.r.write("crates/mobile-ffi/src/handshake.rs", "// v1\nuse hmac::Hmac;\n")
        out = self.classify("t-quiet")
        self.assertEqual(out["content_classes"], {})
        self.assertEqual(out["owner_gated"], ["CRYPTO", "PROTOCOL"])  # handshake.rs, by its path rule


if __name__ == "__main__":
    unittest.main()
