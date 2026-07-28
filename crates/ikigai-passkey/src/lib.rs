//! A minimal single-user WebAuthn assertion verifier — the second factor on the edge's
//! decision links.
//!
//! The emailed decision links (`urn:calendar-request:*`, `urn:contact-block`) are gated today by
//! a signed token in the URL: it proves the link was minted for you, but whoever *holds* it can
//! act. A forwarded mail, a link-preview that logs URLs, a shoulder-surf — and a stranger blocks
//! your senders or declines your bookings. A passkey closes that: acting requires an assertion
//! from your registered device, made *now*. It is phishing-resistant — the assertion is bound to
//! the `ikigai-rs.dev` origin and verifies nowhere else — and the edge holds only the *public*
//! key, so a compromised edge can neither forge one nor learn a secret (the `decide.pub` posture,
//! applied to the human instead of the link).
//!
//! ## Scope, deliberately small
//!
//! - **One user, a handful of credentials.** No user database, no account model — the caller
//!   holds the registered credential(s) and hands the matching one in. Registration trust comes
//!   from the *enrollment context* (a one-time link gated by the existing decide key), not from
//!   attestation, so there is no attestation certificate chain to validate here.
//! - **ES256 only** (ECDSA over NIST P-256, COSE alg −7). It is what Apple, Android and Windows
//!   platform authenticators emit by default. Ed25519 (−8) is a small, additive follow-on; it is
//!   left out rather than half-supported.
//!
//! ## What [`verify`] checks (WebAuthn §7.2, the assertion path)
//!
//! 1. the assertion names the credential we registered;
//! 2. `clientDataJSON` is a `webauthn.get` for our exact `origin` and the exact `challenge` we
//!    issued (the caller stores challenges single-use and short-lived — replay defense lives
//!    there, since a verifier is stateless);
//! 3. `authenticatorData`'s RP-ID hash is `SHA256("ikigai-rs.dev")`;
//! 4. the **user-present** flag is set (and **user-verified**, if the policy demands the biometric);
//! 5. the signature counter has not regressed — a clone that reused a stolen key would show a
//!    counter at or below the last one we saw;
//! 6. the ECDSA-P256 signature verifies over `authenticatorData ‖ SHA256(clientDataJSON)`.
//!
//! Each failure is a distinct [`PasskeyError`] so a caller can log precisely; the *endpoint* that
//! consumes this collapses them all to one refusal, the way the decide links do, so a prober on
//! the wire learns nothing from the shape of the answer. On success [`verify`] returns the new
//! signature counter, which the caller must persist so the next assertion is checked against it.

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

/// A credential registered to the one user, as the edge stores it.
#[derive(Clone)]
pub struct RegisteredCredential {
    /// The `credentialId` the authenticator returns with every assertion.
    pub id: Vec<u8>,
    /// The ES256 public key.
    pub key: VerifyingKey,
    /// The highest signature counter seen so far. Starts at the value registration reported
    /// (often 0). Persisted and advanced on every successful [`verify`].
    pub sign_count: u32,
}

impl RegisteredCredential {
    /// From a SubjectPublicKeyInfo DER blob — what `getPublicKey()` returns in the browser at
    /// registration, so the glue-JS can send the key without any CBOR/attestation parsing.
    pub fn from_spki_der(id: Vec<u8>, der: &[u8], sign_count: u32) -> Result<Self, PasskeyError> {
        let key = VerifyingKey::from_public_key_der(der)
            .map_err(|e| PasskeyError::BadKey(format!("not an SPKI P-256 key: {e}")))?;
        Ok(Self {
            id,
            key,
            sign_count,
        })
    }

    /// From a raw SEC1 point (`0x04 ‖ x ‖ y`) — the other shape a registration payload can carry.
    pub fn from_sec1(id: Vec<u8>, sec1: &[u8], sign_count: u32) -> Result<Self, PasskeyError> {
        let key = VerifyingKey::from_sec1_bytes(sec1)
            .map_err(|e| PasskeyError::BadKey(format!("not a SEC1 P-256 point: {e}")))?;
        Ok(Self {
            id,
            key,
            sign_count,
        })
    }
}

/// The four fields a `navigator.credentials.get()` assertion hands back, as received bytes.
pub struct Assertion<'a> {
    /// Which registered credential the authenticator used.
    pub credential_id: &'a [u8],
    /// `authenticatorData`: `rpIdHash(32) ‖ flags(1) ‖ signCount(4) ‖ …`.
    pub authenticator_data: &'a [u8],
    /// The raw `clientDataJSON` bytes — hashed as-received, never re-serialised.
    pub client_data_json: &'a [u8],
    /// The ECDSA signature, ASN.1 DER (the WebAuthn wire form).
    pub signature: &'a [u8],
}

/// What a valid assertion must match. `challenge_b64url` is the base64url (no padding) of the
/// exact challenge the caller issued and is holding open for this one use.
pub struct Policy<'a> {
    pub rp_id: &'a str,
    pub origin: &'a str,
    pub challenge_b64url: &'a str,
    /// Require the user-verified flag (a biometric / PIN), not merely user-present (a tap).
    pub require_user_verified: bool,
}

/// Every way an assertion can be refused. Distinct for the caller's log; one refusal on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasskeyError {
    /// The assertion names a credential we did not register.
    WrongCredential,
    /// `clientDataJSON` did not parse as JSON with the fields we need.
    BadClientData,
    /// `type` was not `webauthn.get` (e.g. a registration ceremony replayed as a login).
    WrongType,
    /// The assertion was made for a different origin — the phishing guard.
    WrongOrigin,
    /// The challenge did not match the one we issued (stale, replayed, or forged).
    WrongChallenge,
    /// `authenticatorData` was too short to hold the fixed header.
    ShortAuthData,
    /// The RP-ID hash was not `SHA256(rp_id)` — the assertion is for another relying party.
    WrongRpId,
    /// The user-present flag was clear — no human touched the authenticator.
    UserNotPresent,
    /// The policy demanded user-verification and the flag was clear.
    UserNotVerified,
    /// The signature counter did not advance — a possible cloned authenticator.
    CounterRegressed,
    /// The signature did not verify against the registered key over the signed bytes.
    BadSignature,
    /// The stored/registered public key could not be parsed.
    BadKey(String),
}

impl std::fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasskeyError::BadKey(d) => write!(f, "invalid credential key: {d}"),
            other => write!(f, "{other:?}"),
        }
    }
}

impl std::error::Error for PasskeyError {}

/// One string field out of `clientDataJSON`, without pulling in a derive.
fn client_field(json: &serde_json::Value, key: &str) -> Result<String, PasskeyError> {
    json.get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or(PasskeyError::BadClientData)
}

/// Verify one WebAuthn assertion against one registered credential and a policy. On success,
/// returns the new signature counter — the caller MUST persist it, or a cloned authenticator's
/// replay would not be caught next time.
pub fn verify(
    cred: &RegisteredCredential,
    assertion: &Assertion<'_>,
    policy: &Policy<'_>,
) -> Result<u32, PasskeyError> {
    // 1. The assertion must be for the credential we registered.
    if assertion.credential_id != cred.id.as_slice() {
        return Err(PasskeyError::WrongCredential);
    }

    // 2. clientDataJSON: a login, for our origin, answering our challenge.
    let client: serde_json::Value = serde_json::from_slice(assertion.client_data_json)
        .map_err(|_| PasskeyError::BadClientData)?;
    if client_field(&client, "type")? != "webauthn.get" {
        return Err(PasskeyError::WrongType);
    }
    if client_field(&client, "origin")? != policy.origin {
        return Err(PasskeyError::WrongOrigin);
    }
    // The challenge is compared as the base64url text the browser echoes, against the base64url
    // text we issued — no decode step, so a padding or alphabet quirk cannot smuggle a match.
    if client_field(&client, "challenge")? != policy.challenge_b64url {
        return Err(PasskeyError::WrongChallenge);
    }

    // 3. authenticatorData: the RP-ID hash, the flags, and the counter.
    let auth = assertion.authenticator_data;
    if auth.len() < 37 {
        return Err(PasskeyError::ShortAuthData);
    }
    if auth[0..32] != Sha256::digest(policy.rp_id.as_bytes())[..] {
        return Err(PasskeyError::WrongRpId);
    }
    let flags = auth[32];
    if flags & 0x01 == 0 {
        return Err(PasskeyError::UserNotPresent);
    }
    if policy.require_user_verified && flags & 0x04 == 0 {
        return Err(PasskeyError::UserNotVerified);
    }
    let count = u32::from_be_bytes([auth[33], auth[34], auth[35], auth[36]]);

    // 4. The counter must advance. Some authenticators always report 0 — when both the stored and
    //    the presented count are 0 the signal is simply unavailable, so it is not held against a
    //    legitimate device; any non-zero value, though, must be strictly greater than last seen.
    if (count != 0 || cred.sign_count != 0) && count <= cred.sign_count {
        return Err(PasskeyError::CounterRegressed);
    }

    // 5. The signature is over authenticatorData ‖ SHA256(clientDataJSON). ES256 hashes THAT with
    //    SHA-256 internally, so the concatenation is the message and `verify` does the final hash.
    let mut signed = Vec::with_capacity(auth.len() + 32);
    signed.extend_from_slice(auth);
    signed.extend_from_slice(&Sha256::digest(assertion.client_data_json));
    let sig = Signature::from_der(assertion.signature).map_err(|_| PasskeyError::BadSignature)?;
    cred.key
        .verify(&signed, &sig)
        .map_err(|_| PasskeyError::BadSignature)?;

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use p256::pkcs8::EncodePublicKey;

    const RP_ID: &str = "ikigai-rs.dev";
    const ORIGIN: &str = "https://ikigai-rs.dev";
    const CHALLENGE: &str = "Q0hBTExFTkdF"; // base64url("CHALLENGE")

    /// The test harness plays the authenticator: a fixed P-256 key signs assertions exactly as a
    /// real device would (SHA-256 of authData ‖ SHA-256(clientDataJSON), DER-encoded), so the full
    /// verification path — byte layout and signature alike — is exercised end to end, and every
    /// tampered field can be aimed at a specific check.
    struct Authenticator {
        key: SigningKey,
    }

    impl Authenticator {
        fn new() -> Self {
            // A fixed, valid, non-zero scalar — these tests are about the protocol, not keygen.
            Self {
                key: SigningKey::from_bytes(&[0x11u8; 32].into()).unwrap(),
            }
        }

        fn credential(&self, sign_count: u32) -> RegisteredCredential {
            let sec1 = VerifyingKey::from(&self.key)
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
            RegisteredCredential::from_sec1(b"cred-1".to_vec(), &sec1, sign_count).unwrap()
        }

        fn client_data(&self, ty: &str, origin: &str, challenge: &str) -> Vec<u8> {
            format!(r#"{{"type":"{ty}","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#)
                .into_bytes()
        }

        fn auth_data(&self, rp_id: &str, flags: u8, count: u32) -> Vec<u8> {
            let mut d = Sha256::digest(rp_id.as_bytes()).to_vec(); // 32
            d.push(flags); // 1
            d.extend_from_slice(&count.to_be_bytes()); // 4
            d
        }

        /// Sign an assertion the way a device does: ECDSA over authData ‖ SHA256(clientDataJSON).
        fn sign(&self, auth_data: &[u8], client_data: &[u8]) -> Vec<u8> {
            let mut msg = auth_data.to_vec();
            msg.extend_from_slice(&Sha256::digest(client_data));
            let sig: Signature = self.key.sign(&msg);
            sig.to_der().as_bytes().to_vec()
        }
    }

    /// A well-formed, user-verified assertion for the standard policy.
    fn good() -> (Authenticator, Vec<u8>, Vec<u8>, Vec<u8>) {
        let a = Authenticator::new();
        let client = a.client_data("webauthn.get", ORIGIN, CHALLENGE);
        let auth = a.auth_data(RP_ID, 0x05, 7); // UP | UV, count 7
        let sig = a.sign(&auth, &client);
        (a, client, auth, sig)
    }

    fn policy() -> Policy<'static> {
        Policy {
            rp_id: RP_ID,
            origin: ORIGIN,
            challenge_b64url: CHALLENGE,
            require_user_verified: true,
        }
    }

    fn assertion<'a>(auth: &'a [u8], client: &'a [u8], sig: &'a [u8]) -> Assertion<'a> {
        Assertion {
            credential_id: b"cred-1",
            authenticator_data: auth,
            client_data_json: client,
            signature: sig,
        }
    }

    #[test]
    fn a_well_formed_assertion_verifies_and_returns_the_new_counter() {
        let (a, client, auth, sig) = good();
        let cred = a.credential(6); // last seen 6, this one is 7
        let count = verify(&cred, &assertion(&auth, &client, &sig), &policy()).unwrap();
        assert_eq!(count, 7);
    }

    #[test]
    fn an_assertion_for_another_origin_is_refused() {
        let a = Authenticator::new();
        let client = a.client_data("webauthn.get", "https://evil.example", CHALLENGE);
        let auth = a.auth_data(RP_ID, 0x05, 7);
        let sig = a.sign(&auth, &client);
        assert_eq!(
            verify(
                &a.credential(6),
                &assertion(&auth, &client, &sig),
                &policy()
            ),
            Err(PasskeyError::WrongOrigin)
        );
    }

    #[test]
    fn a_stale_or_forged_challenge_is_refused() {
        let a = Authenticator::new();
        let client = a.client_data("webauthn.get", ORIGIN, "b3RoZXI"); // base64url("other")
        let auth = a.auth_data(RP_ID, 0x05, 7);
        let sig = a.sign(&auth, &client);
        assert_eq!(
            verify(
                &a.credential(6),
                &assertion(&auth, &client, &sig),
                &policy()
            ),
            Err(PasskeyError::WrongChallenge)
        );
    }

    #[test]
    fn a_registration_ceremony_replayed_as_a_login_is_refused() {
        let a = Authenticator::new();
        let client = a.client_data("webauthn.create", ORIGIN, CHALLENGE);
        let auth = a.auth_data(RP_ID, 0x05, 7);
        let sig = a.sign(&auth, &client);
        assert_eq!(
            verify(
                &a.credential(6),
                &assertion(&auth, &client, &sig),
                &policy()
            ),
            Err(PasskeyError::WrongType)
        );
    }

    #[test]
    fn an_assertion_for_another_rp_is_refused() {
        let a = Authenticator::new();
        let client = a.client_data("webauthn.get", ORIGIN, CHALLENGE);
        let auth = a.auth_data("attacker.example", 0x05, 7); // wrong RP-ID hash
        let sig = a.sign(&auth, &client);
        assert_eq!(
            verify(
                &a.credential(6),
                &assertion(&auth, &client, &sig),
                &policy()
            ),
            Err(PasskeyError::WrongRpId)
        );
    }

    #[test]
    fn user_presence_and_verification_flags_are_enforced() {
        let a = Authenticator::new();
        let client = a.client_data("webauthn.get", ORIGIN, CHALLENGE);
        // Flags clear: not present at all.
        let none = a.auth_data(RP_ID, 0x00, 7);
        let sig = a.sign(&none, &client);
        assert_eq!(
            verify(
                &a.credential(6),
                &assertion(&none, &client, &sig),
                &policy()
            ),
            Err(PasskeyError::UserNotPresent)
        );
        // Present (tap) but not verified (no biometric), while the policy demands verification.
        let up_only = a.auth_data(RP_ID, 0x01, 7);
        let sig = a.sign(&up_only, &client);
        assert_eq!(
            verify(
                &a.credential(6),
                &assertion(&up_only, &client, &sig),
                &policy()
            ),
            Err(PasskeyError::UserNotVerified)
        );
        // The same up-only assertion passes when verification is not required.
        let lax = Policy {
            require_user_verified: false,
            ..policy()
        };
        assert!(verify(&a.credential(6), &assertion(&up_only, &client, &sig), &lax).is_ok());
    }

    #[test]
    fn a_counter_that_does_not_advance_is_refused_as_a_possible_clone() {
        let (a, client, auth, sig) = good(); // count 7
                                             // Last seen 7 already: a replay at the same counter is refused.
        assert_eq!(
            verify(
                &a.credential(7),
                &assertion(&auth, &client, &sig),
                &policy()
            ),
            Err(PasskeyError::CounterRegressed)
        );
        // And last seen 8: a regression is refused too.
        assert_eq!(
            verify(
                &a.credential(8),
                &assertion(&auth, &client, &sig),
                &policy()
            ),
            Err(PasskeyError::CounterRegressed)
        );
    }

    #[test]
    fn an_authenticator_that_always_reports_zero_is_tolerated() {
        let a = Authenticator::new();
        let client = a.client_data("webauthn.get", ORIGIN, CHALLENGE);
        let auth = a.auth_data(RP_ID, 0x05, 0);
        let sig = a.sign(&auth, &client);
        // Stored 0, presented 0: the counter signal is unavailable, not a regression.
        assert_eq!(
            verify(
                &a.credential(0),
                &assertion(&auth, &client, &sig),
                &policy()
            ),
            Ok(0)
        );
    }

    #[test]
    fn a_signature_by_another_key_is_refused() {
        let a = Authenticator::new();
        let client = a.client_data("webauthn.get", ORIGIN, CHALLENGE);
        let auth = a.auth_data(RP_ID, 0x05, 7);
        // Sign with a DIFFERENT key than the registered credential.
        let other = Authenticator {
            key: SigningKey::from_bytes(&[0x22u8; 32].into()).unwrap(),
        };
        let sig = other.sign(&auth, &client);
        assert_eq!(
            verify(
                &a.credential(6),
                &assertion(&auth, &client, &sig),
                &policy()
            ),
            Err(PasskeyError::BadSignature)
        );
    }

    #[test]
    fn tampered_authenticator_data_breaks_the_signature() {
        let (a, client, mut auth, sig) = good();
        auth[36] ^= 0xFF; // flip the counter after signing
        assert_eq!(
            verify(
                &a.credential(6),
                &assertion(&auth, &client, &sig),
                &policy()
            ),
            Err(PasskeyError::BadSignature)
        );
    }

    #[test]
    fn an_assertion_for_an_unregistered_credential_is_refused() {
        let (a, client, auth, sig) = good();
        let mut other = assertion(&auth, &client, &sig);
        other.credential_id = b"someone-else";
        assert_eq!(
            verify(&a.credential(6), &other, &policy()),
            Err(PasskeyError::WrongCredential)
        );
    }

    #[test]
    fn short_or_garbage_inputs_are_refused_without_panicking() {
        let (a, client, _auth, sig) = good();
        let cred = a.credential(6);
        // Truncated authenticatorData.
        assert_eq!(
            verify(&cred, &assertion(b"short", &client, &sig), &policy()),
            Err(PasskeyError::ShortAuthData)
        );
        // clientDataJSON that is not JSON.
        let auth = a.auth_data(RP_ID, 0x05, 7);
        assert_eq!(
            verify(&cred, &assertion(&auth, b"not json", &sig), &policy()),
            Err(PasskeyError::BadClientData)
        );
        // A signature that is not DER.
        assert_eq!(
            verify(
                &cred,
                &assertion(&auth, &client, b"\x00\x01\x02"),
                &policy()
            ),
            Err(PasskeyError::BadSignature)
        );
    }

    #[test]
    fn a_registered_key_round_trips_through_spki_and_sec1() {
        let a = Authenticator::new();
        let vk = VerifyingKey::from(&a.key);
        let spki = vk.to_public_key_der().unwrap();
        let sec1 = vk.to_encoded_point(false).as_bytes().to_vec();

        let from_spki = RegisteredCredential::from_spki_der(b"cred-1".to_vec(), spki.as_bytes(), 0)
            .expect("SPKI parses");
        let from_sec1 =
            RegisteredCredential::from_sec1(b"cred-1".to_vec(), &sec1, 0).expect("SEC1 parses");

        // Both must parse to the SAME key bytes.
        assert_eq!(
            from_spki.key.to_encoded_point(false).as_bytes(),
            from_sec1.key.to_encoded_point(false).as_bytes(),
            "SPKI and SEC1 must decode to the same key"
        );

        // Both parse to the same key, and both verify a real assertion.
        let client = a.client_data("webauthn.get", ORIGIN, CHALLENGE);
        let auth = a.auth_data(RP_ID, 0x05, 1);
        let sig = a.sign(&auth, &client);
        assert_eq!(
            verify(&from_spki, &assertion(&auth, &client, &sig), &policy()),
            Ok(1)
        );
        assert_eq!(
            verify(&from_sec1, &assertion(&auth, &client, &sig), &policy()),
            Ok(1)
        );
    }

    #[test]
    fn a_malformed_public_key_is_rejected_at_registration() {
        assert!(matches!(
            RegisteredCredential::from_sec1(b"c".to_vec(), b"not a point", 0),
            Err(PasskeyError::BadKey(_))
        ));
        assert!(matches!(
            RegisteredCredential::from_spki_der(b"c".to_vec(), b"not der", 0),
            Err(PasskeyError::BadKey(_))
        ));
    }
}
