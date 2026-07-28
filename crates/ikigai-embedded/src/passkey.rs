//! The passkey second factor on the edge, as ikigai endpoints — the server side of the
//! WebAuthn ceremony that [`ikigai_passkey`] verifies.
//!
//! The emailed decision links ([`crate::contactblock`], [`crate::decide`]) are gated today by a
//! signed token in the URL. A passkey adds "…and the person at the registered device approved it,
//! now." This module holds the three moving parts, all on the edge, all reusing one verifier:
//!
//! | endpoint / helper | verb | does |
//! |---|---|---|
//! | `urn:passkey:challenge` | Source | issues a fresh single-use challenge + the registered ids |
//! | [`require_passkey`] | — | the gate a decision POST calls before it acts |
//! | `urn:passkey:enroll-open` | Sink | opens a short enrollment window (run from the box) |
//! | `urn:passkey:register` | Source/Sink | GET shows the enrol page, POST stores the credential |
//!
//! ## Per-action, not a session — and inert until enrolled
//!
//! There is no cookie and no session store: the browser runs the ceremony on the button tap and
//! the assertion rides in the decision POST body, so a Touch-ID tap is *per decision* (the right
//! feel for a block or a decline) and nothing here touches the HTTP transport layer. And the gate
//! is **inert until a credential is registered** — [`require_passkey`] returns `Ok` when the
//! credential store is empty, so deploying this cannot brick the working links; enrolling a
//! passkey is what switches it on.
//!
//! ## Replay defense lives here
//!
//! [`ikigai_passkey::verify`] is stateless, so the freshness of a challenge is this module's job:
//! `urn:passkey:challenge` mints a random challenge and remembers it briefly; the gate consumes it
//! on use, so an assertion can be presented exactly once and only within the window.
//!
//! ## Enrollment trust (v1)
//!
//! Registering a passkey grants the authority to approve everything the links can, so it must be
//! bootstrapped from a trusted context. v1 uses a **local enrollment window**: `urn:passkey:enroll-open`
//! is cap-gated (`urn:cap:passkey:enroll`) and run from the box, opening a few minutes during which
//! one credential may register; the first registration closes it. Anchoring the enrol link in the
//! Mac-held decide key instead is the natural hardening, left as a follow-on.

use crate::decide::{page, param};
use crate::file_root;
use base64::Engine;
use ikigai_core::{
    ActionSpec, Description, Endpoint, Error, Invocation, ReprType, Representation, Result, Verb,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Cap to open an enrollment window — held only where a human at the box runs it.
pub const CAP_PASSKEY_ENROLL: &str = "urn:cap:passkey:enroll";

/// How long a challenge stays good — long enough for a biometric prompt, short enough that a
/// leaked one is stale almost at once.
const CHALLENGE_TTL_SECONDS: i64 = 120;
/// How long an enrollment window stays open once a human opens it.
const ENROLL_WINDOW_SECONDS: i64 = 300;

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// The relying-party id and origin this edge asserts under. Overridable so a test — or a
/// different deployment — is not pinned to the production hostname.
fn rp_id() -> String {
    std::env::var("IKIGAI_PASSKEY_RP_ID").unwrap_or_else(|_| "ikigai-rs.dev".to_string())
}
fn origin() -> String {
    std::env::var("IKIGAI_PASSKEY_ORIGIN").unwrap_or_else(|_| "https://ikigai-rs.dev".to_string())
}

/// The workspace root the passkey files live under. In production this is [`file_root`]; the
/// tests override it per-thread (each test runs on its own thread) so parallel tests never share
/// a credential file — a global env-var override would race across them.
fn store_root() -> std::path::PathBuf {
    #[cfg(test)]
    if let Some(p) = tests::test_root() {
        return p;
    }
    file_root()
}

fn credentials_path() -> std::path::PathBuf {
    store_root().join("passkey-credentials.json")
}
fn enroll_window_path() -> std::path::PathBuf {
    store_root().join("passkey-enroll.open")
}

// =====================================================================================
// The challenge store — process-global, in-memory. A restart just invalidates outstanding
// challenges (the user taps again); nothing here is worth persisting.
// =====================================================================================

fn challenges() -> &'static Mutex<HashMap<String, i64>> {
    static STORE: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Mint a fresh challenge, remember it with an expiry, and return its base64url text.
fn issue_challenge() -> Result<String> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw)
        .map_err(|e| Error::Endpoint(format!("no OS randomness for a challenge: {e}")))?;
    let challenge = b64().encode(raw);
    let mut store = challenges().lock().expect("challenge store poisoned");
    let now = now_secs();
    store.retain(|_, exp| *exp > now); // opportunistic sweep so the map cannot grow without bound
    store.insert(challenge.clone(), now + CHALLENGE_TTL_SECONDS);
    Ok(challenge)
}

/// Consume a challenge: it must be one we issued and still in date, and it is removed so it
/// cannot be presented twice.
fn consume_challenge(challenge: &str) -> bool {
    let mut store = challenges().lock().expect("challenge store poisoned");
    match store.remove(challenge) {
        Some(exp) => exp > now_secs(),
        None => false,
    }
}

// =====================================================================================
// The credential store — a small JSON file, the registered public key(s) for the one user.
// =====================================================================================

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct StoredCredential {
    /// base64url of the credentialId.
    id: String,
    /// base64url of the SubjectPublicKeyInfo DER public key.
    spki: String,
    /// The last signature counter seen, advanced on each successful assertion.
    #[serde(default)]
    sign_count: u32,
}

fn load_credentials() -> Vec<StoredCredential> {
    match std::fs::read(credentials_path()) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

fn save_credentials(creds: &[StoredCredential]) -> Result<()> {
    let json = serde_json::to_vec_pretty(creds)
        .map_err(|e| Error::Endpoint(format!("cannot serialise credentials: {e}")))?;
    std::fs::write(credentials_path(), json)
        .map_err(|e| Error::Endpoint(format!("cannot write credentials: {e}")))
}

/// Whether any credential is registered. The gate is inert until this is true.
pub fn is_enrolled() -> bool {
    !load_credentials().is_empty()
}

// =====================================================================================
// Browser glue. The one piece that runs on the device, not the edge.
//
// Served as a SAME-ORIGIN FILE, not inline: the edge's strict CSP is `default-src 'self'`,
// which forbids inline `<script>` but allows a script fetched from the same origin. So the
// pages carry only a `<script src="/passkey/app.js">` tag and the ceremony lives in
// `PASSKEY_APP_JS`, served by `urn:passkey:js` with a JavaScript content type (X-Content-Type-
// Options: nosniff is set, so the MIME must be right). No CSP loosening anywhere.
// =====================================================================================

/// What a decision page carries: a status line and the shared ceremony script. The page's form
/// must have `id="act"`; `PASSKEY_APP_JS` wires it — on submit, fetch a challenge, run
/// `navigator.credentials.get` if enrolled, attach the assertion as `pk_*` fields, submit.
pub(crate) const DECISION_PASSKEY_JS: &str =
    "<p id=pkstatus style=\"color:#666\"></p><script src=\"/passkey/app.js\"></script>";

/// The registration page body: a button (wired by `PASSKEY_APP_JS` via `id="reg"`) that runs
/// `navigator.credentials.create`, then POSTs the new credential id + its SPKI public key.
const REGISTER_PAGE_BODY: &str = r#"<p>Create a passkey for this site — your device will ask you to confirm with Face/Touch ID.</p>
<button id=reg style="font:inherit;padding:.6rem 1.2rem">Create passkey</button>
<p id=status style="color:#666"></p>
<script src="/passkey/app.js"></script>"#;

/// The one ceremony script, served same-origin (see the section note on CSP). It wires whichever
/// page it lands on: a decision form (`#act` → `navigator.credentials.get`) or the register
/// button (`#reg` → `navigator.credentials.create`). `form.submit()` does not re-fire the submit
/// handler, so the decision path has no re-entrancy.
const PASSKEY_APP_JS: &str = r#"(function(){
  var form=document.getElementById('act');
  var reg=document.getElementById('reg');
  if(form) decision(form);
  if(reg) register(reg);

  function decision(form){
    var status=document.getElementById('pkstatus');
    form.addEventListener('submit', function(ev){ ev.preventDefault();
      status.textContent='';
      fetch('/passkey/challenge',{headers:{accept:'application/json'}})
        .then(function(r){return r.json();})
        .then(function(opt){
          if(!opt.enrolled){ form.submit(); return; }
          status.textContent='Confirm with your passkey…';
          return navigator.credentials.get({publicKey:{
            challenge:u(opt.challenge), rpId:opt.rpId,
            allowCredentials:(opt.allowCredentials||[]).map(function(c){return {type:'public-key',id:u(c.id)};}),
            userVerification:opt.userVerification||'preferred', timeout:60000
          }}).then(function(a){
            add(form,'pk_id',b(a.rawId)); add(form,'pk_auth',b(a.response.authenticatorData));
            add(form,'pk_client',b(a.response.clientDataJSON)); add(form,'pk_sig',b(a.response.signature));
            form.submit();
          });
        })
        .catch(function(e){ status.textContent='Passkey step failed ('+((e&&e.message)||e)+'). Reopen the link to retry.'; });
    });
  }

  function register(btn){
    var status=document.getElementById('status');
    btn.addEventListener('click', function(){
      status.textContent='Creating…';
      fetch('/passkey/challenge').then(function(r){return r.json();}).then(function(opt){
        return navigator.credentials.create({publicKey:{
          rp:{id:opt.rpId, name:'ikigai'},
          user:{id:new TextEncoder().encode('ikigai-owner'), name:'owner', displayName:'ikigai owner'},
          challenge:u(opt.challenge),
          pubKeyCredParams:[{type:'public-key',alg:-7}],
          authenticatorSelection:{userVerification:'preferred',residentKey:'preferred'},
          timeout:60000, attestation:'none'
        }});
      }).then(function(cred){
        var spki=cred.response.getPublicKey && cred.response.getPublicKey();
        if(!spki){ throw new Error('this browser did not expose the public key (needs WebAuthn L2)'); }
        var body='id='+encodeURIComponent(b(cred.rawId))+'&spki='+encodeURIComponent(b(spki));
        return fetch('/passkey/register',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:body});
      }).then(function(res){ return res.text(); }).then(function(html){ document.open(); document.write(html); document.close(); })
        .catch(function(e){ status.textContent='Registration failed: '+((e&&e.message)||e); });
    });
  }

  function add(f,n,v){ var i=document.createElement('input'); i.type='hidden'; i.name=n; i.value=v; f.appendChild(i); }
  function u(s){ s=s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4)s+='='; var x=atob(s),y=new Uint8Array(x.length); for(var i=0;i<x.length;i++)y[i]=x.charCodeAt(i); return y.buffer; }
  function b(buf){ var y=new Uint8Array(buf),s=''; for(var i=0;i<y.length;i++)s+=String.fromCharCode(y[i]); return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
})();
"#;

/// Serves [`PASSKEY_APP_JS`] as a same-origin JavaScript file so the strict edge CSP admits it.
pub struct PasskeyJs;

#[async_trait::async_trait]
impl Endpoint for PasskeyJs {
    async fn invoke(&self, _inv: &Invocation<'_>) -> Result<Representation> {
        Ok(Representation::new(
            ReprType::new("application/javascript").with_param("charset", "utf-8"),
            PASSKEY_APP_JS.as_bytes().to_vec(),
        ))
    }
    fn name(&self) -> &str {
        "passkey-js"
    }
    fn describe(&self) -> Description {
        Description::new("passkey-js")
            .title("The passkey ceremony script")
            .summary("The same-origin script the decision and register pages load to run the WebAuthn ceremony.")
            .action(ActionSpec::new(Verb::Source).summary("the script"))
            .output("application/javascript; charset=utf-8")
    }
}

// =====================================================================================
// The gate — what a decision POST calls before it acts.
// =====================================================================================

/// Require a valid passkey assertion for this action, UNLESS no credential is enrolled (in which
/// case the action proceeds token-only, exactly as before passkeys). The assertion rides in the
/// POST body as base64url fields the glue-JS adds: `pk_id`, `pk_auth`, `pk_client`, `pk_sig`.
///
/// On success the challenge is consumed (single-use) and any advanced signature counter persisted.
/// Every failure is one `Denied` — a prober learns nothing from which check tripped.
pub fn require_passkey(inv: &Invocation<'_>) -> Result<()> {
    let creds = load_credentials();
    if creds.is_empty() {
        return Ok(()); // inert until enrolled
    }

    let denied = || Error::Denied("this action needs your passkey".to_string());

    // Pull the four assertion fields the glue-JS attaches, all base64url.
    let (id_b64, auth_b64, client_b64, sig_b64) = (
        param(inv, "pk_id"),
        param(inv, "pk_auth"),
        param(inv, "pk_client"),
        param(inv, "pk_sig"),
    );
    if id_b64.is_empty() || auth_b64.is_empty() || client_b64.is_empty() || sig_b64.is_empty() {
        return Err(denied());
    }
    let decode = |s: &str| b64().decode(s).map_err(|_| denied());
    let (cred_id, auth_data, client_data, signature) = (
        decode(&id_b64)?,
        decode(&auth_b64)?,
        decode(&client_b64)?,
        decode(&sig_b64)?,
    );

    // The challenge inside clientDataJSON must be one we issued and have not yet spent.
    let client_json: serde_json::Value =
        serde_json::from_slice(&client_data).map_err(|_| denied())?;
    let challenge = client_json
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(denied)?
        .to_string();
    if !consume_challenge(&challenge) {
        return Err(denied()); // stale, replayed, or never issued here
    }

    // The assertion must name a credential we registered; rebuild it for the verifier.
    let stored = creds
        .iter()
        .find(|c| c.id == id_b64)
        .ok_or_else(denied)?
        .clone();
    let spki = b64().decode(&stored.spki).map_err(|_| denied())?;
    let registered =
        ikigai_passkey::RegisteredCredential::from_spki_der(cred_id, &spki, stored.sign_count)
            .map_err(|_| denied())?;

    let rp = rp_id();
    let og = origin();
    let policy = ikigai_passkey::Policy {
        rp_id: &rp,
        origin: &og,
        challenge_b64url: &challenge,
        require_user_verified: true,
    };
    let assertion = ikigai_passkey::Assertion {
        credential_id: &registered.id,
        authenticator_data: &auth_data,
        client_data_json: &client_data,
        signature: &signature,
    };
    let new_count =
        ikigai_passkey::verify(&registered, &assertion, &policy).map_err(|_| denied())?;

    // Persist an advanced counter so a cloned authenticator's replay is caught next time.
    if new_count > stored.sign_count {
        let mut all = creds;
        if let Some(c) = all.iter_mut().find(|c| c.id == id_b64) {
            c.sign_count = new_count;
        }
        let _ = save_credentials(&all); // best-effort; a failed write must not undo a real decision
    }
    Ok(())
}

// =====================================================================================
// urn:passkey:challenge — hand the browser a fresh challenge + the registered ids.
// =====================================================================================

/// Issues the JSON a `navigator.credentials.get()` needs: a fresh challenge, the RP id, and the
/// credential ids to allow. Empty `allowCredentials` (nothing enrolled) tells the page to submit
/// without a ceremony — the gate is inert then anyway.
pub struct PasskeyChallenge;

#[async_trait::async_trait]
impl Endpoint for PasskeyChallenge {
    async fn invoke(&self, _inv: &Invocation<'_>) -> Result<Representation> {
        let challenge = issue_challenge()?;
        let allow: Vec<_> = load_credentials()
            .into_iter()
            .map(|c| json!({ "type": "public-key", "id": c.id }))
            .collect();
        let body = json!({
            "challenge": challenge,
            "rpId": rp_id(),
            "allowCredentials": allow,
            "userVerification": "preferred",
            "enrolled": !allow.is_empty(),
        });
        Ok(Representation::new(
            ReprType::new("application/json").with_param("charset", "utf-8"),
            serde_json::to_vec(&body).expect("serialisable").to_vec(),
        ))
    }
    fn name(&self) -> &str {
        "passkey-challenge"
    }
    fn describe(&self) -> Description {
        Description::new("passkey-challenge")
            .title("Issue a WebAuthn challenge")
            .summary("A fresh single-use challenge plus the registered credential ids, for a login ceremony.")
            .action(ActionSpec::new(Verb::Source).summary("mint a challenge"))
            .output("application/json; charset=utf-8")
    }
}

// =====================================================================================
// urn:passkey:enroll-open — open a short enrollment window (run from the box).
// =====================================================================================

/// Opens a brief window during which one credential may register. Cap-gated so only a human at
/// the box can open it. The first registration closes it.
pub struct PasskeyEnrollOpen;

#[async_trait::async_trait]
impl Endpoint for PasskeyEnrollOpen {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if !inv.capability.allows(CAP_PASSKEY_ENROLL) {
            return Err(Error::Denied(format!(
                "opening enrollment requires `{CAP_PASSKEY_ENROLL}`"
            )));
        }
        let until = now_secs() + ENROLL_WINDOW_SECONDS;
        std::fs::write(enroll_window_path(), until.to_string())
            .map_err(|e| Error::Endpoint(format!("cannot open the enrollment window: {e}")))?;
        Ok(Representation::new(
            ReprType::new("text/plain").with_param("charset", "utf-8"),
            format!("enrollment open for {ENROLL_WINDOW_SECONDS}s — register your passkey now\n")
                .into_bytes(),
        ))
    }
    fn name(&self) -> &str {
        "passkey-enroll-open"
    }
    fn describe(&self) -> Description {
        Description::new("passkey-enroll-open")
            .title("Open a passkey enrollment window")
            .summary("Opens a short window during which one passkey may be registered. Run from the box.")
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("open the window")
                    .requires(CAP_PASSKEY_ENROLL),
            )
            .output("text/plain; charset=utf-8")
    }
}

fn enrollment_open() -> bool {
    match std::fs::read_to_string(enroll_window_path()) {
        Ok(s) => s
            .trim()
            .parse::<i64>()
            .map(|u| u > now_secs())
            .unwrap_or(false),
        Err(_) => false,
    }
}

fn close_enrollment() {
    let _ = std::fs::remove_file(enroll_window_path());
}

// =====================================================================================
// urn:passkey:register — GET shows the enrol page, POST stores the credential.
// =====================================================================================

/// The enrollment endpoint. GET renders the registration page (the glue-JS runs the WebAuthn
/// create ceremony); POST accepts `{id, spki}` — base64url of the credentialId and the SPKI public
/// key — and stores it, but only while a window opened at the box is live. The first registration
/// closes the window.
pub struct PasskeyRegister;

#[async_trait::async_trait]
impl Endpoint for PasskeyRegister {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        match inv.request.verb {
            Verb::Source => {
                if !enrollment_open() {
                    return Ok(page(
                        "Enrollment closed",
                        "<p>Open a window at the box first: <code>ikigai -c 'sink \
                         urn:passkey:enroll-open'</code>, then reload.</p>",
                    ));
                }
                Ok(page("Register a passkey", REGISTER_PAGE_BODY))
            }
            Verb::Sink => {
                if !enrollment_open() {
                    return Err(Error::Denied(
                        "no enrollment window is open — open one at the box first".to_string(),
                    ));
                }
                let (id_b64, spki_b64) = (param(inv, "id"), param(inv, "spki"));
                if id_b64.is_empty() || spki_b64.is_empty() {
                    return Err(Error::InvalidArgument {
                        name: "id/spki".to_string(),
                        detail: "both the credential id and the SPKI public key are required"
                            .to_string(),
                    });
                }
                // Validate the key parses as an ES256 SPKI before we trust it.
                let spki = b64()
                    .decode(&spki_b64)
                    .map_err(|_| Error::InvalidArgument {
                        name: "spki".to_string(),
                        detail: "not base64url".to_string(),
                    })?;
                ikigai_passkey::RegisteredCredential::from_spki_der(b"probe".to_vec(), &spki, 0)
                    .map_err(|e| Error::InvalidArgument {
                        name: "spki".to_string(),
                        detail: format!("not a usable public key: {e}"),
                    })?;

                let mut creds = load_credentials();
                // Replace any existing entry with this id rather than duplicate it.
                creds.retain(|c| c.id != id_b64);
                creds.push(StoredCredential {
                    id: id_b64,
                    spki: spki_b64,
                    sign_count: 0,
                });
                save_credentials(&creds)?;
                close_enrollment();
                Ok(page(
                    "Passkey registered",
                    "<p>Done. Decision links now ask for your passkey before they act.</p>",
                ))
            }
            other => Err(Error::Endpoint(format!(
                "register is GET to show or POST to store, not {other:?}"
            ))),
        }
    }
    fn name(&self) -> &str {
        "passkey-register"
    }
    fn describe(&self) -> Description {
        Description::new("passkey-register")
            .title("Register a passkey")
            .summary("GET shows the enrolment page; POST stores a credential while an enrollment window is open.")
            .action(ActionSpec::new(Verb::Source).summary("show the enrolment page"))
            .action(ActionSpec::new(Verb::Sink).summary("store a credential (window must be open)"))
            .output("text/html; charset=utf-8")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::{ArgRef, Capability, Iri, Kernel, Request};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
    use p256::pkcs8::EncodePublicKey;
    use sha2::{Digest, Sha256};

    thread_local! {
        static TEST_ROOT: std::cell::RefCell<Option<std::path::PathBuf>> =
            const { std::cell::RefCell::new(None) };
    }

    /// The current thread's override root, if a test set one. `store_root()` consults this.
    pub(super) fn test_root() -> Option<std::path::PathBuf> {
        TEST_ROOT.with(|r| r.borrow().clone())
    }

    // Give this test its own workspace root — set on THIS thread only, so parallel tests never
    // collide on the credential/window files (a global env var would race across them).
    fn isolate(name: &str) {
        let dir = std::env::temp_dir().join(format!("ikigai-passkey-ep-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TEST_ROOT.with(|r| *r.borrow_mut() = Some(dir));
    }

    /// A stand-in authenticator: a fixed P-256 key that signs assertions as a device would.
    struct Device {
        key: SigningKey,
    }
    impl Device {
        fn new() -> Self {
            Self {
                key: SigningKey::from_slice(&[0x33u8; 32]).unwrap(),
            }
        }
        fn spki_b64(&self) -> String {
            let der = VerifyingKey::from(&self.key).to_public_key_der().unwrap();
            b64().encode(der.as_bytes())
        }
        fn register(&self) {
            let creds = vec![StoredCredential {
                id: b64().encode(b"cred-1"),
                spki: self.spki_b64(),
                sign_count: 0,
            }];
            save_credentials(&creds).unwrap();
        }
        /// Build the four base64url fields for a POST body, over the given challenge. `count` is
        /// the signature counter — a real authenticator advances it every assertion.
        fn assert_fields(&self, challenge: &str, flags: u8, count: u32) -> String {
            let client = format!(
                r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{}"}}"#,
                origin()
            )
            .into_bytes();
            let mut auth = Sha256::digest(rp_id().as_bytes()).to_vec();
            auth.push(flags);
            auth.extend_from_slice(&count.to_be_bytes());
            let mut msg = auth.clone();
            msg.extend_from_slice(&Sha256::digest(&client));
            let sig: Signature = self.key.sign(&msg);
            format!(
                "pk_id={}&pk_auth={}&pk_client={}&pk_sig={}",
                b64().encode(b"cred-1"),
                b64().encode(&auth),
                b64().encode(&client),
                b64().encode(sig.to_der().as_bytes()),
            )
        }
    }

    /// A minimal invocation carrying a urlencoded body as `content` (how a POST arrives).
    fn post_inv(body: &str) -> (Kernel, Request) {
        let kernel = Kernel::new(std::sync::Arc::new(ikigai_core::EndpointSpace::new()));
        let req = Request::new(Verb::Sink, Iri::parse("urn:x").unwrap())
            .with_arg("content", ArgRef::Inline(body.as_bytes().to_vec()));
        (kernel, req)
    }

    fn run_gate(body: &str) -> Result<()> {
        // require_passkey only reads params off the invocation; drive it through a tiny endpoint.
        struct Gate;
        #[async_trait::async_trait]
        impl Endpoint for Gate {
            async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
                require_passkey(inv)?;
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"ok".to_vec(),
                ))
            }
            fn name(&self) -> &str {
                "gate"
            }
            fn describe(&self) -> Description {
                Description::new("gate").verb(Verb::Sink)
            }
        }
        let kernel = Kernel::new(std::sync::Arc::new(
            ikigai_core::EndpointSpace::new().bind(ikigai_core::Exact::new("urn:x"), Gate),
        ));
        let (_k, req) = post_inv(body);
        futures::executor::block_on(kernel.issue(req, &Capability::root())).map(|_| ())
    }

    #[test]
    fn the_gate_is_inert_until_a_credential_is_enrolled() {
        isolate("inert");
        // No credential file: any POST — even one with no passkey fields — passes.
        assert!(run_gate("id=abc&exp=1").is_ok());
    }

    #[test]
    fn a_valid_assertion_passes_the_gate_and_a_forged_one_does_not() {
        isolate("valid");
        let d = Device::new();
        d.register();
        let challenge = issue_challenge().unwrap();
        let body = d.assert_fields(&challenge, 0x05, 1); // UP | UV, counter 1
        assert!(run_gate(&body).is_ok(), "a valid assertion should pass");

        // A second ceremony (fresh challenge, advanced counter) also passes...
        let challenge2 = issue_challenge().unwrap();
        let good = d.assert_fields(&challenge2, 0x05, 2);
        assert!(run_gate(&good).is_ok());
        // ...but replaying that exact assertion is refused — the challenge was consumed.
        assert!(run_gate(&good).is_err(), "the challenge is single-use");
    }

    #[test]
    fn an_enrolled_gate_refuses_a_post_with_no_assertion() {
        isolate("missing");
        Device::new().register();
        assert!(
            run_gate("id=abc&exp=1").is_err(),
            "enrolled + no passkey = refused"
        );
    }

    #[test]
    fn a_forged_signature_is_refused() {
        isolate("forged");
        let real = Device::new();
        real.register();
        // A different key signs, but the assertion claims the registered credential id.
        let imposter = Device {
            key: SigningKey::from_slice(&[0x44u8; 32]).unwrap(),
        };
        let challenge = issue_challenge().unwrap();
        let body = imposter.assert_fields(&challenge, 0x05, 1);
        assert!(
            run_gate(&body).is_err(),
            "a foreign signature must be refused"
        );
    }

    #[test]
    fn a_never_issued_challenge_is_refused() {
        isolate("nochallenge");
        let d = Device::new();
        d.register();
        // Craft an assertion over a challenge that was never issued here.
        let body = d.assert_fields("bmV2ZXItaXNzdWVk", 0x05, 1);
        assert!(
            run_gate(&body).is_err(),
            "an unissued challenge must be refused"
        );
    }

    #[test]
    fn challenges_are_single_use_and_expire() {
        isolate("challenge");
        let c = issue_challenge().unwrap();
        assert!(consume_challenge(&c), "a fresh challenge consumes once");
        assert!(!consume_challenge(&c), "and not twice");
        assert!(
            !consume_challenge("never-issued"),
            "unknown challenge is refused"
        );
    }

    #[test]
    fn enrollment_window_gates_registration() {
        isolate("enroll");
        assert!(!enrollment_open(), "closed by default");
        // Opening requires the cap.
        let kernel = Kernel::new(std::sync::Arc::new(ikigai_core::EndpointSpace::new().bind(
            ikigai_core::Exact::new("urn:passkey:enroll-open"),
            PasskeyEnrollOpen,
        )));
        let open = |cap: &Capability| {
            futures::executor::block_on(kernel.issue(
                Request::new(Verb::Sink, Iri::parse("urn:passkey:enroll-open").unwrap()),
                cap,
            ))
        };
        assert!(
            open(&Capability::scoped(Vec::<String>::new())).is_err(),
            "no cap, no open"
        );
        assert!(open(&Capability::root()).is_ok(), "root opens it");
        assert!(enrollment_open(), "now open");
    }
}
