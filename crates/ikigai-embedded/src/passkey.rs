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
//! credential file is ABSENT, so deploying this cannot brick the working links; enrolling a
//! passkey is what switches it on.
//!
//! Once armed it **fails closed**: a credential file that is present but unreadable, or enrolled
//! credentials on an edge with no [`RelyingParty`] configured, refuse every gated decision and
//! say why on stderr — they never read as "not enrolled". The relying party comes from
//! `ikigai serve --passkey-rp-id <domain> [--passkey-origin <url>]` and has no default.
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
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

/// Cap to open an enrollment window — held only where a human at the box runs it.
pub const CAP_PASSKEY_ENROLL: &str = "urn:cap:passkey:enroll";

/// How long a challenge stays good — long enough for a biometric prompt, short enough that a
/// leaked one is stale almost at once. Measured on the MONOTONIC clock, so a backward jump of
/// the wall clock cannot extend one.
const CHALLENGE_TTL: Duration = Duration::from_secs(120);
/// How long an enrollment window stays open once a human opens it.
const ENROLL_WINDOW_SECONDS: i64 = 300;

/// Wall-clock seconds, for the enrollment window ONLY. That window is opened by one process
/// (`ikigai -c 'sink urn:passkey:enroll-open'` at the box) and read by another (the edge), so
/// its deadline has to be a number both can read from the file; an `Instant` means nothing
/// outside the process that took it. Challenges never leave this process, so they use one.
fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

// =====================================================================================
// The relying party — configured by the host, never defaulted.
// =====================================================================================

/// The WebAuthn relying party this edge asserts under: the RP id (a registrable domain such as
/// `ikigai-rs.dev`) and the origin the browser reports (`https://ikigai-rs.dev`).
///
/// **There is no default.** A forgotten setting used to register passkeys silently under the
/// production hostname; now an edge that has not been told its relying party cannot enroll a
/// passkey, and an edge that HAS enrolled ones refuses every gated decision until it is told
/// (fail closed). `ikigai serve --passkey-rp-id <domain> [--passkey-origin <url>]` sets it.
///
/// ```
/// use ikigai_embedded::passkey::RelyingParty;
/// let rp = RelyingParty::new("ikigai-rs.dev", None).unwrap();
/// assert_eq!(rp.origin(), "https://ikigai-rs.dev");
/// let rp = RelyingParty::new("example.org", Some("https://login.example.org")).unwrap();
/// assert_eq!((rp.rp_id(), rp.origin()), ("example.org", "https://login.example.org"));
/// assert!(RelyingParty::new("https://example.org", None).is_err()); // an id, not a URL
/// assert!(RelyingParty::new("example.org", Some("https://example.org/path")).is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelyingParty {
    rp_id: String,
    origin: String,
}

impl RelyingParty {
    /// A relying party for `rp_id`, with `origin` defaulting to `https://<rp_id>`. Refuses an
    /// id that is not a bare host name and an origin that is not `scheme://host[:port]`.
    pub fn new(rp_id: &str, origin: Option<&str>) -> std::result::Result<Self, String> {
        let rp_id = rp_id.trim();
        if rp_id.is_empty()
            || rp_id
                .chars()
                .any(|c| matches!(c, '/' | ':' | '?' | '#' | '@') || c.is_whitespace())
        {
            return Err(format!(
                "a passkey RP id is a bare domain such as `ikigai-rs.dev`, not `{rp_id}`"
            ));
        }
        let origin = match origin {
            Some(o) => o.trim().trim_end_matches('/').to_string(),
            None => format!("https://{rp_id}"),
        };
        let host = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .ok_or_else(|| format!("a passkey origin is `https://host[:port]`, not `{origin}`"))?;
        if host.is_empty() || host.contains(['/', '?', '#', '@']) {
            return Err(format!(
                "a passkey origin is `https://host[:port]` with no path, not `{origin}`"
            ));
        }
        Ok(Self {
            rp_id: rp_id.to_string(),
            origin,
        })
    }
    /// The RP id the authenticator scopes its credential to.
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }
    /// The origin `clientDataJSON` must carry.
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

static RELYING_PARTY: Mutex<Option<RelyingParty>> = Mutex::new(None);

/// Tell this process's passkey endpoints which relying party they serve. Process-global like
/// the instance name, and set once at startup from `serve`'s flags.
pub fn set_relying_party(rp: RelyingParty) {
    *RELYING_PARTY.lock().unwrap_or_else(|e| e.into_inner()) = Some(rp);
}

/// The configured relying party, if any.
#[cfg(not(test))]
fn relying_party() -> Option<RelyingParty> {
    RELYING_PARTY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// The tests override the relying party per thread (as they do `store_root`), so a test that
/// wants the unconfigured case cannot race one that configures it.
#[cfg(test)]
fn relying_party() -> Option<RelyingParty> {
    tests::test_rp()
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

fn challenges() -> &'static Mutex<HashMap<String, Instant>> {
    static STORE: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The monotonic clock challenges expire on. Native-only: the embedded host is a threaded,
/// filesystem-backed process that a wasm build replaces rather than compiles, and the injected
/// `Clock` offers wall time, which is exactly what a challenge's expiry must not follow. The
/// attribute is on the fn because the call is a trailing expression (an attribute on an
/// expression is not stable).
#[allow(clippy::disallowed_methods)]
fn monotonic_now() -> Instant {
    Instant::now()
}

/// Mint a fresh challenge, remember it with an expiry, and return its base64url text.
fn issue_challenge() -> Result<String> {
    issue_challenge_at(monotonic_now())
}

/// [`issue_challenge`] at a given monotonic instant — the seam the expiry tests drive.
fn issue_challenge_at(now: Instant) -> Result<String> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw)
        .map_err(|e| Error::Endpoint(format!("no OS randomness for a challenge: {e}")))?;
    let challenge = b64().encode(raw);
    // Held across no await: every critical section on this lock is a few map operations.
    let mut store = challenges().lock().expect("challenge store poisoned");
    store.retain(|_, exp| *exp > now); // opportunistic sweep so the map cannot grow without bound
    store.insert(challenge.clone(), now + CHALLENGE_TTL);
    Ok(challenge)
}

/// Consume a challenge: it must be one we issued and still in date, and it is removed so it
/// cannot be presented twice.
fn consume_challenge(challenge: &str) -> bool {
    consume_challenge_at(challenge, monotonic_now())
}

/// [`consume_challenge`] at a given monotonic instant.
fn consume_challenge_at(challenge: &str, now: Instant) -> bool {
    let mut store = challenges().lock().expect("challenge store poisoned");
    match store.remove(challenge) {
        Some(exp) => exp > now,
        None => false,
    }
}

// =====================================================================================
// The credential store — a small JSON file, the registered public key(s) for the one user.
//
// Three rules, each one a way the gate used to fail OPEN:
//
// - ABSENT means "not enrolled" (the gate is inert); PRESENT but unreadable or unparsable is an
//   error, and the gate refuses every decision until someone repairs it at the box. It used to
//   read as "not enrolled", so a truncated file silently downgraded every decision to token-only.
// - Writes are ATOMIC (temp file in the same directory, fsync, rename), so a crash leaves the old
//   file or the new one, never half of one.
// - load → verify → save runs under ONE process-wide lock, so two concurrent assertions cannot
//   each write back the copy they loaded and lower the stored signature counter.
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

/// Serializes every read-modify-write of the credential file in this process. It guards no
/// data of its own (the file is the data), so a poisoned lock is safe to take over. Held across
/// no await: the gate and the register endpoint hold it only in synchronous code.
fn credential_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// The registered credentials. `Ok(empty)` only when the file is ABSENT; a file that is present
/// but cannot be read or parsed is an `Err` naming it, which every caller treats as "refuse".
fn load_credentials() -> std::result::Result<Vec<StoredCredential>, String> {
    let path = credentials_path();
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
            format!(
                "{} is present but not a credential list: {e}",
                path.display()
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("{} is present but unreadable: {e}", path.display())),
    }
}

/// The loud half of failing closed: one line on stderr per refused request, naming the file.
fn store_unreadable(detail: &str) {
    eprintln!(
        "ikigai passkey: REFUSING every passkey-gated decision: {detail}. Repair or remove the \
         file at the box (removing it un-enrolls; enroll again with `sink urn:passkey:enroll-open`)."
    );
}

fn save_credentials(creds: &[StoredCredential]) -> Result<()> {
    let json = serde_json::to_vec_pretty(creds)
        .map_err(|e| Error::Endpoint(format!("cannot serialize credentials: {e}")))?;
    write_atomic(&credentials_path(), &json)
        .map_err(|e| Error::Endpoint(format!("cannot write credentials: {e}")))
}

/// Replace `path` with `bytes` whole: write a sibling temp file (owner-only), fsync it, rename it
/// over the target, then fsync the directory so the rename itself survives a crash. A reader —
/// or a crash at any point — sees the old file or the new one, never a truncated one.
fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
    })?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    // Unique per process; within one, the credential lock serializes writers.
    let tmp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp); // a leftover from a crash would refuse `create_new`
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let write_then_rename = |opts: &std::fs::OpenOptions| -> std::io::Result<()> {
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    };
    let written = write_then_rename(&opts);
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return written;
    }
    // Durability of the rename, best-effort: not every platform can open a directory to sync it.
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Whether the gate is armed. True when a credential is registered — and ALSO when the store is
/// present but unreadable, because then the gate refuses everything (it fails closed).
pub fn is_enrolled() -> bool {
    load_credentials().map_or(true, |c| !c.is_empty())
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

/// What `/passkey/register` shows on an edge started without `--passkey-rp-id`.
const NOT_CONFIGURED_BODY: &str = "<p>This edge has no passkey relying party configured, so a \
     passkey registered here would be bound to nothing. Restart it with <code>--passkey-rp-id \
     &lt;domain&gt;</code> (and <code>--passkey-origin</code> if the origin is not \
     <code>https://&lt;domain&gt;</code>), then open an enrollment window.</p>";

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

/// Serves `PASSKEY_APP_JS` as a same-origin JavaScript file so the strict edge CSP admits it.
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
            // ★ ON THE ACTION, not beside it. `Description::action` takes an explicit
            // `ActionSpec` WHOLE — `action_specs()` never merges the flat `.output()` into
            // one — so the flat declaration below is invisible to every consumer that reads
            // the manifold's actions. Kept as well because `Description::outputs` is its own
            // public field; the action is the one that is read. (Conformance 0.2.0's OUTPUTS
            // check found all four passkey faces undeclared this way.)
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("the script")
                    .output("application/javascript; charset=utf-8"),
            )
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
/// "Not enrolled" means the credential file is ABSENT. A file that is present but unreadable, or
/// credentials with no [`RelyingParty`] configured to check them against, refuse every decision
/// and say why on stderr: the gate fails closed, never open.
///
/// On success the challenge is consumed (single-use) and any advanced signature counter persisted.
/// Every failure is one `Denied` — a prober learns nothing from which check tripped.
pub fn require_passkey(inv: &Invocation<'_>) -> Result<()> {
    let denied = || Error::Denied("this action needs your passkey".to_string());

    // One lock from load to save, so a concurrent assertion cannot write back a stale copy.
    let _held = credential_lock();
    let creds = match load_credentials() {
        Ok(creds) => creds,
        Err(detail) => {
            store_unreadable(&detail);
            return Err(denied());
        }
    };
    if creds.is_empty() {
        return Ok(()); // inert until enrolled
    }
    let Some(rp) = relying_party() else {
        eprintln!(
            "ikigai passkey: REFUSING every passkey-gated decision: a credential is enrolled but \
             this edge has no relying party configured (start it with `--passkey-rp-id <domain>`)."
        );
        return Err(denied());
    };

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

    let policy = ikigai_passkey::Policy {
        rp_id: rp.rp_id(),
        origin: rp.origin(),
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
    #[cfg(test)]
    tests::after_verify();

    // Persist an advanced counter so a cloned authenticator's replay is caught next time. The
    // copy written back is the one loaded under the lock still held, so nothing newer can be
    // overwritten, and the guard below means the stored counter only ever rises.
    if new_count > stored.sign_count {
        let mut all = creds;
        if let Some(c) = all.iter_mut().find(|c| c.id == id_b64) {
            c.sign_count = new_count;
        }
        // Best-effort: a failed write must not undo a real decision — but it is said out loud.
        if let Err(e) = save_credentials(&all) {
            eprintln!("ikigai passkey: could not persist the advanced signature counter: {e}");
        }
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
        // The same fail-closed reading as the gate: a broken store or a missing relying party
        // with credentials enrolled is an error the page shows, not "nothing enrolled" (which
        // would tell the page to submit token-only into a gate that will refuse it anyway).
        let unavailable = || Error::Endpoint("passkey sign-in is unavailable on this edge".into());
        let creds = load_credentials().map_err(|detail| {
            store_unreadable(&detail);
            unavailable()
        })?;
        let rp = relying_party();
        if rp.is_none() && !creds.is_empty() {
            eprintln!(
                "ikigai passkey: a credential is enrolled but this edge has no relying party \
                 configured (start it with `--passkey-rp-id <domain>`)."
            );
            return Err(unavailable());
        }
        let challenge = issue_challenge()?;
        let allow: Vec<_> = creds
            .into_iter()
            .map(|c| json!({ "type": "public-key", "id": c.id }))
            .collect();
        let body = json!({
            "challenge": challenge,
            "rpId": rp.as_ref().map(RelyingParty::rp_id),
            "allowCredentials": allow,
            "userVerification": "preferred",
            "enrolled": !allow.is_empty(),
        });
        Ok(Representation::new(
            ReprType::new("application/json").with_param("charset", "utf-8"),
            serde_json::to_vec(&body).expect("serializable").to_vec(),
        ))
    }
    fn name(&self) -> &str {
        "passkey-challenge"
    }
    fn describe(&self) -> Description {
        Description::new("passkey-challenge")
            .title("Issue a WebAuthn challenge")
            .summary("A fresh single-use challenge plus the registered credential ids, for a login ceremony.")
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("mint a challenge")
                    .output("application/json; charset=utf-8"),
            )
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
                    .output("text/plain; charset=utf-8")
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
                if relying_party().is_none() {
                    return Ok(page("Passkeys are not configured", NOT_CONFIGURED_BODY));
                }
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
                // Registering binds a credential to a relying party; with none configured there
                // is nothing correct to bind it to (the old default silently chose production).
                if relying_party().is_none() {
                    return Err(Error::Denied(
                        "this edge has no passkey relying party configured".to_string(),
                    ));
                }
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

                let _held = credential_lock();
                // A store that is present but unreadable is not overwritten from the public
                // face: the person at the box repairs or removes it, then enrolls again.
                let mut creds = load_credentials().map_err(|detail| {
                    store_unreadable(&detail);
                    Error::Endpoint(
                        "the passkey store on this edge is unreadable; repair or remove it at \
                         the box, then enroll again"
                            .to_string(),
                    )
                })?;
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
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("show the enrolment page")
                    .output("text/html; charset=utf-8"),
            )
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("store a credential (window must be open)")
                    .output("text/html; charset=utf-8"),
            )
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
        static TEST_RP: std::cell::RefCell<Option<RelyingParty>> =
            const { std::cell::RefCell::new(None) };
    }

    /// The current thread's override root, if a test set one. `store_root()` consults this.
    pub(super) fn test_root() -> Option<std::path::PathBuf> {
        TEST_ROOT.with(|r| r.borrow().clone())
    }

    /// The current thread's relying party. `relying_party()` reads ONLY this under test, so the
    /// unconfigured case is reachable without racing the configured tests.
    pub(super) fn test_rp() -> Option<RelyingParty> {
        TEST_RP.with(|r| r.borrow().clone())
    }

    const RP_ID: &str = "edge.test";
    const ORIGIN: &str = "https://edge.test";

    fn test_relying_party() -> RelyingParty {
        RelyingParty::new(RP_ID, None).unwrap()
    }

    fn unconfigure() {
        TEST_RP.with(|r| *r.borrow_mut() = None);
    }

    // Give this test its own workspace root — set on THIS thread only, so parallel tests never
    // collide on the credential/window files (a global env var would race across them) — and a
    // configured relying party, which a test that wants none removes with `unconfigure`.
    fn isolate(name: &str) {
        let dir = std::env::temp_dir().join(format!("ikigai-passkey-ep-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TEST_ROOT.with(|r| *r.borrow_mut() = Some(dir));
        TEST_RP.with(|r| *r.borrow_mut() = Some(test_relying_party()));
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
                r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{ORIGIN}"}}"#
            )
            .into_bytes();
            let mut auth = Sha256::digest(RP_ID.as_bytes()).to_vec();
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

    thread_local! {
        static AFTER_VERIFY: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    /// The seam between a successful verification and the counter write-back: a test parks a
    /// closure here to interleave a second request at exactly the point the race lives.
    pub(super) fn after_verify() {
        if let Some(hook) = AFTER_VERIFY.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }

    fn stored_count() -> u32 {
        let bytes = std::fs::read(credentials_path()).unwrap();
        let creds: Vec<StoredCredential> = serde_json::from_slice(&bytes).unwrap();
        creds[0].sign_count
    }

    #[test]
    fn a_corrupt_credential_file_fails_closed() {
        isolate("corrupt");
        Device::new().register();
        // Truncate the store mid-document, as a crash during a non-atomic write would.
        let full = std::fs::read(credentials_path()).unwrap();
        std::fs::write(credentials_path(), &full[..full.len() / 2]).unwrap();
        assert!(
            run_gate("id=abc&exp=1").is_err(),
            "a present but unparsable credential store must refuse, not read as `not enrolled`"
        );
        // An empty (zero-byte) file is present too: still refused.
        std::fs::write(credentials_path(), b"").unwrap();
        assert!(
            run_gate("id=abc&exp=1").is_err(),
            "a zero-byte store refuses"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_credential_write_replaces_the_file_rather_than_rewriting_it_in_place() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        isolate("atomic");
        let d = Device::new();
        d.register();
        let before = std::fs::metadata(credentials_path()).unwrap().ino();
        d.register();
        let meta = std::fs::metadata(credentials_path()).unwrap();
        // An in-place write (truncate, then write) keeps the inode, so a reader or a crash
        // between the two sees a truncated file. Temp + rename swaps in a new inode whole.
        assert_ne!(
            before,
            meta.ino(),
            "the store must be replaced by rename, not truncated and rewritten in place"
        );
        assert_eq!(meta.permissions().mode() & 0o777, 0o600, "owner-only");
        // And no temp file is left behind beside it.
        let leftovers: Vec<_> = std::fs::read_dir(store_root())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "passkey-credentials.json")
            .collect();
        assert!(leftovers.is_empty(), "stray files: {leftovers:?}");
    }

    #[test]
    fn interleaved_assertions_never_lower_the_stored_counter() {
        isolate("race");
        let root = test_root().unwrap();
        let d = Device::new();
        d.register();
        let c_low = issue_challenge().unwrap();
        let c_high = issue_challenge().unwrap();
        let low = d.assert_fields(&c_low, 0x05, 2);
        let high = d.assert_fields(&c_high, 0x05, 3);

        // Request A (counter 2) has verified and is about to write back; request B (counter 3)
        // runs now on another thread. Without a lock B completes inside A's window and A then
        // writes its stale copy over B's; with one, B waits for A and loads A's result.
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let b = std::sync::Arc::new(std::sync::Mutex::new(None));
        let b_slot = b.clone();
        AFTER_VERIFY.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                let handle = std::thread::spawn(move || {
                    TEST_ROOT.with(|r| *r.borrow_mut() = Some(root));
                    TEST_RP.with(|r| *r.borrow_mut() = Some(test_relying_party()));
                    let r = run_gate(&high);
                    let _ = done_tx.send(());
                    r
                });
                // Give B the chance to finish inside A's window (it cannot, under a lock).
                let _ = done_rx.recv_timeout(std::time::Duration::from_millis(300));
                *b_slot.lock().unwrap() = Some(handle);
            }))
        });
        assert!(run_gate(&low).is_ok(), "A's assertion is valid");
        let handle = b.lock().unwrap().take().expect("the hook ran");
        assert!(handle.join().unwrap().is_ok(), "B's assertion is valid");
        assert_eq!(
            stored_count(),
            3,
            "the stored counter must be the highest seen, never a stale write-back"
        );
    }

    /// Issue `verb` at `iri` against a kernel that binds only `endpoint` there.
    fn call(
        iri: &str,
        endpoint: impl Endpoint + 'static,
        verb: Verb,
        body: Option<&str>,
    ) -> Result<Representation> {
        let kernel = Kernel::new(std::sync::Arc::new(
            ikigai_core::EndpointSpace::new().bind(ikigai_core::Exact::new(iri), endpoint),
        ));
        let mut req = Request::new(verb, Iri::parse(iri).unwrap());
        if let Some(body) = body {
            req = req.with_arg("content", ArgRef::Inline(body.as_bytes().to_vec()));
        }
        futures::executor::block_on(kernel.issue(req, &Capability::root()))
    }

    fn open_window() {
        std::fs::write(enroll_window_path(), (now_secs() + 60).to_string()).unwrap();
    }

    #[test]
    fn a_corrupt_store_errors_the_challenge_and_is_not_overwritten_by_registration() {
        isolate("corrupt-faces");
        std::fs::write(credentials_path(), b"[{\"id\":").unwrap();
        assert!(
            call(
                "urn:passkey:challenge",
                PasskeyChallenge,
                Verb::Source,
                None
            )
            .is_err(),
            "the page must not be told `not enrolled` and submit token-only"
        );
        open_window();
        let body = format!(
            "id={}&spki={}",
            b64().encode(b"cred-2"),
            Device::new().spki_b64()
        );
        assert!(
            call(
                "urn:passkey:register",
                PasskeyRegister,
                Verb::Sink,
                Some(&body)
            )
            .is_err(),
            "registration does not paper over a broken store from the public face"
        );
        assert_eq!(std::fs::read(credentials_path()).unwrap(), b"[{\"id\":");
        assert!(is_enrolled(), "a broken store counts as armed");
    }

    #[test]
    fn an_enrolled_gate_with_no_relying_party_refuses_everything() {
        isolate("no-rp-enrolled");
        let d = Device::new();
        d.register();
        let challenge = issue_challenge().unwrap();
        let body = d.assert_fields(&challenge, 0x05, 1);
        unconfigure();
        assert!(run_gate(&body).is_err(), "no RP to check against = refuse");
        assert!(
            call(
                "urn:passkey:challenge",
                PasskeyChallenge,
                Verb::Source,
                None
            )
            .is_err(),
            "and the challenge says so rather than naming no RP"
        );
    }

    #[test]
    fn an_unconfigured_edge_with_nothing_enrolled_stays_inert() {
        isolate("no-rp-inert");
        unconfigure();
        assert!(
            run_gate("id=abc&exp=1").is_ok(),
            "deploying cannot brick the links"
        );
        let rep = call(
            "urn:passkey:challenge",
            PasskeyChallenge,
            Verb::Source,
            None,
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&rep.bytes).unwrap();
        assert_eq!(v["enrolled"], false);
        assert!(
            v["rpId"].is_null(),
            "no RP is reported as none, never a default"
        );
    }

    #[test]
    fn registration_needs_a_relying_party() {
        isolate("no-rp-register");
        open_window();
        let body = format!(
            "id={}&spki={}",
            b64().encode(b"cred-1"),
            Device::new().spki_b64()
        );
        unconfigure();
        assert!(
            call(
                "urn:passkey:register",
                PasskeyRegister,
                Verb::Sink,
                Some(&body)
            )
            .is_err(),
            "nothing to bind a credential to"
        );
        assert!(!credentials_path().exists());
        let page = call("urn:passkey:register", PasskeyRegister, Verb::Source, None).unwrap();
        assert!(String::from_utf8_lossy(&page.bytes).contains("--passkey-rp-id"));

        TEST_RP.with(|r| *r.borrow_mut() = Some(test_relying_party()));
        assert!(call(
            "urn:passkey:register",
            PasskeyRegister,
            Verb::Sink,
            Some(&body)
        )
        .is_ok());
        assert!(is_enrolled());
    }

    #[test]
    fn a_challenge_expires_on_the_monotonic_clock() {
        isolate("ttl");
        let t0 = monotonic_now();
        let fresh = issue_challenge_at(t0).unwrap();
        assert!(consume_challenge_at(
            &fresh,
            t0 + CHALLENGE_TTL - Duration::from_secs(1)
        ));
        let stale = issue_challenge_at(t0).unwrap();
        assert!(
            !consume_challenge_at(&stale, t0 + CHALLENGE_TTL),
            "a challenge is dead at its TTL"
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
