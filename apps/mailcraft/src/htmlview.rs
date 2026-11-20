//! Showing a mail's HTML as the sender meant it: the system's own browser engine (WebView2 on
//! Windows, WebKitGTK on Linux) in a child view laid over the reading pane.
//!
//! Mail is hostile input, so every message is prepared before it is shown:
//! - a Content-Security-Policy goes first: no scripts, no forms, no plugins, no frames, and no
//!   remote images until the reader asks for them (tracking pixels, like Outlook);
//! - `cid:` references (pictures sent inside the mail) point at the view's own `mailcraft:`
//!   address, which hands out the open message's pictures and nothing else;
//! - any navigation away from the message (a clicked link) is cancelled and handed to the
//!   default browser instead.
//!
//! The page itself comes through that address too (`mailcraft://localhost/message/<n>`; on
//! Windows WebView2 sees it as `http://mailcraft.localhost/...`). It used to be handed over as
//! one string, with every picture written into it as base64, and WebView2 refuses strings over
//! 2 MB: an Outlook reply with a 1.3 MB screenshot opened blank (17 Nov 2026). Through
//! the address there is no size limit, and pictures cost nothing until they are drawn.
//!
//! Once the reader clicks into a message the view has the keyboard, and MailCraft's shortcuts
//! (Ctrl+W, Delete, Ctrl+R...) went nowhere (2026-10-29). MailCraft's own small script
//! hands those keys back; copying, selecting and zooming stay with the message. The policy lets
//! that one script run by a random code (a nonce) made for each message, so a script in the
//! mail itself still cannot.

use base64::Engine;
use regex::Regex;
use std::sync::LazyLock;

/// A picture carried inside the mail: its Content-ID, MIME type and bytes.
pub struct Inline {
    pub cid: String,
    pub mime: String,
    pub bytes: Vec<u8>,
}

/// The parts of a parsed mail that the HTML can show by `cid:` (anything with a Content-ID).
pub fn inline_parts(m: &mail_parser::Message) -> Vec<Inline> {
    use mail_parser::MimeHeaders;
    m.parts
        .iter()
        .filter_map(|p| {
            let cid = p.content_id()?.to_string();
            let ct = p.content_type()?;
            Some(Inline { cid, mime: format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("octet-stream")), bytes: p.contents().to_vec() })
        })
        .collect()
}

static REMOTE_IMG: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"(?i)(<img[^>]+src\s*=\s*["']?\s*https?:|url\(\s*["']?\s*https?:|background\s*=\s*["']?\s*https?:)"#).ok());

/// Does the message pull pictures from the internet?
pub fn has_remote_images(html: &str) -> bool {
    REMOTE_IMG.as_ref().is_some_and(|r| r.is_match(html))
}

/// Where the view finds the open message's `n`th inline picture (on the page's own address).
fn inline_path(n: usize) -> String {
    format!("/inline/{n}")
}

/// The policy's opening, as `prepare` writes it; `page_policy` reads it back.
const CSP_META: &str = "<meta http-equiv=\"Content-Security-Policy\" content=\"";

/// The message, ready to show: the policy first, inline pictures pointed at the view's own
/// address. `theme_css` (dark reading, high contrast) goes last, so it wins over the message's
/// own style. Show it with [`HtmlView::show`] and the same `inline`.
pub fn prepare(html: &str, inline: &[Inline], allow_remote: bool, theme_css: &str) -> String {
    // 'self' is the view's own address: the mail's own pictures, and nothing from outside.
    let img = if allow_remote { "img-src 'self' data: https: http:" } else { "img-src 'self' data:" };
    // No random code, no script at all: the keys then simply stay with the message.
    let (scripts, ours) = match nonce() {
        Some(n) => (format!("'nonce-{n}'"), format!("<script nonce=\"{n}\">{KEYS_SCRIPT}</script>")),
        None => ("'none'".to_string(), String::new()),
    };
    let csp = format!(
        "default-src 'none'; {img}; style-src 'unsafe-inline' data:; font-src data:; media-src 'none'; script-src {scripts}; object-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'"
    );
    let mut body = html.to_string();
    // Longest Content-ID first, so one that starts another's is not swapped inside it.
    let mut order: Vec<usize> = (0..inline.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(inline.get(i).map_or(0, |p| p.cid.len())));
    for i in order {
        let Some(p) = inline.get(i) else { continue };
        let cid = p.cid.trim_matches(['<', '>']);
        if cid.is_empty() {
            continue;
        }
        let at = inline_path(i);
        for form in [format!("cid:{cid}"), format!("CID:{cid}")] {
            body = body.replace(&form, &at);
        }
    }
    // Before <html>: the parser puts these in <head> ahead of anything that loads. No referrer:
    // a remote picture the reader allowed learns nothing about where it was shown.
    format!(
        "{CSP_META}{csp}\"><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\"><meta name=\"color-scheme\" content=\"light\">\
{ours}\
         <style>html{{background:#fff}} body{{margin:14px 18px; font-family:'Segoe UI',Arial,sans-serif; font-size:14px; overflow-wrap:anywhere}} img{{max-width:100%;height:auto}}</style>{body}{}",
        if theme_css.is_empty() { String::new() } else { format!("<style>{theme_css}</style>") }
    ) + &format!("<style>{}</style>", crate::links::CSS)
}

/// The policy `prepare` put at the top of a page, to send again as the page's header.
#[cfg(any(windows, target_os = "linux"))]
fn page_policy(page: &str) -> Option<&str> {
    let rest = page.strip_prefix(CSP_META)?;
    rest.get(..rest.find('"')?)
}

/// A fresh random code for the one script a message may run (MailCraft's own); None when
/// there is no randomness to make one from.
fn nonce() -> Option<String> {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 16];
    ring::rand::SystemRandom::new().fill(&mut b).ok()?;
    Some(base64::engine::general_purpose::STANDARD.encode(b))
}

/// Plain-text mail as HTML that keeps its line breaks.
pub fn from_text(text: &str) -> String {
    let esc = text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    format!("<pre style=\"white-space:pre-wrap;font-family:Consolas,'Courier New',monospace;font-size:13px\">{esc}</pre>")
}

/// The view's own address (a custom protocol): `mailcraft://localhost/...`.
#[cfg(any(windows, target_os = "linux"))]
const SCHEME: &str = "mailcraft";

/// The address of page `n` as the view is told to load it. WebView2 only takes custom schemes
/// through wry's stand-in, `http://mailcraft.localhost/...` (plain http, as wry does by
/// default: an https page would block the http pictures a reader allows); WebKitGTK takes the
/// scheme itself.
#[cfg(any(windows, target_os = "linux"))]
fn page_url(n: u64) -> String {
    if cfg!(windows) { format!("http://{SCHEME}.localhost/message/{n}") } else { format!("{SCHEME}://localhost/message/{n}") }
}

/// Is `url` page `n`, in any of the forms the engines report it (WebView2's http or https
/// stand-in, or the scheme itself), give or take a #fragment (a link within the message)?
#[cfg(any(windows, target_os = "linux"))]
fn is_page(url: &str, n: u64) -> bool {
    let url = url.split('#').next().unwrap_or(url);
    let path = ["http://mailcraft.localhost", "https://mailcraft.localhost", "mailcraft://localhost"].iter().find_map(|p| url.strip_prefix(p));
    path == Some(format!("/message/{n}").as_str())
}

/// Is `url` on the view's own address at all (any page, picture or path)? Such a URL is never
/// a link to open in the browser: there is nothing the browser could show at it.
#[cfg(any(windows, target_os = "linux"))]
fn is_ours(url: &str) -> bool {
    ["http://mailcraft.localhost", "https://mailcraft.localhost", "mailcraft://localhost"]
        .iter()
        .any(|p| url.strip_prefix(p).is_some_and(|rest| rest.is_empty() || rest.starts_with(['/', '?', '#'])))
}

/// What the view's address hands out: the message shown now and its inline pictures, nothing
/// else (no files, no other messages).
#[cfg(any(windows, target_os = "linux"))]
#[derive(Default)]
struct Served {
    /// Which page this is; each message (or new look of one) gets the next number.
    page: u64,
    html: std::sync::Arc<[u8]>,
    policy: String,
    /// MIME type and bytes of each inline picture, by its place in `prepare`'s list.
    parts: Vec<(String, std::sync::Arc<[u8]>)>,
}

#[cfg(any(windows, target_os = "linux"))]
impl Served {
    /// Page `page`: `html` from [`prepare`] and the same `inline` pictures.
    fn new(page: u64, html: &str, inline: &[Inline]) -> Served {
        Served {
            page,
            html: html.as_bytes().into(),
            policy: page_policy(html).unwrap_or(BLANK_POLICY).to_string(),
            parts: inline.iter().map(|p| (p.mime.clone(), p.bytes.as_slice().into())).collect(),
        }
    }
}

/// Until a message is shown: an empty page, under the strictest policy.
#[cfg(any(windows, target_os = "linux"))]
const BLANK_POLICY: &str = "default-src 'none'; style-src 'unsafe-inline'; frame-src 'none'; form-action 'none'; base-uri 'none'";

#[cfg(any(windows, target_os = "linux"))]
type Reply = wry::http::Response<std::borrow::Cow<'static, [u8]>>;

/// A reply to the view; `headers` are only ones made here (never the mail's), so they are valid.
#[cfg(any(windows, target_os = "linux"))]
fn reply(status: u16, headers: &[(&str, &str)], body: Vec<u8>) -> Reply {
    let mut r = wry::http::Response::builder().status(status);
    for (k, v) in headers {
        r = r.header(*k, *v);
    }
    r.body(std::borrow::Cow::Owned(body)).unwrap_or_else(|_| {
        let mut bare = wry::http::Response::new(std::borrow::Cow::Borrowed(&[][..]));
        *bare.status_mut() = wry::http::StatusCode::INTERNAL_SERVER_ERROR;
        bare
    })
}

/// A MIME type from the mail, only if it is a plain type/subtype (it goes into a header).
#[cfg(any(windows, target_os = "linux"))]
fn safe_mime(m: &str) -> &str {
    let ok = m.len() <= 100
        && m.split_once('/').is_some_and(|(t, s)| {
            let good = |x: &str| !x.is_empty() && x.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&b));
            good(t) && good(s)
        });
    if ok { m } else { "application/octet-stream" }
}

/// Answer one request on the view's address (`mailcraft://localhost/...`, which is how wry
/// hands it over on both engines): the current page, or one of its inline pictures; 404 for
/// anything else.
#[cfg(any(windows, target_os = "linux"))]
fn answer(served: &Served, req: &wry::http::Request<Vec<u8>>) -> Reply {
    let uri = req.uri();
    let ours = uri.scheme_str() == Some(SCHEME) && uri.host() == Some("localhost");
    if !ours || !matches!(*req.method(), wry::http::Method::GET | wry::http::Method::HEAD) {
        return reply(404, &[], Vec::new());
    }
    let path = uri.path();
    if path == format!("/message/{}", served.page) {
        let policy = if served.policy.is_empty() { BLANK_POLICY } else { served.policy.as_str() };
        return reply(
            200,
            &[
                ("Content-Type", "text/html; charset=utf-8"),
                ("Content-Security-Policy", policy),
                ("Referrer-Policy", "no-referrer"),
                ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff"),
            ],
            served.html.to_vec(),
        );
    }
    let part = path.strip_prefix("/inline/").and_then(|n| n.parse::<usize>().ok()).and_then(|n| served.parts.get(n));
    match part {
        Some((mime, bytes)) => reply(
            200,
            &[
                ("Content-Type", safe_mime(mime)),
                // Should a part ever be opened as a page of its own: nothing in it runs.
                ("Content-Security-Policy", "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; sandbox"),
                ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff"),
            ],
            bytes.to_vec(),
        ),
        None => reply(404, &[], Vec::new()),
    }
}

/// The browser view itself (Windows and Linux).
#[cfg(any(windows, target_os = "linux"))]
pub struct HtmlView {
    view: wry::WebView,
    _context: wry::WebContext,
    /// Keys pressed in the view that belong to MailCraft, waiting for the next frame.
    keys: std::sync::Arc<std::sync::Mutex<Vec<egui::Event>>>,
    loaded: std::rc::Rc<std::cell::Cell<bool>>,
    /// The page and pictures the view's address hands out (shared with its handler).
    served: std::sync::Arc<std::sync::Mutex<Served>>,
    /// What is shown: the page, and each inline picture's Content-ID and size.
    shown: Option<(String, Vec<(String, usize)>)>,
    visible: bool,
    /// Where it was last put (x, y, width, height in physical pixels).
    bounds: Option<(i32, i32, u32, u32)>,
}

#[cfg(any(windows, target_os = "linux"))]
impl HtmlView {
    pub fn new(window: &impl wry::raw_window_handle::HasWindowHandle, ctx: egui::Context) -> Result<Self, String> {
        #[cfg(target_os = "linux")]
        gtk::init().map_err(|e| e.to_string())?;
        // WebView2 keeps its profile beside the exe unless told otherwise, and that fails
        // (Access is denied) when the exe runs from a share or Program Files.
        let dir = crate::accounts::cache_path().with_file_name("WebView2");
        let _ = std::fs::create_dir_all(&dir);
        let mut context = wry::WebContext::new(Some(dir));
        // A page that finished loading may have taken the keyboard; `show` gives it back.
        let loaded = std::rc::Rc::new(std::cell::Cell::new(false));
        let flag = loaded.clone();
        let keys = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (sink, repaint) = (keys.clone(), ctx.clone());
        let served = std::sync::Arc::new(std::sync::Mutex::new(Served::default()));
        let (to_serve, nav_served) = (served.clone(), served.clone());
        let builder = wry::WebViewBuilder::new_with_web_context(&mut context)
            // The message and its pictures, by address: no 2 MB limit (see the top of the file).
            .with_custom_protocol(SCHEME.to_string(), move |_id, req| match to_serve.lock() {
                Ok(s) => answer(&s, &req),
                Err(_) => reply(404, &[], Vec::new()),
            })
            // Ctrl+scroll (and Ctrl + plus, minus, 0) zooms the message: WebView2's own zoom,
            // off unless asked for (2026-10-29: "sometimes I need to zoom in, but can't").
            .with_hotkeys_zoom(true)
            .with_ipc_handler(move |req: wry::http::Request<String>| {
                log::debug!("message view: {}", req.body());
                // Once a run: the evidence that the message's key script runs on this PC.
                static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
                if req.body() == "ready" && !SAID.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    log::info!("the message view hands AltMail's keys back (Ctrl+W, Delete...)");
                }
                if let Some(ev) = key_event(req.body())
                    && let Ok(mut k) = sink.lock()
                {
                    k.push(ev);
                    repaint.request_repaint();
                }
            })
            .with_on_page_load_handler(move |event, _url| {
                if matches!(event, wry::PageLoadEvent::Finished) {
                    flag.set(true);
                    ctx.request_repaint();
                }
            })
            .with_url(page_url(0))
            .with_visible(false)
            .with_devtools(false)
            .with_navigation_handler(move |url: String| {
                // The message itself is the page on the view's own address, the one shown now;
                // anything else is a click.
                if nav_served.lock().is_ok_and(|s| is_page(&url, s.page)) {
                    return true;
                }
                // An older page of our own (the first blank one, or a message already replaced
                // when the next is shown quickly) is stopped here, never handed to the browser.
                if !is_ours(&url) {
                    open_externally(&url);
                }
                false
            })
            .with_new_window_req_handler(|url: String, _features| {
                if !is_ours(&url) {
                    open_externally(&url);
                }
                wry::NewWindowResponse::Deny
            });
        // Plain http for the stand-in address (wry's default, said out loud): see `page_url`.
        #[cfg(windows)]
        let builder = wry::WebViewBuilderExtWindows::with_https_scheme(builder, false);
        let view = builder.build_as_child(window).map_err(|e| e.to_string())?;
        Ok(HtmlView { view, _context: context, keys, loaded, served, shown: None, visible: false, bounds: None })
    }

    /// Show `html` (from [`prepare`], with the same `inline` pictures) over `rect`, given in
    /// physical pixels.
    pub fn show(&mut self, html: &str, inline: &[Inline], x: f32, y: f32, w: f32, h: f32) {
        let same = self.shown.as_ref().is_some_and(|(page, parts)| {
            page == html && parts.len() == inline.len() && parts.iter().zip(inline).all(|((c, n), p)| *c == p.cid && *n == p.bytes.len())
        });
        if !same {
            let page = match self.served.lock() {
                Ok(mut s) => {
                    *s = Served::new(s.page.wrapping_add(1), html, inline);
                    Some(s.page)
                }
                Err(_) => None,
            };
            // Loaded with the lock let go: the engine may ask for the page straight away.
            if let Some(n) = page {
                let _ = self.view.load_url(&page_url(n));
            }
            // Loading a page can pull the keyboard into the view: give it back, so the list's
            // keys (arrows, Delete, Ctrl+A...) keep working; again when the load finishes.
            let _ = self.view.focus_parent();
            self.shown = Some((html.to_string(), inline.iter().map(|p| (p.cid.clone(), p.bytes.len())).collect()));
        }
        // Only when it moved or changed size: on Windows each move is a real window move, which
        // brings another frame, which moved it again: MailCraft and Explorer kept busy for ever.
        let bounds = (x as i32, y as i32, w.max(1.0) as u32, h.max(1.0) as u32);
        if self.bounds != Some(bounds) {
            let _ = self.view.set_bounds(wry::Rect {
                position: wry::dpi::PhysicalPosition::new(bounds.0, bounds.1).into(),
                size: wry::dpi::PhysicalSize::new(bounds.2, bounds.3).into(),
            });
            self.bounds = Some(bounds);
        }
        if self.loaded.replace(false) {
            let _ = self.view.focus_parent();
        }
        if !self.visible {
            let _ = self.view.set_visible(true);
            // Showing it must not take the keyboard from the message list (shortcuts, Ctrl+A).
            let _ = self.view.focus_parent();
            self.visible = true;
        }
    }

    /// Keys pressed in the view that are MailCraft's: the keyboard goes back to MailCraft with
    /// them, so the next ones reach it directly.
    pub fn take_keys(&self) -> Vec<egui::Event> {
        let keys = self.keys.lock().map(|mut k| std::mem::take(&mut *k)).unwrap_or_default();
        if !keys.is_empty() {
            let _ = self.view.focus_parent();
        }
        keys
    }

    /// The system's print dialog for what the view shows.
    pub fn print(&self) -> Result<(), String> {
        self.view.print().map_err(|e| e.to_string())
    }

    pub fn hide(&mut self) {
        if self.visible {
            let _ = self.view.set_visible(false);
            self.visible = false;
        }
    }
}

/// MailCraft's script in each message (by the nonce): hands MailCraft's keys back, through
/// the browser's own message channel (wry's `window.ipc` wrapper is itself an added script,
/// and those did not run in a page loaded from text in the test). Kept by the message: copy and select all (Ctrl+C, Ctrl+A, Ctrl+Insert), zoom (Ctrl with
/// plus, minus, 0), and plain typing and arrows, which scroll it. Everything else with Ctrl or
/// Alt, and Delete, Escape and the function keys, are MailCraft's. The mouse's back and
/// forward buttons come back as Alt+Left / Alt+Right (back and forward between folders).
const KEYS_SCRIPT: &str = r#"(function () {
  var post = (window.chrome && window.chrome.webview) ? function (m) { window.chrome.webview.postMessage(m); }
    : (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.ipc) ? function (m) { window.webkit.messageHandlers.ipc.postMessage(m); }
    : null;
  if (!post) return;
  var mine = ['KeyC', 'KeyA', 'Insert', 'Equal', 'Minus', 'Digit0', 'NumpadAdd', 'NumpadSubtract', 'Numpad0'];
  document.addEventListener('keydown', function (e) {
    var ours = (e.ctrlKey || e.altKey) ? mine.indexOf(e.code) < 0 : /^(Delete|Escape|F[0-9]+)$/.test(e.code);
    if (!ours || /^(Control|Shift|Alt|Meta)/.test(e.code)) return;
    e.preventDefault();
    e.stopPropagation();
    post('key:' + (e.ctrlKey ? 1 : 0) + (e.shiftKey ? 1 : 0) + (e.altKey ? 1 : 0) + ':' + e.code);
  }, true);
  var side = function (e) { return e.button === 3 || e.button === 4; };
  document.addEventListener('mousedown', function (e) { if (side(e)) e.preventDefault(); }, true);
  document.addEventListener('mouseup', function (e) {
    if (!side(e)) return;
    e.preventDefault();
    e.stopPropagation();
    post('key:001:' + (e.button === 3 ? 'ArrowLeft' : 'ArrowRight'));
  }, true);
  post('ready');
})();"#;

/// A key handed back by [`KEYS_SCRIPT`] ("key:<ctrl><shift><alt>:<code>") as egui's own.
#[cfg(any(windows, target_os = "linux"))]
fn key_event(msg: &str) -> Option<egui::Event> {
    let rest = msg.strip_prefix("key:")?;
    let (mods, code) = rest.split_once(':')?;
    let mut m = mods.chars().map(|c| c == '1');
    let (ctrl, shift, alt) = (m.next()?, m.next()?, m.next()?);
    let key = egui::Key::from_name(code.strip_prefix("Digit").unwrap_or(code))?;
    let modifiers = egui::Modifiers { alt, ctrl, shift, mac_cmd: false, command: ctrl };
    Some(egui::Event::Key { key, physical_key: Some(key), pressed: true, repeat: false, modifiers })
}

/// Linux: WebKitGTK needs GTK's events pumped; call once a frame.
pub fn pump() {
    #[cfg(target_os = "linux")]
    while gtk::is_initialized() && gtk::events_pending() {
        gtk::main_iteration_do(false);
    }
}

fn open_externally(url: &str) {
    #[cfg(windows)]
    {
        if url.starts_with("http://") || url.starts_with("https://") || url.starts_with("mailto:") {
            let _ = open::that_detached(url);
        }
    }
    #[cfg(not(windows))]
    log::info!("link clicked: {url}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn our_own_address_is_never_a_link() {
        for url in [
            "http://mailcraft.localhost/message/0",
            "https://mailcraft.localhost/message/9#x",
            "mailcraft://localhost/inline/2",
            "http://mailcraft.localhost",
        ] {
            assert!(is_ours(url), "{url}");
        }
        for url in [
            "http://mailcraft.localhost.evil.example/message/0",
            "https://example.com/mailcraft.localhost/message/0",
            "http://mailcraft.localhostx/",
            "mailto:a@b.c",
        ] {
            assert!(!is_ours(url), "{url}");
        }
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn keys_from_the_view_become_egui_keys() {
        let Some(egui::Event::Key { key, modifiers, pressed, .. }) = key_event("key:100:KeyW") else { panic!("Ctrl+W not read") };
        assert_eq!(key, egui::Key::W);
        assert!(pressed && modifiers.ctrl && modifiers.command && !modifiers.shift && !modifiers.alt);
        let Some(egui::Event::Key { key, modifiers, .. }) = key_event("key:110:Tab") else { panic!("Ctrl+Shift+Tab not read") };
        assert_eq!(key, egui::Key::Tab);
        assert!(modifiers.ctrl && modifiers.shift);
        assert!(matches!(key_event("key:000:Delete"), Some(egui::Event::Key { key: egui::Key::Delete, .. })));
        assert!(matches!(key_event("key:100:Digit1"), Some(egui::Event::Key { key: egui::Key::Num1, .. })));
        // F5, and the mouse's back button as the script hands it back (Alt+Left).
        assert!(matches!(key_event("key:000:F5"), Some(egui::Event::Key { key: egui::Key::F5, modifiers, .. }) if modifiers.is_none()));
        let Some(egui::Event::Key { key, modifiers, .. }) = key_event("key:001:ArrowLeft") else { panic!("Alt+Left not read") };
        assert!(key == egui::Key::ArrowLeft && modifiers.alt && !modifiers.ctrl && !modifiers.shift);
        for junk in ["", "key:", "key:1:KeyW", "key:100:NoSuchKey", "click:100:KeyW", "key:10x"] {
            assert!(key_event(junk).is_none(), "{junk:?}");
        }
    }

    #[test]
    fn policy_first_cid_inlined_remote_detected() {
        let html = r#"<html><body><img src="cid:logo@x"><img src="https://tracker.example/p.gif"><script>alert(1)</script></body></html>"#;
        assert!(has_remote_images(html));
        assert!(!has_remote_images("<img src='data:image/png;base64,AA'>"));
        let out = prepare(html, &[Inline { cid: "<logo@x>".into(), mime: "image/png".into(), bytes: vec![1, 2, 3] }], false, "");
        assert!(out.starts_with("<meta http-equiv=\"Content-Security-Policy\""));
        // Only MailCraft's own script, by its nonce; the mail's <script> has none.
        let nonce = out.split("script-src 'nonce-").nth(1).and_then(|r| r.split('\'').next()).unwrap();
        assert!(nonce.len() >= 20 && out.contains(&format!("<script nonce=\"{nonce}\">")) && out.contains("<script>alert(1)</script>"));
        // The mail's own pictures (the view's address) and data:, nothing remote.
        assert!(out.contains("img-src 'self' data:;"));
        assert!(out.contains("<meta name=\"referrer\" content=\"no-referrer\">"));
        assert_ne!(
            nonce,
            prepare(html, &[], false, "").split("script-src 'nonce-").nth(1).and_then(|r| r.split('\'').next()).unwrap(),
            "a new nonce each time"
        );
        assert!(out.contains("<img src=\"/inline/0\">") && !out.contains("cid:logo") && !out.contains("base64,AQID"));
        assert!(prepare(html, &[], true, "").contains("img-src 'self' data: https: http:"));
        assert_eq!(
            from_text("a < b\n"),
            "<pre style=\"white-space:pre-wrap;font-family:Consolas,'Courier New',monospace;font-size:13px\">a &lt; b\n</pre>"
        );
    }

    #[test]
    fn longer_content_ids_are_not_swapped_inside() {
        let parts = [
            Inline { cid: "<img@x>".into(), mime: "image/png".into(), bytes: vec![1] },
            Inline { cid: "<img@x.2>".into(), mime: "image/png".into(), bytes: vec![2] },
            Inline { cid: "<>".into(), mime: "image/png".into(), bytes: vec![3] },
        ];
        let out = prepare("<img src=\"cid:img@x\"><img src=\"CID:img@x.2\"><p>cid:</p>", &parts, false, "");
        assert!(out.contains("<img src=\"/inline/0\"><img src=\"/inline/1\"><p>cid:</p>"), "{out}");
    }

    /// A real, decodable PNG of `w` x `h` coloured noise, stored uncompressed (so it is big).
    fn noisy_png(w: u32, h: u32) -> Vec<u8> {
        fn crc(data: &[u8]) -> u32 {
            let mut c = 0xFFFF_FFFFu32;
            for &b in data {
                c ^= u32::from(b);
                for _ in 0..8 {
                    c = if c & 1 == 1 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
                }
            }
            !c
        }
        fn chunk(out: &mut Vec<u8>, kind: &[u8], data: &[u8]) {
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            let start = out.len();
            out.extend_from_slice(kind);
            out.extend_from_slice(data);
            let c = crc(&out[start..]);
            out.extend_from_slice(&c.to_be_bytes());
        }
        let mut x: u32 = 2_463_534_242;
        let mut raw = Vec::new();
        for _ in 0..h {
            raw.extend_from_slice(&[0]); // filter: none
            for _ in 0..w * 3 {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                raw.push((x >> 24) as u8);
            }
        }
        // zlib, stored blocks only.
        let mut z = vec![0x78, 0x01];
        let blocks: Vec<&[u8]> = raw.chunks(65_535).collect();
        for (i, b) in blocks.iter().enumerate() {
            z.push(u8::from(i + 1 == blocks.len()));
            z.extend_from_slice(&(b.len() as u16).to_le_bytes());
            z.extend_from_slice(&(!(b.len() as u16)).to_le_bytes());
            z.extend_from_slice(b);
        }
        let (mut a, mut b) = (1u32, 0u32);
        for &byte in &raw {
            a = (a + u32::from(byte)) % 65_521;
            b = (b + a) % 65_521;
        }
        z.extend_from_slice(&((b << 16) | a).to_be_bytes());
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&w.to_be_bytes());
        ihdr.extend_from_slice(&h.to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
        chunk(&mut png, b"IHDR", &ihdr);
        chunk(&mut png, b"IDAT", &z);
        chunk(&mut png, b"IEND", &[]);
        png
    }

    /// A synthetic Outlook-style reply: about 700 KB of HTML and a 1.6 MB screenshot inline.
    /// As one string with the picture in base64 it is well over WebView2's 2 MB limit.
    fn big_mail() -> (Vec<u8>, Vec<u8>) {
        let png = noisy_png(900, 600);
        assert!(png.len() > 1_500_000);
        let row = "<p class=MsoNormal><span style='font-size:11.0pt;font-family:\"Calibri\",sans-serif'>Synthetic reply text for the size test.</span></p>\r\n";
        let html = format!("<html><body>{}<img width=800 src=\"cid:image001.png@01DABCDE.12345670\"></body></html>", row.repeat(5_000));
        let b64 = base64::engine::general_purpose::STANDARD.encode(&png);
        let wrapped: Vec<&str> = b64.as_bytes().chunks(76).map(|c| std::str::from_utf8(c).unwrap()).collect();
        let raw = format!(
            "From: A <a@example.com>\r\nTo: B <b@example.com>\r\nSubject: Big inline picture\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/related; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}\r\n\
--b1\r\nContent-Type: image/png; name=\"image001.png\"\r\nContent-ID: <image001.png@01DABCDE.12345670>\r\n\
Content-Transfer-Encoding: base64\r\nContent-Disposition: inline; filename=\"image001.png\"\r\n\r\n{}\r\n--b1--\r\n",
            wrapped.join("\r\n")
        );
        (raw.into_bytes(), png)
    }

    #[cfg(any(windows, target_os = "linux"))]
    fn get(served: &Served, uri: &str) -> Reply {
        answer(served, &wry::http::Request::get(uri).body(Vec::new()).unwrap())
    }

    /// A user's blank Outlook reply (17 Nov 2026), synthetic: the page over 2 MB the old way now
    /// goes by address, whole, with its picture served beside it.
    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn page_over_2mb_with_big_inline_picture_is_served_by_address() {
        let (raw, png) = big_mail();
        let m = mail_parser::MessageParser::default().parse(&raw).unwrap();
        let html = m.body_html(0).unwrap().to_string();
        let inline = inline_parts(&m);
        assert_eq!(inline.len(), 1);
        assert_eq!(inline[0].bytes, png, "the picture comes out of the mail intact");
        let old_size = html.len() + base64::engine::general_purpose::STANDARD.encode(&png).len();
        assert!(old_size > 2 * 1024 * 1024, "the old one-string page would be {old_size} bytes");

        let page = prepare(&html, &inline, false, "");
        assert!(page.contains("src=\"/inline/0\"") && !page.contains("cid:"));
        let served = Served::new(7, &page, &inline);

        let r = get(&served, "mailcraft://localhost/message/7");
        assert_eq!(r.status(), 200);
        assert_eq!(r.body().as_ref(), page.as_bytes(), "the whole page, not cut at 2 MB");
        assert_eq!(r.headers()["Content-Type"], "text/html; charset=utf-8");
        let csp = r.headers()["Content-Security-Policy"].to_str().unwrap();
        assert!(page.starts_with(&format!("{CSP_META}{csp}\"")) && csp.contains("script-src 'nonce-") && csp.contains("img-src 'self' data:;"));
        assert_eq!(r.headers()["Referrer-Policy"], "no-referrer");

        let r = get(&served, "mailcraft://localhost/inline/0");
        assert_eq!(r.status(), 200);
        assert_eq!(r.body().as_ref(), png.as_slice());
        assert_eq!(r.headers()["Content-Type"], "image/png");

        // Only this message: no other page, no other part, no files, no other host or scheme.
        for uri in [
            "mailcraft://localhost/message/6",
            "mailcraft://localhost/message/8",
            "mailcraft://localhost/inline/1",
            "mailcraft://localhost/inline/-1",
            "mailcraft://localhost/inline/0x0",
            "mailcraft://localhost/",
            "mailcraft://localhost/../../Windows/win.ini",
            "mailcraft://localhost/C:/Windows/win.ini",
            "mailcraft://other/message/7",
            "http://mailcraft.localhost/message/7",
            "file://localhost/etc/passwd",
        ] {
            assert_eq!(get(&served, uri).status(), 404, "{uri}");
        }
        let post = wry::http::Request::post("mailcraft://localhost/message/7").body(Vec::new()).unwrap();
        assert_eq!(answer(&served, &post).status(), 404);
    }

    /// A page whose HTML alone is over 2 MB (no pictures at all) comes through whole.
    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn html_over_2mb_is_served_whole() {
        let html = format!("<p>{}</p>", "word ".repeat(600_000));
        let page = prepare(&html, &[], false, "");
        assert!(page.len() > 3_000_000);
        let r = get(&Served::new(1, &page, &[]), "mailcraft://localhost/message/1");
        assert_eq!((r.status().as_u16(), r.body().len()), (200, page.len()));
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn only_the_page_shown_counts_as_the_message() {
        assert!(page_url(3).ends_with("/message/3"));
        assert!(is_page(&page_url(3), 3));
        for url in ["http://mailcraft.localhost/message/3", "https://mailcraft.localhost/message/3", "mailcraft://localhost/message/3#sec2"] {
            assert!(is_page(url, 3), "{url}");
        }
        for url in [
            "http://mailcraft.localhost/message/2",
            "http://mailcraft.localhost/message/3/x",
            "http://mailcraft.localhost/inline/0",
            "http://mailcraft.localhost.evil.example/message/3",
            "http://evil.example/mailcraft.localhost/message/3",
            "about:blank",
            "data:text/html,hi",
            "https://example.com/",
            "",
        ] {
            assert!(!is_page(url, 3), "{url}");
        }
        // Before any message: the blank page 0, under the strict policy.
        let r = get(&Served::default(), "mailcraft://localhost/message/0");
        assert_eq!((r.status().as_u16(), r.body().len()), (200, 0));
        assert_eq!(r.headers()["Content-Security-Policy"], BLANK_POLICY);
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn mail_mime_types_only_go_into_headers_when_plain() {
        assert_eq!(safe_mime("image/png"), "image/png");
        assert_eq!(safe_mime("image/svg+xml"), "image/svg+xml");
        for junk in ["image/png\r\nX-Evil: 1", "image", "/png", "image/", "text/html; charset=x", "image/p ng", ""] {
            assert_eq!(safe_mime(junk), "application/octet-stream", "{junk:?}");
        }
        let served = Served::new(1, "", &[Inline { cid: "a".into(), mime: "image/png\r\nSet-Cookie: x=1".into(), bytes: vec![1] }]);
        let r = get(&served, "mailcraft://localhost/inline/0");
        assert_eq!(r.headers()["Content-Type"], "application/octet-stream");
        assert!(r.headers().get("Set-Cookie").is_none());
        assert_eq!(page_policy("<p>no policy</p>"), None);
    }

    /// The real thing, by hand (never on a user's PC: it opens a window): load a message into a
    /// browser view through the address and report what the engine made of it.
    /// `MAILCRAFT_TEST_EML=<file>` picks the mail (default: the synthetic big one). Prints only
    /// sizes and picture dimensions, never the mail's text.
    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    #[ignore = "opens a window with a browser view; run by hand on a build host"]
    fn live_view_shows_a_big_message() {
        use std::sync::{Arc, Mutex};
        use winit::application::ApplicationHandler;
        use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};

        let raw = match std::env::var("MAILCRAFT_TEST_EML") {
            Ok(p) => std::fs::read(p).unwrap(),
            Err(_) => big_mail().0,
        };
        let m = mail_parser::MessageParser::default().parse(&raw).unwrap();
        let html = m.body_html(0).unwrap().to_string();
        let inline = inline_parts(&m);
        let page = prepare(&html, &inline, false, "");
        let pictures: usize = inline.iter().map(|p| p.bytes.len()).sum();
        let old = html.len() + inline.iter().map(|p| p.bytes.len().div_ceil(3) * 4 + p.mime.len() + 13).sum::<usize>();
        println!(
            "mail {} bytes; html {}; {} inline parts, {pictures} bytes; old one-string page ~{old}; new page {}",
            raw.len(),
            html.len(),
            inline.len(),
            page.len()
        );

        struct App {
            page: String,
            inline: Vec<Inline>,
            window: Option<winit::window::Window>,
            view: Option<HtmlView>,
            report: Arc<Mutex<Option<String>>>,
            asked: std::time::Instant,
            start: std::time::Instant,
            done: Option<String>,
        }
        impl ApplicationHandler for App {
            fn resumed(&mut self, el: &ActiveEventLoop) {
                if self.window.is_some() {
                    return;
                }
                let attrs = winit::window::Window::default_attributes()
                    .with_title("AltMail view test")
                    .with_inner_size(winit::dpi::PhysicalSize::new(1000, 800));
                let w = el.create_window(attrs).unwrap();
                let mut v = HtmlView::new(&w, egui::Context::default()).unwrap();
                v.show(&self.page, &self.inline, 0.0, 0.0, 1000.0, 800.0);
                self.view = Some(v);
                self.window = Some(w);
            }
            fn window_event(&mut self, _: &ActiveEventLoop, _: winit::window::WindowId, _: winit::event::WindowEvent) {}
            fn about_to_wait(&mut self, el: &ActiveEventLoop) {
                el.set_control_flow(ControlFlow::Poll);
                pump();
                if let Some(r) = self.report.lock().unwrap().take() {
                    let v: serde_json::Value = serde_json::from_str(&r).unwrap_or_default();
                    // The engine hands back the script's JSON as a JSON string.
                    let v: serde_json::Value = v.as_str().and_then(|s| serde_json::from_str(s).ok()).unwrap_or(v);
                    let ok = v["href"].as_str().is_some_and(|h| is_page(h, 1))
                        && v["state"] == "complete"
                        && v["imgs"].as_array().is_some_and(|a| a.iter().all(|i| i[0] == true));
                    if ok {
                        self.done = Some(v.to_string());
                        el.exit();
                        return;
                    }
                }
                if self.start.elapsed().as_secs() > 60 {
                    self.done = Some("timed out".into());
                    el.exit();
                    return;
                }
                if self.asked.elapsed().as_millis() > 500
                    && let Some(v) = &self.view
                {
                    self.asked = std::time::Instant::now();
                    let sink = self.report.clone();
                    let js = "JSON.stringify({href: location.href, state: document.readyState, html: document.documentElement.outerHTML.length, \
                              text: document.body ? document.body.innerText.length : -1, \
                              imgs: Array.from(document.images).map(function (i) { return [i.complete, i.naturalWidth, i.naturalHeight, i.src.slice(0, 40)]; })})";
                    let _ = v.view.evaluate_script_with_callback(js, move |r| {
                        *sink.lock().unwrap() = Some(r);
                    });
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }

        let mut builder = EventLoop::builder();
        #[cfg(windows)]
        winit::platform::windows::EventLoopBuilderExtWindows::with_any_thread(&mut builder, true);
        #[cfg(target_os = "linux")]
        winit::platform::x11::EventLoopBuilderExtX11::with_any_thread(&mut builder, true);
        let el = builder.build().unwrap();
        let now = std::time::Instant::now();
        let mut app = App { page, inline, window: None, view: None, report: Arc::default(), asked: now, start: now, done: None };
        el.run_app(&mut app).unwrap();
        let done = app.done.unwrap_or_default();
        println!("view: {done}");
        let v: serde_json::Value = serde_json::from_str(&done).expect("the view never showed page 1 with every picture loaded");
        let imgs = v["imgs"].as_array().cloned().unwrap_or_default();
        let ours: Vec<_> = imgs.iter().filter(|i| i[3].as_str().is_some_and(|s| s.contains("/inline/"))).collect();
        assert!(v["text"].as_i64().unwrap_or(0) > 0, "the page has text");
        assert!(ours.iter().all(|i| i[1].as_i64().unwrap_or(0) > 0), "every inline picture decoded: {imgs:?}");
    }
}
