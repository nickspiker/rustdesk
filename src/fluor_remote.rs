//! Passless remote viewer on fluor — a third `InvokeUiSession` backend beside sciter and
//! flutter, used for fleet peers. fluor is a pure-Rust CPU compositor that works in TRUE
//! device pixels on every platform, so the sciter-on-retina scaling/coordinate mess (the
//! x=0 mouse, the 2x magnification) is designed out: the frame is blitted 1:1 and the cursor
//! maps by identity.
//!
//! RustDesk's Rust session machinery is reused untouched — we construct a `Session`, spawn
//! its `io_loop`, and this module only implements the UI trait (receive decoded frames,
//! render, and translate input back into `send_mouse`/`send_key`).

use std::sync::{Arc, Mutex};

use fluor::canvas::Canvas;
use fluor::event::{ElementState, Event as FEvent, Key, MouseButton, MouseScrollDelta, NamedKey};
use fluor::host::app::{run_app, Context, FluorApp};
use fluor::host::{EventResponse, WakeSender};
use fluor::paint::draw_image;
use fluor::pixel::Blend;
use fluor::{BlendMode, Coord};

use hbb_common::config::keys;
use hbb_common::{log, message_proto::*, rendezvous_proto::ConnType};
use scrap::ImageFormat;

use crate::ui_session_interface::{io_loop, InvokeUiSession, Session};

/// Cross-thread wake payload: the io_loop thread nudges the fluor UI thread.
/// (Real connection-drop teardown is a Phase-4 item; today the user closes the window.)
#[derive(Clone, Copy)]
pub enum Wake {
    Frame,
}

/// A decoded frame already converted to fluor's α+darkness packing, plus its dimensions.
#[derive(Default)]
struct FrameBuf {
    pixels: Vec<u32>,
    w: usize,
    h: usize,
    /// Bumped on every new frame so the renderer knows there's something fresh.
    gen: u64,
}

/// State shared between the io_loop-side handler (writer) and the fluor app (reader).
#[derive(Default)]
struct Shared {
    frame: Mutex<FrameBuf>,
    /// Set once the fluor host hands us the wake proxy (after app construction).
    proxy: Mutex<Option<Arc<dyn WakeSender<Wake>>>>,
    /// Remote cursor position (device px in the remote's space), for drawing our own pointer.
    cursor: Mutex<(i32, i32)>,
}

impl Shared {
    fn wake(&self, w: Wake) {
        if let Some(p) = self.proxy.lock().unwrap().as_ref() {
            p.send(w);
        }
    }
}

/// The `InvokeUiSession` implementor. Cheap to clone (just an Arc), which the session and the
/// io_loop both need. Almost every method is a no-op for a viewer — the ones that matter are
/// `on_rgba` (frame), `set_cursor_position`, and `close_success`.
#[derive(Clone, Default)]
pub struct FluorHandler {
    shared: Arc<Shared>,
}

impl InvokeUiSession for FluorHandler {
    fn on_rgba(&self, _display: usize, rgba: &mut scrap::ImageRgb) {
        let (w, h) = (rgba.w, rgba.h);
        if w == 0 || h == 0 || rgba.raw.len() < w * h * 4 {
            return;
        }
        // Source is a 32-bit RGBA (ARGB fmt on this build). fluor wants α + per-channel
        // darkness: keep α, invert the low 24 bits (255-x == !x per byte). If red/blue look
        // swapped on first run, the fmt is ABGR — flip here.
        let src = &rgba.raw;
        let n = w * h;
        let mut out = vec![0u32; n];
        let swap_rb = matches!(rgba.fmt(), ImageFormat::ABGR);
        for i in 0..n {
            let b0 = src[i * 4] as u32;
            let b1 = src[i * 4 + 1] as u32;
            let b2 = src[i * 4 + 2] as u32;
            let a = src[i * 4 + 3] as u32;
            // Interpret little-endian channel order; produce 0xAARRGGBB darkness.
            let (r, g, b) = if swap_rb { (b0, b1, b2) } else { (b2, b1, b0) };
            out[i] = (a << 24) | ((255 - r) << 16) | ((255 - g) << 8) | (255 - b);
        }
        let mut f = self.shared.frame.lock().unwrap();
        f.pixels = out;
        f.w = w;
        f.h = h;
        f.gen = f.gen.wrapping_add(1);
        drop(f);
        self.shared.wake(Wake::Frame);
    }

    fn set_cursor_position(&self, cp: CursorPosition) {
        *self.shared.cursor.lock().unwrap() = (cp.x, cp.y);
        self.shared.wake(Wake::Frame);
    }

    fn close_success(&self) {
        // Despite the name, this fires on the FIRST FRAME to dismiss the "connecting…"
        // dialog — it means CONNECTED, not closed. Do NOT tear down the window here.
        log::info!("fluor: first frame — connected");
        self.shared.wake(Wake::Frame);
    }

    fn msgbox(&self, msgtype: &str, title: &str, text: &str, _link: &str, _retry: bool) {
        log::info!("fluor msgbox [{msgtype}] {title}: {text}");
    }

    // ── everything below is not needed by a bare viewer (yet) ──
    fn set_cursor_data(&self, _cd: CursorData) {}
    fn set_cursor_id(&self, _id: String) {}
    fn set_display(&self, _x: i32, _y: i32, _w: i32, _h: i32, _cursor_embedded: bool, _scale: f64) {}
    fn switch_display(&self, _display: &hbb_common::message_proto::SwitchDisplay) {}
    fn set_peer_info(&self, _pi: &hbb_common::message_proto::PeerInfo) {}
    fn set_displays(&self, _displays: &Vec<hbb_common::message_proto::DisplayInfo>) {}
    fn set_platform_additions(&self, _data: &str) {}
    fn on_connected(&self, _conn_type: ConnType) {}
    fn update_privacy_mode(&self) {}
    fn set_permission(&self, _name: &str, _value: bool) {}
    fn update_quality_status(&self, _qs: crate::client::QualityStatus) {}
    fn set_connection_type(&self, _is_secured: bool, _direct: bool, _stream_type: &str) {}
    fn set_fingerprint(&self, _fingerprint: String) {}
    fn job_error(&self, _id: i32, _err: String, _file_num: i32) {}
    fn job_done(&self, _id: i32, _file_num: i32) {}
    fn clear_all_jobs(&self) {}
    fn new_message(&self, _msg: String) {}
    fn update_transfer_list(&self) {}
    fn load_last_job(&self, _cnt: i32, _job_json: &str, _auto_start: bool) {}
    fn update_folder_files(
        &self,
        _id: i32,
        _entries: &Vec<FileEntry>,
        _path: String,
        _is_local: bool,
        _only_count: bool,
    ) {
    }
    fn confirm_delete_files(&self, _id: i32, _i: i32, _name: String) {}
    fn override_file_confirm(
        &self,
        _id: i32,
        _file_num: i32,
        _to: String,
        _is_upload: bool,
        _is_identical: bool,
    ) {
    }
    fn update_block_input_state(&self, _on: bool) {}
    fn job_progress(&self, _id: i32, _file_num: i32, _speed: f64, _finished_size: f64) {}
    fn adapt_size(&self) {}
    fn cancel_msgbox(&self, _tag: &str) {}
    fn switch_back(&self, _id: &str) {}
    fn portable_service_running(&self, _running: bool) {}
    fn on_voice_call_started(&self) {}
    fn on_voice_call_closed(&self, _reason: &str) {}
    fn on_voice_call_waiting(&self) {}
    fn on_voice_call_incoming(&self) {}
    fn get_rgba(&self, _display: usize) -> *const u8 {
        std::ptr::null()
    }
    fn next_rgba(&self, _display: usize) {}
    fn set_multiple_windows_session(
        &self,
        _sessions: Vec<hbb_common::message_proto::WindowsSession>,
    ) {
    }
    fn set_current_display(&self, _disp_idx: i32) {}
    fn update_record_status(&self, _start: bool) {}
    fn printer_request(&self, _id: i32, _path: String) {}
    fn handle_screenshot_resp(&self, _sid: String, _msg: String) {}
    fn handle_terminal_response(&self, _response: hbb_common::message_proto::TerminalResponse) {}
}

// ── the fluor application ──

/// Mouse button masks matching RustDesk's `send_mouse` protocol (buttons << 3 | type).
const TYPE_MOVE: i32 = 0;
const TYPE_DOWN: i32 = 1;
const TYPE_UP: i32 = 2;
const TYPE_WHEEL: i32 = 3;
const BTN_LEFT: i32 = 1;
const BTN_RIGHT: i32 = 2;
const BTN_MIDDLE: i32 = 4;

/// Opaque dark-grey letterbox, α+darkness packed (darkness 0xC0 → visible 0x3F).
const BACKDROP: u32 = 0xFFC0_C0C0;

struct FluorViewer {
    session: Session<FluorHandler>,
    shared: Arc<Shared>,
    // opsin-style view transform: fractional so it rides resizes. zoom_rel * span = px scale.
    /// 1:1 by default (each remote pixel → one viewport pixel = crisp, opsin's model). Scroll
    /// pans; the frame is bigger than the window so we show a portion and pan to reach the rest.
    zoom: f32,
    /// Pan: remote-pixel coordinate shown at the window's top-left. Clamped to the frame.
    pan_x: f32,
    pan_y: f32,
    /// The exact (frame-left, frame-top, zoom) used in the last render, in viewport-pixel
    /// space — the mouse maps with this so it's ALWAYS consistent with what's drawn:
    /// remote = (cursor − frame_origin) / zoom.  At zoom=1 that's plain subtraction.
    view_fx: f32,
    view_fy: f32,
    // input bookkeeping
    buttons: i32, // currently-held button mask
    last_seen_gen: u64,
}

impl FluorViewer {
    /// Frame dimensions, or (0,0) if none yet.
    fn frame_dims(&self) -> (usize, usize) {
        let f = self.shared.frame.lock().unwrap();
        (f.w, f.h)
    }

    /// Where the frame's top-left sits in the window this frame (viewport px), given the
    /// current zoom + pan. Centered when the scaled frame is smaller than the window; panned
    /// (clamped so you can't scroll past the edges) when it's bigger.
    fn frame_origin(&self, vw: f32, vh: f32, fw: f32, fh: f32) -> (f32, f32) {
        let dst_w = fw * self.zoom;
        let dst_h = fh * self.zoom;
        let fx = if dst_w <= vw {
            (vw - dst_w) * 0.5
        } else {
            -self.pan_x.clamp(0.0, fw - vw / self.zoom) * self.zoom
        };
        let fy = if dst_h <= vh {
            (vh - dst_h) * 0.5
        } else {
            -self.pan_y.clamp(0.0, fh - vh / self.zoom) * self.zoom
        };
        (fx, fy)
    }

    /// Map a cursor position (viewport px) to a remote-px coordinate using the EXACT transform
    /// the last render drew with — pure `(cursor − frame_origin) / zoom`. Clamped to the frame.
    fn to_remote(&self, x: Coord, y: Coord) -> Option<(i32, i32)> {
        let (fw, fh) = self.frame_dims();
        if fw == 0 || self.zoom <= 0.0 {
            return None;
        }
        let rx = ((x - self.view_fx) / self.zoom).floor() as i32;
        let ry = ((y - self.view_fy) / self.zoom).floor() as i32;
        if rx < 0 || ry < 0 || rx >= fw as i32 || ry >= fh as i32 {
            return None;
        }
        Some((rx, ry))
    }

    fn send_move(&self, x: Coord, y: Coord) {
        if let Some((rx, ry)) = self.to_remote(x, y) {
            self.session
                .send_mouse((self.buttons << 3) | TYPE_MOVE, rx, ry, false, false, false, false);
        }
    }
}

impl FluorApp for FluorViewer {
    type UserEvent = Wake;

    fn set_event_proxy(&mut self, proxy: Arc<dyn WakeSender<Self::UserEvent>>) {
        *self.shared.proxy.lock().unwrap() = Some(proxy);
    }

    fn init(&mut self, _ctx: &mut Context) {}

    fn on_resize(&mut self, _w: u32, _h: u32, _ctx: &mut Context) {}

    fn on_user_event(&mut self, event: Self::UserEvent, ctx: &mut Context) -> EventResponse {
        match event {
            Wake::Frame => ctx.window.request_redraw(),
        }
        EventResponse::Pass
    }

    fn on_event(&mut self, event: &FEvent, ctx: &mut Context) -> EventResponse {
        match event {
            FEvent::CloseRequested => return EventResponse::Close,
            FEvent::CursorMoved { .. } => {
                self.send_move(ctx.cursor_x, ctx.cursor_y);
            }
            FEvent::MouseInput { state, button } => {
                let (cx, cy) = (ctx.cursor_x, ctx.cursor_y);
                let btn = match button {
                    MouseButton::Left => BTN_LEFT,
                    MouseButton::Right => BTN_RIGHT,
                    MouseButton::Middle => BTN_MIDDLE,
                    _ => 0,
                };
                if btn == 0 {
                    return EventResponse::Pass;
                }
                let pressed = matches!(state, ElementState::Pressed);
                let ty = if pressed { TYPE_DOWN } else { TYPE_UP };
                if pressed {
                    self.buttons |= btn;
                } else {
                    self.buttons &= !btn;
                }
                if let Some((rx, ry)) = self.to_remote(cx, cy) {
                    self.session
                        .send_mouse((btn << 3) | ty, rx, ry, false, false, false, false);
                }
            }
            FEvent::MouseWheel { delta } => {
                // Scroll pans the 1:1 view (the frame is bigger than the window). Shift isn't
                // tracked yet, so vertical scroll pans vertically; that's enough to reach the
                // whole remote height, and the remote-cursor auto-nudge covers width.
                let (_dx, dy) = match delta {
                    MouseScrollDelta::Lines(x, y) => (*x * 40.0, *y * 40.0),
                    MouseScrollDelta::Pixels(x, y) => (*x, *y),
                };
                self.pan_y -= dy;
                let (fw, fh) = self.frame_dims();
                let vh = ctx.viewport.height_px as f32;
                if fh as f32 > vh / self.zoom {
                    self.pan_y = self.pan_y.clamp(0.0, fh as f32 - vh / self.zoom);
                }
                let _ = fw;
                ctx.window.request_redraw();
            }
            FEvent::KeyboardInput { event } => {
                let down = matches!(event.state, ElementState::Pressed);
                self.send_key(ctx, &event.logical_key, down, event.text.as_deref());
            }
            _ => {}
        }
        EventResponse::Pass
    }

    fn render(&mut self, target: &mut [u32], ctx: &mut Context) {
        let bw = ctx.viewport.width_px as usize;
        let bh = ctx.viewport.height_px as usize;
        let vw = bw as f32;
        let vh = bh as f32;
        // Transparent first — draw_image composes UNDER existing content, so an opaque pre-fill
        // would hide the video (that was the grey box). Backdrop goes under at the END.
        for px in target.iter_mut() {
            *px = 0;
        }
        let f = self.shared.frame.lock().unwrap();
        let (fw, fh) = (f.w, f.h);
        if fw == 0 || fh == 0 || f.pixels.len() < fw * fh {
            drop(f);
            for px in target.iter_mut() {
                *px = BACKDROP;
            }
            return;
        }
        // 1:1 by default (zoom=1): each remote pixel → one viewport pixel, crisp. Frame is
        // drawn at (fx, fy); draw_image clips the part that's off-window. Store the exact
        // origin so the mouse maps with the identical transform.
        let (fx, fy) = self.frame_origin(vw, vh, fw as f32, fh as f32);
        self.view_fx = fx;
        self.view_fy = fy;
        if self.last_seen_gen != f.gen {
            self.last_seen_gen = f.gen;
            log::info!(
                "fluor: 1:1 blit frame {fw}x{fh} zoom={:.2} origin=({:.0},{:.0}) viewport {bw}x{bh}",
                self.zoom, fx, fy
            );
        }
        let dst_w = fw as f32 * self.zoom;
        let dst_h = fh as f32 * self.zoom;
        let cx = fx + dst_w * 0.5;
        let cy = fy + dst_h * 0.5;
        {
            let mut canvas = Canvas::new(target, bw, bh, ctx.damage);
            draw_image(&mut canvas, &f.pixels, fw, fh, cx, cy, dst_w, dst_h, None);
        }
        drop(f);
        // Backdrop UNDER everything: fills the letterbox and makes the window opaque, while
        // the (opaque) video pixels ride through unchanged.
        for px in target.iter_mut() {
            *px = px.under(BACKDROP, BlendMode::Normal);
        }
    }

    fn cursor_for(
        &self,
        _x: Coord,
        _y: Coord,
        _ctx: &Context,
    ) -> fluor::event::CursorIcon {
        fluor::event::CursorIcon::Default
    }
}

impl FluorViewer {
    fn send_key(&self, _ctx: &Context, key: &Key, down: bool, text: Option<&str>) {
        // RustDesk's `chr` field is a VIRTUAL KEYCODE, not a Unicode codepoint — stuffing a
        // char into it scrambles every key (what "keymap completely fucked" was). Two correct
        // paths instead: named keys go through set_control_key (down+up); printable text is
        // TYPED verbatim via a Legacy `seq` on the down edge — layout-agnostic, so Dvorak (or
        // anything) on either side produces exactly the character the sender saw.
        let control = match key {
            Key::Named(n) => match n {
                NamedKey::Enter => Some(ControlKey::Return),
                NamedKey::Backspace => Some(ControlKey::Backspace),
                NamedKey::Tab => Some(ControlKey::Tab),
                NamedKey::Escape => Some(ControlKey::Escape),
                NamedKey::Delete => Some(ControlKey::Delete),
                NamedKey::ArrowLeft => Some(ControlKey::LeftArrow),
                NamedKey::ArrowRight => Some(ControlKey::RightArrow),
                NamedKey::ArrowUp => Some(ControlKey::UpArrow),
                NamedKey::ArrowDown => Some(ControlKey::DownArrow),
                NamedKey::Home => Some(ControlKey::Home),
                NamedKey::End => Some(ControlKey::End),
                NamedKey::PageUp => Some(ControlKey::PageUp),
                NamedKey::PageDown => Some(ControlKey::PageDown),
                _ => None,
            },
            _ => None,
        };
        if let Some(ck) = control {
            let mut evt = KeyEvent::new();
            evt.mode = KeyboardMode::Legacy.into();
            evt.down = down;
            evt.set_control_key(ck);
            self.session.send_key_event(&evt);
            return;
        }
        // Printable character (incl. NamedKey::Space via its text " "): type on the down edge.
        if down {
            let t = text.unwrap_or("");
            let is_printable = t.chars().next().map(|c| !c.is_control()).unwrap_or(false);
            if is_printable {
                let mut evt = KeyEvent::new();
                evt.mode = KeyboardMode::Legacy.into();
                evt.press = true;
                evt.set_seq(t.to_string());
                self.session.send_key_event(&evt);
            }
        }
    }
}

/// Launch the fluor remote viewer for a fleet peer. Blocks on the fluor event loop; the
/// io_loop runs on a spawned thread, exactly as the sciter/flutter paths spawn theirs.
pub fn run(cmd: String, id: String, password: String, args: Vec<String>) {
    let _ = keys::OPTION_VIEW_STYLE; // keep the keys import meaningful for future settings
    let force_relay = args.contains(&"--relay".to_string());
    let session: Session<FluorHandler> = Session {
        password: password.clone(),
        args,
        server_keyboard_enabled: Arc::new(std::sync::RwLock::new(true)),
        server_file_transfer_enabled: Arc::new(std::sync::RwLock::new(true)),
        server_clipboard_enabled: Arc::new(std::sync::RwLock::new(true)),
        reconnect_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        ..Default::default()
    };
    let conn_type = if cmd == "--file-transfer" {
        ConnType::FILE_TRANSFER
    } else if cmd == "--view-camera" {
        ConnType::VIEW_CAMERA
    } else if cmd == "--port-forward" {
        ConnType::PORT_FORWARD
    } else if cmd == "--rdp" {
        ConnType::RDP
    } else {
        ConnType::DEFAULT_CONN
    };
    session
        .lc
        .write()
        .unwrap()
        .initialize(id, conn_type, None, force_relay, None, None, None);

    let shared = session.ui_handler.shared.clone();

    let io = session.clone();
    let round = io.connection_round_state.lock().unwrap().new_round();
    std::thread::spawn(move || {
        io_loop(io, round);
    });

    let app = FluorViewer {
        session,
        shared,
        zoom: 1.0,
        pan_x: 0.0,
        pan_y: 0.0,
        view_fx: 0.0,
        view_fy: 0.0,
        buttons: 0,
        last_seen_gen: 0,
    };
    if let Err(e) = run_app(app) {
        log::error!("fluor viewer event loop: {e:?}");
    }
}
