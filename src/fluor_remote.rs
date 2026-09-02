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
use std::time::{Duration, Instant};

use fluor::canvas::Canvas;
use fluor::event::{
    ElementState, Event as FEvent, Key, ModifiersState, MouseButton, MouseScrollDelta, NamedKey,
};
use fluor::host::app::{run_app, Context, FluorApp};
use fluor::host::{EventResponse, WakeSender};
use fluor::paint::draw_image;
use fluor::pixel::Blend;
use fluor::text::TextStyle;
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
    /// The current display's origin (x, y) in the remote's virtual-desktop space. Added to
    /// mapped coords so a non-primary monitor (origin != 0,0) targets the right pixels.
    display_origin: Mutex<(i32, i32)>,
    /// Which host display index we're viewing — the target of resolution-follow.
    display_idx: Mutex<i32>,
    /// The peer's OS ("Linux"/"Windows"/"Mac"), from PeerInfo. Map-mode keys carry a
    /// peer-platform keycode, converted from our canonical Windows scancode.
    peer_platform: Mutex<String>,
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
    fn set_display(&self, x: i32, y: i32, _w: i32, _h: i32, _cursor_embedded: bool, _scale: f64) {
        *self.shared.display_origin.lock().unwrap() = (x, y);
    }
    fn switch_display(&self, display: &hbb_common::message_proto::SwitchDisplay) {
        *self.shared.display_idx.lock().unwrap() = display.display;
        *self.shared.display_origin.lock().unwrap() = (display.x, display.y);
    }
    fn set_peer_info(&self, pi: &hbb_common::message_proto::PeerInfo) {
        *self.shared.display_idx.lock().unwrap() = pi.current_display;
        *self.shared.peer_platform.lock().unwrap() = pi.platform.clone();
    }
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

/// Quiet time after the last window-size change before we ask the host to follow — long enough
/// that dragging the window doesn't mint an xrandr mode per pixel, short enough to feel live.
const FOLLOW_DEBOUNCE: Duration = Duration::from_millis(300);

/// Visible-RGB → fluor's α+darkness packing (same as on_rgba / opsin's `argb`). Const so HUD
/// colours are compile-time.
const fn argb(r: u8, g: u8, b: u8, a: u8) -> u32 {
    ((a as u32) << 24) | (((255 - r) as u32) << 16) | (((255 - g) as u32) << 8) | ((255 - b) as u32)
}
/// Bright HUD colours (α+darkness). Green for the mouse line, amber for keys, black shadow.
const HUD_GREEN: u32 = argb(0x30, 0xFF, 0x50, 0xFF);
const HUD_AMBER: u32 = argb(0xFF, 0xC0, 0x20, 0xFF);
const HUD_SHADOW: u32 = argb(0x00, 0x00, 0x00, 0xFF);

struct FluorViewer {
    session: Session<FluorHandler>,
    shared: Arc<Shared>,
    /// Pan: the remote-pixel coordinate shown at the window's top-left. Scroll to move it.
    /// The frame is ALWAYS drawn 1:1 (no scaling, ever); when it's bigger than the window you
    /// pan to reach the rest. Clamped so you can't scroll past the edges.
    pan_x: f32,
    pan_y: f32,
    // input bookkeeping
    buttons: i32, // currently-held button mask
    last_seen_gen: u64,
    // ── resolution-follow: ask the host to render at exactly this window's backing size, so
    //    the frame fills the window 1:1 (no scaling) and the mouse maps by identity ──
    follow_target: (i32, i32), // most recent window backing size seen
    follow_at: Option<Instant>, // when the debounce elapses and we send the follow
    last_follow: (i32, i32),   // last size actually requested (avoids resend spam)
    /// Cursor derived from the last raw CursorMoved (raw − window_origin, pass-0 px). Used by
    /// MouseInput (which carries no position) and as the send_move source.
    last_cursor: (Coord, Coord),
    /// Last time HUD telemetry was chatted to the host (throttle ~2s). The host logs HUD|
    /// lines, giving us the viewer's runtime numbers on the HOST's disk — readable even when
    /// the viewer machine is unreachable.
    last_telemetry: Option<std::time::Instant>,
    // ── on-screen diagnostic HUD (Ctrl+Alt+H toggles) ──
    hud: bool,
    dbg_raw: (Coord, Coord),     // raw winit event position (untransformed)
    dbg_worg: (i32, i32),        // ctx.window_origin at that event
    dbg_cur: (Coord, Coord),     // raw − window_origin = what we map with
    dbg_ctx_cur: (Coord, Coord), // fluor's ctx.cursor_x/y (for comparison — mac reads 0)
    dbg_vp: (u32, u32),          // ctx.viewport.width_px/height_px
    dbg_org: (f32, f32),         // frame origin used to map
    dbg_rem: (i32, i32),         // resulting remote px sent (−1,−1 = off-frame)
    dbg_key: String,             // last keypress: logical key + text + path taken
}

impl FluorViewer {
    /// Frame dimensions, or (0,0) if none yet.
    fn frame_dims(&self) -> (usize, usize) {
        let f = self.shared.frame.lock().unwrap();
        (f.w, f.h)
    }

    /// The frame's top-left corner in the window, in window pixels. ALWAYS 1:1 — scale is a
    /// constant 1.0, NEVER fit/zoom. Centered: letterbox when the frame is smaller than the
    /// window, center-crop when larger (only transiently, while the host is still catching up
    /// to a resolution-follow — steady state is frame == viewport, origin 0,0). Returns
    /// `(ox, oy, 1.0)`; the ONE source of truth — render draws the frame here, the mouse
    /// inverts it by plain subtraction.
    fn view_rect(&self, vw: f32, vh: f32, fw: f32, fh: f32) -> (f32, f32, f32) {
        ((vw - fw) * 0.5, (vh - fh) * 0.5, 1.0)
    }

    /// Map a window cursor position to a remote pixel: subtract the frame's origin, clamp to
    /// the frame. With scale pinned at 1.0 this is pure subtraction — no transform left to
    /// get wrong.
    fn to_remote(&self, ctx: &Context, x: Coord, y: Coord) -> Option<(i32, i32)> {
        let (fw, fh) = self.frame_dims();
        if fw == 0 {
            return None;
        }
        let vw = ctx.viewport.width_px as f32;
        let vh = ctx.viewport.height_px as f32;
        let (ox, oy, scale) = self.view_rect(vw, vh, fw as f32, fh as f32);
        let rx = ((x - ox) / scale) as i32;
        let ry = ((y - oy) / scale) as i32;
        Some((rx.clamp(0, fw as i32 - 1), ry.clamp(0, fh as i32 - 1)))
    }

    fn send_move(&self, ctx: &Context, x: Coord, y: Coord) {
        if let Some((rx, ry)) = self.to_remote(ctx, x, y) {
            self.session
                .send_mouse((self.buttons << 3) | TYPE_MOVE, rx, ry, false, false, false, false);
        }
    }

    /// Resolution-follow: ask the host to render at exactly this window's backing-pixel size.
    /// When it does, frame == viewport, so the video fills the window 1:1 (crisp, no scaling)
    /// and `to_remote` becomes identity — the whole "hard-left" transform class disappears.
    /// Debounced so dragging the window doesn't mint an xrandr mode per pixel. Returns `true`
    /// while a follow is still pending (caller keeps redrawing so the flush isn't stranded on a
    /// static screen with no input).
    fn maybe_follow(&mut self, ctx: &Context) -> bool {
        let target = (ctx.viewport.width_px as i32, ctx.viewport.height_px as i32);
        if target.0 <= 0 || target.1 <= 0 {
            return false;
        }
        if target != self.follow_target {
            // Size changed — (re)start the debounce; don't send mid-drag.
            self.follow_target = target;
            self.follow_at = Some(Instant::now() + FOLLOW_DEBOUNCE);
            return true;
        }
        if target != self.last_follow {
            let due = self.follow_at.map_or(true, |t| Instant::now() >= t);
            if due {
                let idx = *self.shared.display_idx.lock().unwrap();
                log::info!(
                    "fgtw-diag: follow SEND change_resolution display={} {}x{}",
                    idx, target.0, target.1
                );
                self.session.change_resolution(idx, target.0, target.1);
                self.last_follow = target;
                self.follow_at = None;
                return false;
            }
            return true; // waiting for the debounce
        }
        false
    }
}

impl FluorApp for FluorViewer {
    type UserEvent = Wake;

    fn set_event_proxy(&mut self, proxy: Arc<dyn WakeSender<Self::UserEvent>>) {
        *self.shared.proxy.lock().unwrap() = Some(proxy);
    }

    fn init(&mut self, _ctx: &mut Context) {}

    /// Open at the FULL monitor, not fluor's default half. This is the visible-window size; the
    /// default `monitor/2` was the "quarter area / mostly wallpaper" the user kept reporting.
    fn initial_size(&self, monitor: (u32, u32)) -> (u32, u32) {
        monitor
    }

    fn on_resize(&mut self, _w: u32, _h: u32, ctx: &mut Context) {
        // Window resized → the host should follow to the new backing size.
        if self.maybe_follow(ctx) {
            ctx.window.request_redraw();
        }
    }

    fn on_user_event(&mut self, event: Self::UserEvent, ctx: &mut Context) -> EventResponse {
        match event {
            Wake::Frame => ctx.window.request_redraw(),
        }
        EventResponse::Pass
    }

    fn on_event(&mut self, event: &FEvent, ctx: &mut Context) -> EventResponse {
        // Keep the host sized to this window (debounced inside). Cheap; runs on every event.
        if self.maybe_follow(ctx) {
            ctx.window.request_redraw();
        }
        match event {
            FEvent::CloseRequested => return EventResponse::Close,
            FEvent::CursorMoved { x, y } => {
                // Map from the RAW winit position minus the window's origin — both in pass-0
                // pixel space — bypassing fluor's internal cursor bookkeeping entirely. On the
                // Mac (fullscreen-compositor host) ctx.cursor_x arrives ≈0 with garbage y; the
                // raw event position is the one value winit reports directly from the OS.
                let wo = ctx.window_origin;
                let (cx, cy) = (*x - wo.0 as Coord, *y - wo.1 as Coord);
                self.last_cursor = (cx, cy);
                // Capture the exact runtime values for the on-screen HUD — this is the ground
                // truth we could never get off the Mac's logs.
                let (fw, fh) = self.frame_dims();
                let (ox, oy, _scale) = self.view_rect(
                    ctx.viewport.width_px as f32,
                    ctx.viewport.height_px as f32,
                    fw as f32,
                    fh as f32,
                );
                self.dbg_raw = (*x, *y);
                self.dbg_worg = wo;
                self.dbg_cur = (cx, cy);
                self.dbg_ctx_cur = (ctx.cursor_x, ctx.cursor_y);
                self.dbg_vp = (ctx.viewport.width_px, ctx.viewport.height_px);
                self.dbg_org = (ox, oy);
                self.dbg_rem = self.to_remote(ctx, cx, cy).unwrap_or((-1, -1));
                self.send_move(ctx, cx, cy);
                if self.hud {
                    ctx.window.request_redraw();
                }
            }
            FEvent::MouseInput { state, button } => {
                let (cx, cy) = self.last_cursor;
                let btn = match button {
                    MouseButton::Left => BTN_LEFT,
                    MouseButton::Right => BTN_RIGHT,
                    MouseButton::Middle => BTN_MIDDLE,
                    _ => 0,
                };
                if btn == 0 {
                    return EventResponse::Pass;
                }
                // Send the REAL coordinate on down/up — NOT 0,0. The old "host reuses the last
                // MOVE position" assumption was false for this host: it took the 0,0 literally
                // and every click landed at the top-left. Position with a MOVE, then click at
                // the SAME coordinate.
                let Some((rx, ry)) = self.to_remote(ctx, cx, cy) else {
                    return EventResponse::Pass; // click outside the frame
                };
                self.send_move(ctx, cx, cy);
                let pressed = matches!(state, ElementState::Pressed);
                let ty = if pressed { TYPE_DOWN } else { TYPE_UP };
                if pressed {
                    self.buttons |= btn;
                } else {
                    self.buttons &= !btn;
                }
                self.session
                    .send_mouse((btn << 3) | ty, rx, ry, false, false, false, false);
            }
            FEvent::MouseWheel { delta } => {
                // Scroll pans the 1:1 view when the frame is bigger than the window.
                let (_dx, dy) = match delta {
                    MouseScrollDelta::Lines(x, y) => (*x * 40.0, *y * 40.0),
                    MouseScrollDelta::Pixels(x, y) => (*x, *y),
                };
                self.pan_y -= dy;
                let (_fw, fh) = self.frame_dims();
                let vh = ctx.viewport.height_px as f32;
                if fh as f32 > vh {
                    self.pan_y = self.pan_y.clamp(0.0, fh as f32 - vh);
                }
                ctx.window.request_redraw();
            }
            FEvent::KeyboardInput { event } => {
                let down = matches!(event.state, ElementState::Pressed);
                // Local hotkeys FIRST (Ctrl+Alt+… or Cmd+Alt+…) — intercepted, never sent to the
                // remote. Enter=fullscreen toggle, H=HUD.
                let m = ctx.modifiers;
                let hotkey = (m.ctrl || m.meta) && m.alt;
                if hotkey && down {
                    match &event.logical_key {
                        Key::Named(NamedKey::Enter) => return EventResponse::ToggleMaximized,
                        Key::Character(c) if c.eq_ignore_ascii_case("h") => {
                            self.hud = !self.hud;
                            ctx.window.request_redraw();
                            return EventResponse::Handled;
                        }
                        _ => {}
                    }
                }
                // CHARACTER (keysym) delivery, NOT physical-keycode passthrough. We send the
                // character the sender's layout produced; the host types it as a literal Unicode
                // keysym bound to a spare keycode (libxdo "U{:X}"), which is layout-INDEPENDENT on
                // both ends. Map mode was abandoned: it injected a raw keycode that the host's
                // per-device XTEST layout re-interpreted — and that layout comes up US or Dvorak
                // nondeterministically across relaunches, so the same build mangled ("the"->"kjd")
                // on one connect and not the next. Keysym delivery honors exactly what you typed,
                // Dvorak↔Dvorak or any mix, every time. Named/control keys route via control_key.
                // Forward the live modifier state so Shift+Enter, Ctrl+arrows, Alt+…, Cmd+… reach
                // the host (the Legacy path's sync_modifiers presses/releases these to match).
                self.send_key(ctx, &event.logical_key, down, event.text.as_deref(), m);
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
        // Drive resolution-follow from render too, so the initial follow fires even if the user
        // never moves the mouse (keep ticking until the debounce flushes, then stop).
        if self.maybe_follow(ctx) {
            ctx.window.request_redraw();
        }
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
        // The frame drawn 1:1 at its centered origin — same rect the mouse inverts, so draw
        // and input can't disagree. Steady state (after host follow) is frame == viewport.
        let (ox, oy, scale) = self.view_rect(vw, vh, fw as f32, fh as f32);
        let dw = fw as f32 * scale;
        let dh = fh as f32 * scale;
        if self.last_seen_gen != f.gen {
            self.last_seen_gen = f.gen;
            log::info!(
                "fluor: blit frame {fw}x{fh} 1:1 org=({ox:.0},{oy:.0}) viewport {bw}x{bh}"
            );
        }
        let cx = ox + dw * 0.5;
        let cy = oy + dh * 0.5;
        {
            let mut canvas = Canvas::new(target, bw, bh, ctx.damage);
            draw_image(&mut canvas, &f.pixels, fw, fh, cx, cy, dw, dh, None);
        }
        drop(f);
        // Backdrop UNDER everything: fills the letterbox and makes the window opaque, while
        // the (opaque) video pixels ride through unchanged.
        for px in target.iter_mut() {
            *px = px.under(BACKDROP, BlendMode::Normal);
        }
        // ── On-screen diagnostic HUD (Ctrl+Alt+H). Drawn last so it sits over everything. ──
        if self.hud {
            let line1 = format!(
                "raw={:.0},{:.0}  worg={},{}  cur={:.0},{:.0}  fluorcur={:.0},{:.0}",
                self.dbg_raw.0, self.dbg_raw.1, self.dbg_worg.0, self.dbg_worg.1,
                self.dbg_cur.0, self.dbg_cur.1, self.dbg_ctx_cur.0, self.dbg_ctx_cur.1
            );
            let line2 = format!(
                "vp={}x{}  frame={}x{}  org={:.0},{:.0}  ->remote={},{}   (1:1, subtract only)",
                self.dbg_vp.0, self.dbg_vp.1, fw, fh,
                self.dbg_org.0, self.dbg_org.1, self.dbg_rem.0, self.dbg_rem.1
            );
            let line3 = format!("key: {}", self.dbg_key);
            let line4 = "Ctrl+Alt: Enter=fullscreen  H=hud";
            let size = (bh as f32 * 0.028).clamp(16.0, 40.0);
            let x = size * 0.5;
            let mut y = size * 0.9;
            let mut canvas = Canvas::new(target, bw, bh, ctx.damage);
            for (i, s) in [line1.as_str(), line2.as_str(), line3.as_str(), line4].into_iter().enumerate() {
                let colour = if i == 2 { HUD_AMBER } else { HUD_GREEN };
                // 1px shadow for legibility over bright video, then the text.
                ctx.text.draw_text_left(&mut canvas, s, x + 1.5, y + 1.5, &TextStyle::new(size, HUD_SHADOW), None, None);
                ctx.text.draw_text_left(&mut canvas, s, x, y, &TextStyle::new(size, colour), None, None);
                y += size * 1.25;
            }
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
    /// The held modifiers as RustDesk `ControlKey`s, for `KeyEvent::modifiers`. The host's Legacy
    /// `sync_modifiers` presses/releases these around the key so combos (Shift+Enter, Ctrl+←,
    /// Alt+…, Cmd/Super+…) actually land instead of arriving as the bare key.
    fn mod_keys(m: ModifiersState) -> Vec<hbb_common::protobuf::EnumOrUnknown<ControlKey>> {
        let mut v = Vec::new();
        if m.shift {
            v.push(ControlKey::Shift.into());
        }
        if m.ctrl {
            v.push(ControlKey::Control.into());
        }
        if m.alt {
            v.push(ControlKey::Alt.into());
        }
        if m.meta {
            v.push(ControlKey::Meta.into());
        }
        v
    }

    fn send_key(&self, _ctx: &Context, key: &Key, down: bool, text: Option<&str>, mods: ModifiersState) {
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
            evt.modifiers = Self::mod_keys(mods);
            evt.set_control_key(ck);
            self.session.send_key_event(&evt);
            return;
        }
        // Printable character (incl. NamedKey::Space via its text " "): type on the down edge.
        // Send each codepoint as Unicode (NOT Seq): the host types it as a direct keysym,
        // layout-independent. Seq went through xdo_enter_text's physical-key lookup, which a
        // Dvorak host re-translated ("the" -> "kjd"). `text` already holds the layout-resolved
        // character fluor produced, so this is exactly what the user pressed.
        if down {
            let t = text.unwrap_or("");
            for c in t.chars() {
                if c.is_control() {
                    continue;
                }
                let mut evt = KeyEvent::new();
                evt.mode = KeyboardMode::Legacy.into();
                evt.press = true;
                evt.modifiers = Self::mod_keys(mods);
                evt.set_unicode(c as u32);
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
        pan_x: 0.0,
        pan_y: 0.0,
        buttons: 0,
        last_seen_gen: 0,
        follow_target: (0, 0),
        follow_at: None,
        last_follow: (0, 0),
        last_cursor: (0.0, 0.0),
        last_telemetry: None,
        hud: false, // off by default; Ctrl+Alt+H toggles the on-screen diagnostic overlay
        dbg_raw: (0.0, 0.0),
        dbg_worg: (0, 0),
        dbg_cur: (0.0, 0.0),
        dbg_ctx_cur: (0.0, 0.0),
        dbg_vp: (0, 0),
        dbg_org: (0.0, 0.0),
        dbg_rem: (0, 0),
        dbg_key: String::new(),
    };
    if let Err(e) = run_app(app) {
        log::error!("fluor viewer event loop: {e:?}");
    }
}
