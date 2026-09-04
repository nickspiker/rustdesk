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
use fluor::host::{EventResponse, MenuItem, WakeSender};
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
    /// How many displays the host has — for wrap-around host-monitor switching (Ctrl+Alt+←/→).
    /// Filled from PeerInfo/set_displays; 0 until connected (switch is a no-op until then).
    display_count: Mutex<usize>,
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
        *self.shared.display_count.lock().unwrap() = pi.displays.len();
    }
    fn set_displays(&self, displays: &Vec<hbb_common::message_proto::DisplayInfo>) {
        *self.shared.display_count.lock().unwrap() = displays.len();
    }
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

/// Native-menu item ids (echoed back as `FEvent::MenuItem`). Our namespace; kept stable.
const MENU_FULLSCREEN: u32 = 1;
const MENU_HUD: u32 = 2;
const MENU_HOST_NEXT: u32 = 3;
const MENU_HOST_PREV: u32 = 4;
const MENU_LOCAL_NEXT: u32 = 5;
const MENU_LOCAL_PREV: u32 = 6;

/// Trackpad `Pixels` scroll → "lines" divisor. A swipe is hundreds of px; this + accumulation
/// keeps scroll speed sane (bigger = slower). Wheel `Lines` bypass this (already ±1/notch).
const SCROLL_PX_PER_LINE: f32 = 120.0;

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
/// If the host's frame still hasn't become our window size this long after a follow request,
/// re-send it. Makes the follow self-healing against a dropped/ignored request (host restart,
/// reconnect blip) instead of the old fire-once-and-hope that left the crop stuck forever.
const FOLLOW_RETRY: Duration = Duration::from_millis(1200);
/// Retries per target before we stop asking. Each request restarts the host's capturer, so an unreachable size must not be retried forever.
const FOLLOW_MAX_TRIES: u32 = 5;

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
    /// Scroll accumulators: sub-line wheel/trackpad deltas pile up here and we forward whole
    /// lines as they cross ±1, keeping the remainder. No forced ±1-per-event, so fine-grained
    /// trackpad `Pixels` scroll proportionally instead of flooding the host with a line per micro-event.
    scroll_acc_x: f32,
    scroll_acc_y: f32,
    // input bookkeeping
    buttons: i32, // currently-held button mask
    last_seen_gen: u64,
    // ── resolution-follow: ask the host to render at exactly this window's backing size, so
    //    the frame fills the window 1:1 (no scaling) and the mouse maps by identity ──
    /// Set until the first render starts the io_loop with our real viewport size.
    io_pending: Option<Session<FluorHandler>>,
    follow_target: (i32, i32), // most recent window backing size seen
    follow_at: Option<Instant>, // when the debounce elapses and we send the follow
    follow_tries: u32,          // retries spent on the CURRENT target (reset when the target moves)
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
        // DONE when the host's frame is already exactly our window — the follow converged.
        let (fw, fh) = self.frame_dims();
        if (fw as i32, fh as i32) == target {
            self.follow_at = None;
            self.follow_target = target;
            self.follow_tries = 0;
            return false;
        }
        // Window size changed — (re)start the debounce so dragging doesn't spam requests.
        if target != self.follow_target {
            self.follow_target = target;
            self.follow_tries = 0;
            self.follow_at = Some(Instant::now() + FOLLOW_DEBOUNCE);
            return true;
        }
        // Debounce elapsed and the frame still isn't our size → (re)send, then re-arm a RETRY.
        // Self-healing: keep asking until the frame actually becomes `target`. The old code sent
        // ONCE and marked success — so a single dropped request (host restarting mid-send, a
        // reconnect blip) left the crop forever. Now a lost request just retries next tick.
        // Give up after FOLLOW_MAX_TRIES on one target. Retrying forever is worse than not
        // following: every request restarts the host's capturer, so a host that cannot reach
        // this size gets thrashed into sending nothing at all (the black screen). Stopping
        // leaves the last good frame drawn 1:1 and centred — small, but honest and alive.
        if self.follow_tries >= FOLLOW_MAX_TRIES {
            return false;
        }
        let due = self.follow_at.map_or(true, |t| Instant::now() >= t);
        if due {
            self.follow_tries += 1;
            let idx = *self.shared.display_idx.lock().unwrap();
            log::info!(
                "fgtw-diag: follow SEND change_resolution display={} {}x{} (frame is {fw}x{fh})",
                idx, target.0, target.1
            );
            self.session.change_resolution(idx, target.0, target.1);
            if self.follow_tries == FOLLOW_MAX_TRIES {
                log::warn!(
                    "fluor: host did not reach {}x{} after {} tries — leaving the frame 1:1 and centred",
                    target.0, target.1, FOLLOW_MAX_TRIES
                );
            }
            self.follow_at = Some(Instant::now() + FOLLOW_RETRY);
        }
        true // keep ticking until frame == target
    }
}

impl FluorApp for FluorViewer {
    type UserEvent = Wake;

    fn set_event_proxy(&mut self, proxy: Arc<dyn WakeSender<Self::UserEvent>>) {
        *self.shared.proxy.lock().unwrap() = Some(proxy);
    }

    fn init(&mut self, _ctx: &mut Context) {}

    /// Native menu bar (always visible on macOS) carrying the viewer controls — so we don't have
    /// to steal Ctrl+Alt combos from the guest. Static for now; clicks arrive as
    /// `FEvent::MenuItem(id)` and are handled in `on_event`.
    fn menu(&self) -> Vec<MenuItem> {
        vec![
            // "Remote" = the host (leviathan): which of ITS monitors we're viewing.
            MenuItem::Sub {
                label: "Remote".into(),
                items: vec![
                    MenuItem::Action { id: MENU_HOST_NEXT, label: "Next Host Monitor".into() },
                    MenuItem::Action { id: MENU_HOST_PREV, label: "Previous Host Monitor".into() },
                ],
            },
            // "Local" = this Mac: which of OUR monitors the viewer window lives on, plus view toggles.
            MenuItem::Sub {
                label: "Local".into(),
                items: vec![
                    MenuItem::Action { id: MENU_LOCAL_NEXT, label: "Move to Next Monitor".into() },
                    MenuItem::Action { id: MENU_LOCAL_PREV, label: "Move to Previous Monitor".into() },
                    MenuItem::Separator,
                    MenuItem::Action { id: MENU_FULLSCREEN, label: "Toggle Fullscreen".into() },
                    MenuItem::Action { id: MENU_HUD, label: "Toggle Input HUD".into() },
                ],
            },
        ]
    }

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
                // Pass the wheel THROUGH to the host (RustDesk MOUSE_TYPE_WHEEL), not a local pan —
                // the follow makes frame == window, so there's nothing to pan. Normalize to the
                // dominant axis and send small signed line-counts, exactly like the stock client;
                // the host applies its own sign/scale. Pixels (trackpad) scale down to ~lines.
                // To "lines": a wheel notch is Lines(±1); trackpad Pixels are fine-grained, so
                // scale them WAY down (a single swipe is hundreds of px). Then ACCUMULATE and only
                // forward whole lines as they cross ±1, carrying the remainder — no forced ±1 per
                // micro-event, which was flooding the host (the "scroll is HUGE" bug).
                let (dx, dy) = match delta {
                    MouseScrollDelta::Lines(x, y) => (*x, *y),
                    MouseScrollDelta::Pixels(x, y) => {
                        (*x / SCROLL_PX_PER_LINE, *y / SCROLL_PX_PER_LINE)
                    }
                };
                self.scroll_acc_x += dx;
                self.scroll_acc_y += dy;
                let (mut x, mut y) = (self.scroll_acc_x.trunc() as i32, self.scroll_acc_y.trunc() as i32);
                self.scroll_acc_x -= x as f32;
                self.scroll_acc_y -= y as f32;
                // Dominant axis only, like the stock client.
                if x.abs() >= y.abs() {
                    y = 0;
                } else {
                    x = 0;
                }
                if x != 0 || y != 0 {
                    self.session
                        .send_mouse(TYPE_WHEEL, x, y, false, false, false, false);
                }
            }
            FEvent::KeyboardInput { event } => {
                let down = matches!(event.state, ElementState::Pressed);
                // NO local hotkey interception — every combo (Ctrl+Alt+anything included) passes
                // straight through to the guest. Viewer controls (Fullscreen, HUD, host/local
                // monitor switch) live in the macOS menu bar instead, so nothing is stolen from the
                // remote. `m` still feeds the keysym fallback below.
                let m = ctx.modifiers;
                // RAW KEY PASSTHROUGH — a keyboard is just key-down and key-up. Forward the
                // PHYSICAL key position on BOTH edges (KeyboardMode::Map) so the host replays the
                // exact press/release sequence: modifiers are ordinary held keys, and simultaneous
                // chords ([ ] h all down at once), held keys, key-repeat, and games all Just Work
                // because nothing is fused. The host's XTEST device is layout-resynced to the real
                // keyboard (ensure_injection_layout_synced) so each position becomes the right
                // character — the mangle that once forced the keysym-click detour is gone. Keysym
                // "click" modeled TYPING, not a keyboard: it collapsed down+up, so holds/chords
                // were structurally impossible. This is the keyboard.
                if let Some(code) = self.map_physical(event.physical_key) {
                    let mut e = KeyEvent::new();
                    e.mode = KeyboardMode::Map.into();
                    e.down = down;
                    e.set_chr(code);
                    self.session.send_key_event(&e);
                } else {
                    // Non-Linux peer or unmapped key: fall back to layout-independent keysym text
                    // (down edge only — correct characters on any host layout, but no hold/chord).
                    self.send_key(ctx, &event.logical_key, down, event.text.as_deref(), m);
                }
            }
            FEvent::MenuItem(id) => match *id {
                MENU_FULLSCREEN => return EventResponse::ToggleMaximized,
                MENU_HUD => {
                    self.hud = !self.hud;
                    ctx.window.request_redraw();
                }
                MENU_HOST_NEXT => self.switch_host_display(1),
                MENU_HOST_PREV => self.switch_host_display(-1),
                MENU_LOCAL_NEXT => return EventResponse::MoveToMonitor(1),
                MENU_LOCAL_PREV => return EventResponse::MoveToMonitor(-1),
                _ => {}
            },
            _ => {}
        }
        EventResponse::Pass
    }

    fn render(&mut self, target: &mut [u32], ctx: &mut Context) {
        let bw = ctx.viewport.width_px as usize;
        let bh = ctx.viewport.height_px as usize;
        // First render: we finally know the window size, so state it and connect. Everything
        // downstream (login custom_resolution, the host reaching that size before its video
        // service starts) keys off this one value.
        if let Some(io) = self.io_pending.take() {
            let (w, h) = (ctx.viewport.width_px as i32, ctx.viewport.height_px as i32);
            if w > 0 && h > 0 {
                log::info!("fluor: requesting {w}x{h} at login (our window size)");
                *io.lc.read().unwrap().fgtw_desired_resolution.lock().unwrap() = Some((w, h));
            }
            let round = io.connection_round_state.lock().unwrap().new_round();
            std::thread::spawn(move || {
                io_loop(io, round);
            });
        }
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
        // Only log while frame != viewport (following/transient); silent once converged to 1:1
        // steady state so we don't spam a line per frame (that buried the follow-SEND line once).
        if self.last_seen_gen != f.gen {
            self.last_seen_gen = f.gen;
            if fw != bw || fh != bh {
                log::info!(
                    "fluor: blit {fw}x{fh} into viewport {bw}x{bh} org=({ox:.0},{oy:.0}) — following"
                );
            }
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
        // ── On-screen diagnostic HUD (menu bar → Local → HUD). Drawn last so it sits over everything. ──
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
            let line4 = "menu bar: Local/Remote monitor · Fullscreen · HUD";
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
    /// Switch which HOST monitor we view by `delta` (±1), wrapping over the host's display count.
    /// Shared by the Ctrl+Alt+←/→ hotkey and the "Remote" menu. No-op with a single host display;
    /// the host switches, echoes SwitchDisplay back, and resolution-follow re-fits the new monitor.
    fn switch_host_display(&self, delta: i32) {
        let count = *self.shared.display_count.lock().unwrap() as i32;
        if count > 1 {
            let cur = *self.shared.display_idx.lock().unwrap();
            let next = (cur + delta).rem_euclid(count);
            log::info!("fluor: switch to host display {next}/{count}");
            self.session.switch_display(next);
        }
    }

    /// fluor's neutral USB HID usage (`physical_key`) → the PEER's Map-mode keycode. `None` →
    /// caller falls back to the keysym text path. On Linux the peer wants an Xorg keycode =
    /// evdev + 8, where HID→evdev is the kernel's usage→keycode table. The host is layout-
    /// resynced, so keycode 45 (physical K) → Dvorak 't', held for real. Windows/macOS peers
    /// aren't wired (their HID→keycode tables) — those fall back; the Linux fleet is the target.
    fn map_physical(&self, hid: u16) -> Option<u32> {
        if hid == 0 {
            return None;
        }
        let plat = self.shared.peer_platform.lock().unwrap().to_lowercase();
        if plat.contains("windows") || plat.contains("mac") {
            return None;
        }
        let evdev: u32 = match hid {
            0x04 => 30, 0x05 => 48, 0x06 => 46, 0x07 => 32, 0x08 => 18, 0x09 => 33, 0x0A => 34,
            0x0B => 35, 0x0C => 23, 0x0D => 36, 0x0E => 37, 0x0F => 38, 0x10 => 50, 0x11 => 49,
            0x12 => 24, 0x13 => 25, 0x14 => 16, 0x15 => 19, 0x16 => 31, 0x17 => 20, 0x18 => 22,
            0x19 => 47, 0x1A => 17, 0x1B => 45, 0x1C => 21, 0x1D => 44,
            0x1E => 2, 0x1F => 3, 0x20 => 4, 0x21 => 5, 0x22 => 6, 0x23 => 7, 0x24 => 8,
            0x25 => 9, 0x26 => 10, 0x27 => 11,
            0x28 => 28, 0x29 => 1, 0x2A => 14, 0x2B => 15, 0x2C => 57, 0x2D => 12, 0x2E => 13,
            0x2F => 26, 0x30 => 27, 0x31 => 43, 0x33 => 39, 0x34 => 40, 0x35 => 41, 0x36 => 51,
            0x37 => 52, 0x38 => 53, 0x39 => 58,
            0x3A => 59, 0x3B => 60, 0x3C => 61, 0x3D => 62, 0x3E => 63, 0x3F => 64, 0x40 => 65,
            0x41 => 66, 0x42 => 67, 0x43 => 68, 0x44 => 87, 0x45 => 88,
            0x49 => 110, 0x4A => 102, 0x4B => 104, 0x4C => 111, 0x4D => 107, 0x4E => 109,
            0x4F => 106, 0x50 => 105, 0x51 => 108, 0x52 => 103, 0x53 => 69, 0x65 => 127,
            0x54 => 98, 0x55 => 55, 0x56 => 74, 0x57 => 78, 0x58 => 96, 0x59 => 79, 0x5A => 80,
            0x5B => 81, 0x5C => 75, 0x5D => 76, 0x5E => 77, 0x5F => 71, 0x60 => 72, 0x61 => 73,
            0x62 => 82, 0x63 => 83,
            0xE0 => 29, 0xE1 => 42, 0xE2 => 56, 0xE3 => 125, 0xE4 => 97, 0xE5 => 54, 0xE6 => 100,
            0xE7 => 126,
            _ => return None,
        };
        Some(evdev + 8) // Xorg keycode
    }

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

    // The io_loop is NOT started here. What the host must match is our WINDOW, not our
    // monitor — they differ by the menu bar, and asking for the monitor size meant a second,
    // corrective resolution change a moment later, with each change restarting the host's
    // capturer (the glitching). The viewport is only known once the window exists, so the
    // first render states it and starts the connection; login then carries the right size and
    // the host changes resolution exactly once.
    let io_pending = Some(session.clone());

    let app = FluorViewer {
        session,
        shared,
        scroll_acc_x: 0.0,
        scroll_acc_y: 0.0,
        buttons: 0,
        last_seen_gen: 0,
        io_pending,
        follow_target: (0, 0),
        follow_tries: 0,
        follow_at: None,
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
