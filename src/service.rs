
#[cfg(not(target_os = "macos"))]
fn main() {}

#[cfg(target_os = "macos")]
fn main() {
    librustdesk::common::load_custom_client();
    hbb_common::init_log(false, "service");
    librustdesk::start_os_service();
}
