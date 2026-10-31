//! Every host surface must carry the same configured representation cache bounds.
use futures::executor::block_on;
use ikigai_core::{Capability, Iri, Kernel, Request, Verb};

fn check(kernel: &Kernel) {
    let request = Request::new(Verb::Source, Iri::parse("urn:kernel:cache").unwrap());
    let rep = block_on(kernel.issue(request, &Capability::root())).unwrap();
    let text = std::str::from_utf8(&rep.bytes).unwrap();
    assert!(text.contains(" / 12345 "), "{text}");
    assert!(text.contains(" / 512.0 MB"), "{text}");
}

#[test]
fn every_host_surface_uses_configured_bounds() {
    use ikigai_embedded as host;
    let home = std::env::temp_dir().join(format!("iki-host-cache-{}", std::process::id()));
    std::fs::create_dir_all(home.join("files")).unwrap();
    std::fs::write(
        home.join("config.toml"),
        "cache.max_entries = 12_345\ncache.max_bytes = 536_870_912\n",
    )
    .unwrap();
    host::config::set_config_home(home.clone()).unwrap();
    host::set_file_root(home.join("files"));
    check(&host::kernel());
    check(&host::watched_kernel());
    check(&host::trusted_kernel_with_mounts("Cache test", Vec::new()));
    check(&host::kernel_for("Cache test"));
    check(&host::kernel_for_with_eval("Cache test"));
    check(&host::calendar_server_kernel());
    check(&host::calendar_server_kernel_with_eval());
    check(&host::served_kernel_hosting(
        "Cache test",
        Default::default(),
        Vec::new(),
        None,
    ));
    std::fs::remove_dir_all(home).unwrap();
}
