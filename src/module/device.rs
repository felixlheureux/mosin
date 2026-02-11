use crate::constants;

pub async fn start_device() -> Result<tun::AsyncDevice, Box<dyn std::error::Error>> {
    let mut config = tun::Configuration::default();

    config
        .tun_name(constants::TUN_DEVICE_NAME)
        .address(constants::TUN_ADDRESS)
        .netmask(constants::TUN_NETMASK)
        .destination(constants::TUN_DESTINATION)
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|config| {
        config.ensure_root_privileges(true);
    });

    let device = tun::create_as_async(&config)?;

    Ok(device)
}
