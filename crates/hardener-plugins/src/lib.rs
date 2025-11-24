pub mod audit;
pub mod firewall;
pub mod kernel;
pub mod mac;
pub mod macros;
pub mod pam;
pub mod permissions;
pub mod services;
pub mod ssh;

// Re-export dependencies for macro use
#[doc(hidden)]
pub use audit::AuditHardeningPlugin;
pub use firewall::FirewallHardeningPlugin;
pub use hardener_common;
pub use hardener_core;
pub use kernel::KernelHardeningPlugin;
pub use mac::MacHardeningPlugin;
pub use pam::PamHardeningPlugin;
pub use permissions::PermissionsHardeningPlugin;
pub use services::ServicesHardeningPlugin;
pub use ssh::SshHardeningPlugin;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use hardener_core::plugin::HardeningPlugin;

    use crate::define_plugin;

    // Use the macro to define a test plugin
    define_plugin! {
        TestPlugin {
            id: "test-plugin",
            name: "Test Plugin",
            version: "0.1.0",
            description: "A test plugin for macro validation",
            category: Kernel,
            dependencies: [],
        }
    }

    #[test]
    fn test_macro_generates_plugin() {
        // Create an instance
        let plugin = TestPlugin;

        // Test metadata
        let meta = plugin.metadata();
        assert_eq!(meta.plugin_id.to_string(), "test-plugin");
        assert_eq!(meta.plugin_name, "Test Plugin");
        assert_eq!(meta.plugin_version, "0.1.0");
        assert_eq!(
            meta.plugin_description,
            "A test plugin for macro validation"
        );

        // Test dependencies
        let deps = plugin.dependencies();
        assert_eq!(deps.len(), 0);
    }
}
