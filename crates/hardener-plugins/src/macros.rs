//! Macros for reducing plugin boilerplate.
//!
//! Provides the `define_plugin!` macro to generate standard plugin structure.

/// Defines a hardening plugin with standard boilerplate.
#[macro_export]
macro_rules! define_plugin {
    (
        $plugin_name:ident {
            id: $id:expr,
            name: $name:expr,
            version: $version:expr,
            description: $description:expr,
            category: $category:ident,
            dependencies: [$($dep:expr),*],
        }
    ) => {
        // Generate the plugin struct
        pub struct $plugin_name;

        // Implement helper methods
        impl $plugin_name {
            fn metadata_impl() -> $crate::hardener_core::plugin::PluginMetadata {
                use $crate::hardener_common::types::{FindingCategory, PluginId};
                use $crate::hardener_core::plugin::PluginMetadata;

                PluginMetadata {
                    plugin_category: FindingCategory::$category,
                    plugin_description: $description.to_string(),
                    plugin_id: PluginId::from($id),
                    plugin_name: $name.to_string(),
                    plugin_version: $version.to_string(),
                }
            }
        }

        // Implement the HardeningPlugin trait
        #[async_trait::async_trait]
        impl $crate::hardener_core::plugin::HardeningPlugin for $plugin_name {
            fn metadata(&self) -> $crate::hardener_core::plugin::PluginMetadata {
                Self::metadata_impl()
            }

            fn dependencies(&self) -> Vec<$crate::hardener_common::types::PluginId> {

                vec![$(PluginId::from($dep)),*]
            }

            async fn scan(
                &self,
                _ctx: &$crate::hardener_core::Context,
            ) -> $crate::hardener_common::error::Result<$crate::hardener_core::plugin::ScanResult> {
                todo!("Implement scan() for {}", stringify!($plugin_name))
            }

            async fn apply(
                &self,
                _ctx: &mut $crate::hardener_core::Context,
                _config: &$crate::hardener_core::PluginConfig,
            ) -> $crate::hardener_common::error::Result<$crate::hardener_core::plugin::ApplyResult> {
                todo!("Implement apply() for {}", stringify!($plugin_name))
            }

            async fn rollback(
                &self,
                _ctx: &mut $crate::hardener_core::Context,
                _checkpoint: &$crate::hardener_core::plugin::Checkpoint,
            ) -> $crate::hardener_common::error::Result<()> {
                todo!("Implement rollback() for {}", stringify!($plugin_name))
            }

            async fn validate(
                &self,
                _ctx: &$crate::hardener_core::Context,
                _config: &$crate::hardener_core::PluginConfig,
            ) -> $crate::hardener_common::error::Result<$crate::hardener_core::plugin::ValidationReport> {
                todo!("Implement validate() for {}", stringify!($plugin_name))
            }
        }
    };
}
