// Copyright (c) 2024-present YISHENG TANG
// SPDX-License-Identifier: Apache-2.0

//! Generic hot-reloadable configuration holder.
//!
//! Provides thread-safe, lock-free configuration management using `ArcSwap`.
//! Designed to be reused across all binaries in the mandate ecosystem.
//!
//! # Example
//!
//! ```rust
//! use mandate_core::config::ConfigHolder;
//!
//! #[derive(Clone, Default)]
//! struct MyConfig {
//!     timeout_secs: u64,
//!     enabled: bool,
//! }
//!
//! let holder = ConfigHolder::new(MyConfig::default());
//!
//! // Read current config
//! let config = holder.load();
//! println!("timeout: {}", config.timeout_secs);
//!
//! // Update atomically
//! holder.update(|c| c.timeout_secs = 30);
//! ```

use arc_swap::ArcSwap;
use std::sync::Arc;

/// Thread-safe hot-reloadable configuration holder.
///
/// Uses `ArcSwap` internally for lock-free reads and atomic writes.
/// Suitable for configuration that is read frequently but updated rarely.
pub struct ConfigHolder<T> {
    inner: ArcSwap<T>,
}

impl<T> ConfigHolder<T> {
    /// Create a new config holder with the given initial configuration.
    pub fn new(config: T) -> Self {
        Self {
            inner: ArcSwap::from_pointee(config),
        }
    }

    /// Load the current configuration.
    ///
    /// Returns an `Arc<T>` for zero-copy access. The returned Arc is a snapshot
    /// and won't be affected by subsequent updates.
    pub fn load(&self) -> Arc<T> {
        self.inner.load_full()
    }

    /// Replace the current configuration with a new one.
    ///
    /// This operation is atomic - readers will see either the old or new config,
    /// never a partial update.
    pub fn store(&self, config: T) {
        self.inner.store(Arc::new(config));
    }
}

impl<T: Clone> ConfigHolder<T> {
    /// Atomically update the configuration using a closure.
    ///
    /// The closure receives a mutable reference to a clone of the current config.
    /// After the closure returns, the modified config is stored atomically.
    ///
    /// Note: This is not a true compare-and-swap. If concurrent updates occur,
    /// the last update wins. For most configuration use cases, this is acceptable.
    pub fn update<F>(&self, f: F)
    where
        F: FnOnce(&mut T),
    {
        let mut config = (*self.load()).clone();
        f(&mut config);
        self.store(config);
    }
}

impl<T: Default> Default for ConfigHolder<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Default, PartialEq, Debug)]
    struct TestConfig {
        value: u64,
        enabled: bool,
    }

    #[test]
    fn test_new_and_load() {
        let config = TestConfig {
            value: 42,
            enabled: true,
        };
        let holder = ConfigHolder::new(config.clone());
        let loaded = holder.load();
        assert_eq!(*loaded, config);
    }

    #[test]
    fn test_store() {
        let holder = ConfigHolder::new(TestConfig::default());

        let new_config = TestConfig {
            value: 100,
            enabled: true,
        };
        holder.store(new_config.clone());

        assert_eq!(*holder.load(), new_config);
    }

    #[test]
    fn test_update() {
        let holder = ConfigHolder::new(TestConfig {
            value: 10,
            enabled: false,
        });

        holder.update(|c| {
            c.value = 20;
            c.enabled = true;
        });

        let loaded = holder.load();
        assert_eq!(loaded.value, 20);
        assert!(loaded.enabled);
    }

    #[test]
    fn test_default() {
        let holder: ConfigHolder<TestConfig> = ConfigHolder::default();
        let loaded = holder.load();
        assert_eq!(loaded.value, 0);
        assert!(!loaded.enabled);
    }

    #[test]
    fn test_snapshot_isolation() {
        let holder = ConfigHolder::new(TestConfig {
            value: 1,
            enabled: false,
        });

        // Take a snapshot
        let snapshot = holder.load();
        assert_eq!(snapshot.value, 1);

        // Update the config
        holder.store(TestConfig {
            value: 2,
            enabled: true,
        });

        // Snapshot should still show old value
        assert_eq!(snapshot.value, 1);

        // New load should show new value
        assert_eq!(holder.load().value, 2);
    }
}
