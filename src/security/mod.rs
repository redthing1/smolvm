//! Internal launch policy, preparation, and hardening support.
//!
//! This module starts as a pure policy boundary: it describes what a launch is
//! allowed to use without changing runtime behavior. Later hardening stages add
//! prepared paths and platform-specific enforcement behind this boundary.

pub mod audit;
pub mod policy;
pub mod prepare;
