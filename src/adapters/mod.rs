//! Adapters map each folded primitive's native output into the SEAM contract.
//!
//! Adding/removing a primitive = adding/removing a module here. The core
//! (`seam`, `decide`) never changes. This is the whole point of the fold: the
//! set of folded primitives is a living, demand-driven registry — not a fixed
//! bill of materials decided up front.

#[cfg(feature = "wire-custos")]
pub mod custos;

#[cfg(feature = "wire-probatio")]
pub mod probatio;

// Later — dock when a flow needs it:
//   pub mod intentio; // intentio_reexec::ExecResult -> ReexecProof (standalone EVM leg)
