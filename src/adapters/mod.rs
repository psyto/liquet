//! Adapters map each folded primitive's native output into the SEAM contract.
//!
//! Adding/removing a primitive = adding/removing a module here. The core
//! (`seam`, `decide`) never changes. This is the whole point of the fold: the
//! set of folded primitives is a living, demand-driven registry — not a fixed
//! bill of materials decided up front.

#[cfg(feature = "wire-custos")]
pub mod custos;

// Phase 2+ — documented, not yet wired. Dock each when a real flow needs it:
//   pub mod probatio; // probatio_xvm::ReconstructedLeg -> ReexecProof (SVM / cross-VM)
//   pub mod intentio; // intentio_reexec::ExecResult    -> ReexecProof (EVM leg)
