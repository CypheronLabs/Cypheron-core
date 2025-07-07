pub mod traits;
pub mod composite;
pub mod schemes;
pub mod ecdsa;

pub use traits::{HybridEngine, HybridScheme};
pub use composite::{CompositeSignature, CompositeKeypair};
pub use schemes::{EccDilithium, EccFalcon, EccSphincs};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HybridVariant {
    EccDilithium2,
    EccDilithium3, 
    EccDilithium5,
    EccFalcon512,
    EccFalcon1024,
    EccSphincs,
}