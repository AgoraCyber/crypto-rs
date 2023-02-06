use thiserror::Error;

#[derive(Debug, Error)]
pub enum SchnorrError {
    #[error("Target is not a correct adaptor signature")]
    IncorrectAdaptorSig,

    #[error("Secret value must be non zero")]
    NonZeroScalar,
}
