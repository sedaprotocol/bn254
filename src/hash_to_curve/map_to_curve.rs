use anyhow::Result;

pub(crate) trait MapToCurve {
    type Output;

    fn map_to_curve(self) -> Result<Self::Output>;
}
