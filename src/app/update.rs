/// Update availability state.
///
/// `hint` defaults to `""` via `#[derive(Default)]`. In practice `App::new()`
/// always overwrites it with the detected install method, so the empty default
/// is only visible when constructing `UpdateState` in isolation (e.g. tests).
#[derive(Default)]
pub struct UpdateState {
    /// Available version string (None if up to date or unchecked).
    pub(in crate::app) available: Option<String>,
    /// Update announcement headline.
    pub(in crate::app) headline: Option<String>,
    /// Update hint string (install command suggestion).
    pub(in crate::app) hint: &'static str,
}

impl UpdateState {
    /// Construct with the current install-method hint detected at runtime.
    pub fn with_current_hint() -> Self {
        Self {
            hint: crate::update::update_hint(),
            ..Self::default()
        }
    }

    pub fn available(&self) -> Option<&String> {
        self.available.as_ref()
    }

    pub fn headline(&self) -> Option<&str> {
        self.headline.as_deref()
    }

    pub fn hint(&self) -> &'static str {
        self.hint
    }

    pub fn announce(&mut self, version: String, headline: Option<String>) {
        self.available = Some(version);
        self.headline = headline;
    }
}
