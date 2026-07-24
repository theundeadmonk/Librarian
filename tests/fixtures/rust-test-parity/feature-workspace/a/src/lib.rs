/// Confirms that the workspace-wide dependency feature is active.
///
/// ```
/// assert!(feature_observer::workspace_feature_is_enabled());
/// ```
pub fn workspace_feature_is_enabled() -> bool {
    shared_feature::enabled()
}

#[cfg(test)]
mod tests {
    #[test]
    fn workspace_dependency_feature_is_unified() {
        assert!(shared_feature::enabled());
    }
}
