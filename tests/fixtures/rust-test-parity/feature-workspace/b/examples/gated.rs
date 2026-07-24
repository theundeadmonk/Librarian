fn main() {
    assert!(feature_provider::enabled());
}

#[cfg(test)]
mod tests {
    #[test]
    fn resolved_feature_is_active() {
        assert!(feature_provider::enabled());
    }
}
