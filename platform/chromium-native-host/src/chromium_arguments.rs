pub fn valid_extension_origin(value: &str) -> bool {
    const PREFIX: &str = "chrome-extension://";
    value.len() == PREFIX.len() + 33
        && value.starts_with(PREFIX)
        && value.ends_with('/')
        && value[PREFIX.len()..value.len() - 1]
            .bytes()
            .all(|byte| (b'a'..=b'p').contains(&byte))
}

pub fn valid_parent_window(value: &str) -> bool {
    const PREFIX: &str = "--parent-window=";
    value.strip_prefix(PREFIX).is_some_and(|handle| {
        !handle.is_empty() && handle.len() <= 20 && handle.bytes().all(|b| b.is_ascii_digit())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chromium_arguments_are_exactly_bounded() {
        assert!(valid_extension_origin(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"
        ));
        assert!(!valid_extension_origin(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
        ));
        assert!(!valid_extension_origin(
            "chrome-extension://abcdefghijklmnopabcdefghijklmn0p/"
        ));
        assert!(valid_parent_window("--parent-window=0"));
        assert!(valid_parent_window("--parent-window=18446744073709551615"));
        assert!(!valid_parent_window("--parent-window="));
        assert!(!valid_parent_window("--parent-window=-1"));
    }
}
