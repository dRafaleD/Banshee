use anyhow::Result;

const WORDMARK: &str = r#"
BBBB   A   N   N  SSSS H  H EEEE EEEE
B   B A A  NN  N S     H  H E    E
BBBB AAAAA N N N  SSS  HHHH EEE  EEE
B   B A   A N  NN     S H  H E    E
BBBB  A   A N   N SSSS  H  H EEEE EEEE
"#;

const MINI_EMBLEM: &str = r#"
       .-------.
      /  .-.    \
     |  /   \   |
     | | ( ) |  |
     |  \ | /   |
      \  `-'   /
       '-----'
"#;

const MASK: &str = r#"
                    .-=================-.
                 .-'    .-''''''-.       '-.
               .'       /  _  _    \        '.
              /        |  / || \    |         \
             ;         | |  ||  |   |          ;
             |         | | (  ) |   |          |
             |         | |  /\  |   |          |
             |         | | /||\ |   |          |
             |         | || || ||   |          |
             |         | || || ||   |          |
             ;          \||_||_||  /           ;
              \          \_______/            /
               '.        /  ___  \          .'
                 '-.____/__/   \__\______. -'
                    /      /     \      \
                   /______/       \______\
"#;

pub fn print(compact: bool, mask_only: bool) -> Result<()> {
    crate::output::write_raw(render(compact, mask_only).as_bytes())
}

pub fn render(compact: bool, mask_only: bool) -> String {
    if mask_only {
        return format!("{MASK}\n");
    }
    if compact {
        return format!("{MINI_EMBLEM}\n{WORDMARK}\n  offline security analysis toolkit\n");
    }
    format!("{MINI_EMBLEM}\n{WORDMARK}\n{MASK}\n  BANSHEE // OFFLINE SECURITY ANALYSIS TOOLKIT\n")
}

#[cfg(test)]
mod tests {
    use super::render;

    #[test]
    fn default_banner_contains_wordmark_and_mask() {
        let banner = render(false, false);
        assert!(banner.contains("BBBB"));
        assert!(banner.contains("(  )"));
        assert!(banner.contains("OFFLINE SECURITY"));
    }

    #[test]
    fn compact_and_mask_only_are_distinct() {
        assert!(!render(true, false).contains(".============"));
        assert!(!render(false, true).contains("BBBB"));
    }
}
