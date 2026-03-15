# Bug Report: purple codebase review

All actionable bugs have been fixed. Remaining items are accepted limitations.

## Fixed

- **BUG-1:** `parse_include_line` misparses `Include =path` — fixed separator stripping
- **BUG-2:** `multi_select` stale after sort — cleared in `apply_sort()`
- **BUG-3:** Redundant `kill()/wait()` on exited tunnels — removed from removal loop
- **BUG-4:** `trim_start_matches('#')` strips multiple `#` — changed to `strip_prefix('#')`
- **BUG-5:** Alias validate doesn't trim before whitespace check — now trims first
- **BUG-6:** Tag input lacks cursor movement — added Left/Right/Home/End support
- **BUG-7:** Config reload during ConfirmDelete dialog — added to skip list
- **BUG-11:** `atomic_write` temp file replaces extension — now appends suffix
- **BUG-12:** Snippet INI parser trims command values — changed to `trim_start()` only
- **BUG-13:** Missing Include `=` tests — added 3 new test cases
- **BUG-14:** Askpass marker path traversal — alias now sanitized
- **BUG-15:** Sort resets selection — now preserves selected host alias
- **BUG-16:** CLI tag match case-sensitive — changed to `eq_ignore_ascii_case`
- **BUG-19:** Import creates invisible pattern aliases — now validates and skips

## Accepted (not fixed)

- **BUG-8:** History file race between instances — inherent to multi-process; atomic write prevents corruption
- **BUG-9:** `ping_all` coordinator doesn't join workers — results arrive via channel; no data loss while app runs
- **BUG-10:** `contains_ci` ASCII-only folding — correct for SSH hostnames (always ASCII)
- **BUG-17:** Version cache uses `fs::write` — gracefully handles corrupt cache; low risk
- **BUG-18:** `file_browser_paths` orphaned on rename — cosmetic; just loses saved browse position
