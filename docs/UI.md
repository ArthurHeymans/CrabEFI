# Native setup UI

The `ui` feature provides a keyboard-first framebuffer interface for Boot,
Secure Boot and platform settings. People open firmware setup rarely, so every
screen says what it does, shows its keys, and explains the selected item in
place. It uses W3C APG interaction conventions and
[WCAG2ICT](https://www.w3.org/TR/wcag2ict-22/) as design guidance, not as a claim
of WCAG conformance or assistive-technology compatibility.

## Design ("Ledger")

- **Paper and ink.** Warm off-white surfaces, near-black text and one muted
  green for the single filled action on a surface. Amber marks unsaved drafts,
  countdowns and weakening actions; red marks destructive ones. Every state
  also has a non-colour cue: a `*` for drafts, an outline for keyboard focus, a
  left bar and bold text for the selection, and explicit wording for danger.
- **Folder tabs.** Boot, Security and Firmware are tabs whose first letter is
  underlined: it is the shortcut. `Firmware *` shows unsaved drafts from any
  page. The header chip shows the Secure Boot state.
- **Tables and a details pane.** Lists are ruled tables. A details pane beside
  them explains the selected entry, option or action, lists its facts, and
  holds its buttons with their keys.
- **Notice strip.** One full-width line states the page's situation: the boot
  countdown, unsaved changes with Save and Discard, a successful save with
  Restart now, a failed save with Try again, or an operation's result.
- **Key legend.** The footer lists the page's own keys on the left and the
  fixed global keys on the right (B/S/F pages, F8 text size, R restart).
  Dialogs and editors replace it with their own keys.
- **Bitmap honest.** Only `noto-sans-mono-bitmap` (Regular and Bold, ASCII),
  solid rectangles, 1-2 px rules and dots are used. Truncation uses `...`.
  Modal backdrops repaint the screen through a darker palette instead of
  reading back and blending framebuffer pixels.

The design targets **1024 x 768** (for example a ThinkPad X61) with compact
typography and **1920 x 1080** with large typography. Below 860 px wide the
details panes give way to an action bar (Boot, Security) or the Details dialog
(`?`, Firmware). The smallest supported graphical viewport is 640 x 400;
smaller displays use the text interface.

## Interaction contract

- **Tab / Shift+Tab:** move between the tabs, the page's lists (Firmware also
  has its Sections list) and its buttons. Arrows move within the focused group.
  Activating the current tab does not leave the page or prompt.
- **Enter:** boot the selected entry, open the selected action, or edit the
  selected option. Space activates a focused button but never boots.
- **Escape:** cancel a dialog, picker or editor without committing, or go back
  to Boot through the unsaved-changes decision. It never discards drafts.
- **F10 (or W):** save firmware settings. **R:** restart, guarded the same way
  as leaving when drafts exist. **F8:** compact/large text for the session.
- **Boot:** `E` edits the selected Linux entry's command line once, in the
  details pane. Enter boots with it; nothing is written back to disk.
- **Firmware:** Left/Right change the selected value in place; Enter opens a
  picker or field editor anchored to the row; `D` sets the default as a draft;
  `?` shows full help. Read-only and unavailable options say why.
- **Pointer:** a list click selects without activating. Buttons, tabs, section
  rows and picker choices are clickable; a picker choice is applied with
  "Use value". Clicking above or below a scrollbar thumb pages the list.
  Wheel reports, where delivered, scroll the viewport and never retarget the
  selection.

## Dialogs and review

Modal dialogs focus their safe choice first (Cancel, Keep editing, Close) and
return it on Escape. Destructive confirmations are outlined in red and never
filled. The unsaved-changes guard names the destination ("You are going to the
Boot page", "You are restarting the computer") and lists each change as
`saved -> unsaved`.

Trust review shows identities before consent: source, result, and every
certificate that will be enrolled, including the bundled Microsoft UEFI CA,
each with subject, labelled SHA-256 fingerprint and validity. Byte-identical
certificates are identified as the same certificate. Identity blocks are never
split; long reviews page by whole blocks, and the confirm button stays
unavailable until every page was shown. The import commits the owned bytes
verified before review; changing the ESP file while a review is open does not
change what is enrolled. This UI does not replace runtime authentication,
persistence or replay enforcement.

## Layout and implementation

- `ui/theme.rs` owns the palette and the dimmed backdrop mapping.
- `ui/layout.rs` owns typography and physical metrics for both modes.
- `ui/kit.rs` owns chrome: header and tabs, key legend, notice strip, pane
  titles, fact sheets and modal frames.
- `ui/controls.rs` owns focus groups, rows, buttons and viewport movement.
- `ui/dialog.rs` owns modals, trust review, anchored pickers and editors.
- Screens keep their domain state and cursor-safe partial repaints; unit tests
  compare partial and full repaints pixel for pixel.

There is no browser DOM, native OS accessibility API or exported accessibility
service. Serial keyboard input is supported (including BackTab, Delete, F8 and
F10), and text-only builds remain available, but full nonvisual parity requires
separate work and testing.

## Validation

Unit tests cover focus traversal, safe activation, editor state and caret
boundaries, whole-block review paging, palette contrast, bounded layouts at
640 x 400 to 1920 x 1080, scroll/selection independence and cursor-safe
repainting. QEMU checks exercise real input and rendering at 640 x 480,
1024 x 768, 1280 x 800 and 1920 x 1080: countdown, one-shot command line handed
to a real Linux kernel, pickers, number editing, unsaved/leave/restart guards,
save and failed save, custom key review and enrollment, key listing and the
Clear all keys confirmation. Synthetic CFR fixtures exercise the real guest
parser and settings backend; they are not physical-machine configuration claims.

Relevant references:

- [APG keyboard interface](https://www.w3.org/WAI/ARIA/apg/practices/keyboard-interface/)
- [APG modal dialog pattern](https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/)
- [WCAG non-text contrast guidance](https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast.html)

Automated checks and screenshots are evidence, not a substitute for testing
with people who use different input and visual accommodations.
