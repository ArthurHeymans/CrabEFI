# Native setup UI

The `ui` feature provides a keyboard-first framebuffer interface for Boot,
Secure Boot and platform settings. It uses W3C APG interaction conventions and
[WCAG2ICT](https://www.w3.org/TR/wcag2ict-22/) as design guidance, not as a claim
of WCAG conformance or assistive-technology compatibility.

## Interaction contract

- **Tab / Shift+Tab:** move between navigation, content and contextual actions.
  Arrows move within the focused group. Activating the current navigation tab
  does not leave the screen or prompt to discard drafts.
- **Enter:** open the selected setting/action, or boot from the boot list.
  Space activates a focused button, but never boots from the boot list.
- **B / S / F:** Boot, Security and Settings shortcuts, where available.
  Shortcuts are not dispatched while editing a field.
- **Escape:** cancel a dialog without committing, or leave a settings screen
  through its unsaved-changes decision. With no bootable media, Back from
  Settings or Security returns to the restart screen.
- **F8:** switch compact/large text and layout for the current session. The
  preference is not persisted. High-resolution displays default to larger text;
  resolution is not assumed to reveal physical display DPI.
- **Pointer:** one list click selects, without activating. Use the explicit
  Boot/Open/Edit action to activate. Clicking above/below a scrollbar thumb
  pages the list; dragging is not required or implemented. Wheel reports, where
  supplied by the device, also scroll the viewport. Neither retargets selection.
  Keyboard navigation reveals the selected target again.
- **Settings shortcuts:** paging, j/k, +/- and D (draft default) belong to the
  content group. W is an explicit screen-wide Save shortcut, outside editors.

The visible focus indicator is a strong outline. Selection has a persistent
marker; changed drafts have an asterisk and a changed-count summary. Read-only
values use `[R]` and have an explanation in Details. Dangerous operations have
explicit warning text and still require confirmation. Accent-filled buttons
represent an action, not keyboard focus: Cancel can own focus without looking
like the recommended affirmative operation.

## Dialogs and review

Modal dialogs replace the interactive shell while open. Their controls have a
local, bidirectional focus sequence; returning leaves the invoking screen's
selection, focus group and drafts intact.

Text editors begin with field focus. They support Left/Right/Home/End/Delete,
Backspace and Ctrl+U, plus Tab traversal to Cancel and Apply. Validation retains
the draft and returns focus to the field. Input is explicitly ASCII, at most
255 bytes; existing UTF-8 values retain valid caret/deletion boundaries, but
this is not a claim of internationalized input or font coverage.

Enum editors offer Cancel, Choice details and an explicit Apply draft button.
A row click only selects a choice. Reopening or changing text size reveals the
current choice; viewport-only scrolling leaves its labeled target unchanged.
Details exposes complete labels and Draft/Saved/Default values on narrow screens.

Trust review uses labeled blocks rather than concatenated paragraphs. Source,
operation, certificates, signer, timestamp, counts, replacement warnings and file
identity remain distinct. Fingerprint blocks fit together on a review page;
long prose repeats its label when continued. Previous/Next buttons and keyboard
paging expose the complete review. Reused PK/KEK/db certificates are identified
as the same certificate rather than needlessly repeating an identity.

The import still commits the owned bytes verified before review. Changing the
ESP file while a review is open must not change what is enrolled. This UI does
not replace runtime authentication, persistence or replay enforcement.

## Layout and implementation

- Supported graphical viewport: at least **640 x 400**. Smaller boot-menu
  viewports use the existing text interface instead of squeezing clipped controls.
- Content width is bounded; wider layouts provide nearby contextual details.
  Narrow layouts retain a Details action rather than forcing a side pane.
- `ui/layout.rs` owns typography and physical metrics.
- `ui/controls.rs` owns focus-group traversal, control rendering contracts and
  viewport movement. Borrowed descriptors derive from live state, not a second
  retained widget tree.
- Screens retain domain state and their cursor-safe repaint paths. Focus
  movement, selection and activation are different operations.
- Keyboard input samples modifiers from the source device at dequeue time;
  this is not a historical per-keystroke modifier snapshot. Serial CSI BackTab,
  Delete and F8 are normalized alongside physical-keyboard input.

There is no browser DOM, native OS accessibility API or exported accessibility
service. Internal control descriptions and semantic-state tests do not make the
framebuffer screen-reader accessible. Serial keyboard input is supported, and
text-only builds remain available, but full nonvisual parity and usability with
real assistive technology require separate work and testing.

## Validation

Unit tests cover focus traversal, safe activation, editor state and caret
boundaries, complete fingerprint blocks, palette contrast, bounded layout,
scroll/selection independence and cursor-safe repainting. QEMU checks should
exercise actual input and rendering at 640 x 400, 640 x 480, 800 x 600 and native
1920 x 1080, including both text sizes, failed saves and authentication consent.
Synthetic CFR fixtures exercise the real guest parser and settings backend;
they are not physical-machine configuration claims.

Relevant references:

- [APG keyboard interface](https://www.w3.org/WAI/ARIA/apg/practices/keyboard-interface/)
- [APG modal dialog pattern](https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/)
- [WCAG non-text contrast guidance](https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast.html)

Automated checks and screenshots are evidence, not a substitute for testing
with people who use different input and visual accommodations.
