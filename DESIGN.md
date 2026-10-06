---
version: alpha
name: AD Diagnostics
description: A Windows admin utility that looks like it shipped with the OS. Two themes, Dark mode and the light one, Flashbang.
colors:
  primary: "#005fb8"
  on-primary: "#ffffff"
  background: "#f3f3f3"
  panel: "#ffffff"
  surface: "#fbfbfb"
  border: "#d1d1d1"
  row-line: "#ededed"
  text: "#1b1b1b"
  text-dim: "#5f5f5f"
  pass: "#0f7b0f"
  warn: "#9d5d00"
  fail: "#c42b1c"
  skip: "#767676"
  primary-dark: "#4cc2ff"
  on-primary-dark: "#000000"
  background-dark: "#202020"
  panel-dark: "#1c1c1c"
  surface-dark: "#2d2d2d"
  border-dark: "#3d3d3d"
  row-line-dark: "#2a2a2a"
  text-dark: "#f2f2f2"
  text-dim-dark: "#a3a3a3"
  pass-dark: "#6ccb5f"
  warn-dark: "#fce100"
  fail-dark: "#ff99a4"
  skip-dark: "#8a8a8a"
typography:
  title:
    fontFamily: Segoe UI
    fontSize: 15px
    fontWeight: 700
  group-heading:
    fontFamily: Segoe UI
    fontSize: 13px
    fontWeight: 700
  body:
    fontFamily: Segoe UI
    fontSize: 12px
    fontWeight: 400
  caption:
    fontFamily: Segoe UI
    fontSize: 11px
    fontWeight: 400
  value:
    fontFamily: Cascadia Code
    fontSize: 11px
    fontWeight: 400
rounded:
  none: 0px
  control: 4px
spacing:
  gutter: 14px
  row: 24px
  control-gap: 8px
components:
  button:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
  button-dark:
    backgroundColor: "{colors.surface-dark}"
    textColor: "{colors.text-dark}"
    rounded: "{rounded.control}"
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    rounded: "{rounded.control}"
  button-primary-dark:
    backgroundColor: "{colors.primary-dark}"
    textColor: "{colors.on-primary-dark}"
    rounded: "{rounded.control}"
  button-danger:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.fail}"
    rounded: "{rounded.control}"
  button-danger-dark:
    backgroundColor: "{colors.surface-dark}"
    textColor: "{colors.fail-dark}"
    rounded: "{rounded.control}"
  tab:
    backgroundColor: "{colors.background}"
    textColor: "{colors.text-dim}"
  tab-selected:
    backgroundColor: "{colors.background}"
    textColor: "{colors.text}"
  tab-dark:
    backgroundColor: "{colors.background-dark}"
    textColor: "{colors.text-dim-dark}"
  tab-selected-dark:
    backgroundColor: "{colors.background-dark}"
    textColor: "{colors.text-dark}"
  input:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
  input-dark:
    backgroundColor: "{colors.surface-dark}"
    textColor: "{colors.text-dark}"
  result-row:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.text}"
  result-row-dark:
    backgroundColor: "{colors.panel-dark}"
    textColor: "{colors.text-dark}"
  status-pass:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.pass}"
  status-warn:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.warn}"
  status-fail:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.fail}"
  status-pass-dark:
    backgroundColor: "{colors.panel-dark}"
    textColor: "{colors.pass-dark}"
  status-warn-dark:
    backgroundColor: "{colors.panel-dark}"
    textColor: "{colors.warn-dark}"
  status-fail-dark:
    backgroundColor: "{colors.panel-dark}"
    textColor: "{colors.fail-dark}"
  ticket-badge:
    backgroundColor: "{colors.pass}"
    textColor: "{colors.on-primary}"
  ticket-badge-dark:
    backgroundColor: "{colors.pass-dark}"
    textColor: "{colors.on-primary-dark}"
---

# AD Diagnostics

## Overview

A diagnostic utility that domain admins and helpdesk staff run on a domain-joined Windows PC to see why Active Directory isn't working. It should look like it shipped with Windows, beside Event Viewer and Resource Monitor: plain, dense, and trusted. It is not a dashboard and has no brand of its own.

The tokens live in `MainForm.cs` (the `Themed(light, dark)` properties). The theme starts from the Windows app setting (`AppsUseLightTheme`); the header button switches it while the app runs and is labelled with the theme it switches to: "Dark mode" or "Flashbang" (the light theme's name in this app). The choice is not saved.

## Colors

Windows 11's own system values, so the app matches the OS around it.

- **Primary (#005fb8, dark #4cc2ff):** the Windows default accent. Used for the primary button, links, the selected tab's underline, the selected run and the running ring. Nothing else.
- **Background (#f3f3f3, dark #202020):** the window. **Panel (#ffffff, dark #1c1c1c):** the results list and text panes. **Surface (#fbfbfb, dark #2d2d2d):** buttons and inputs. Background, panel and surface must stay three different values in each theme: `SetTheme` maps a control's colour to the same token in the other theme by value.
- **Status:** pass #0f7b0f, warn #9d5d00, fail #c42b1c, skip #767676 (dark: #6ccb5f, #fce100, #ff99a4, #8a8a8a). Status colour goes on the mark and the status word only.
- **Text (#1b1b1b, dark #f2f2f2)** and **text-dim (#5f5f5f, dark #a3a3a3)** for captions, counts and skipped details.

## Typography

- **Segoe UI** for everything a person reads as interface: 11pt bold title, 9.5pt bold group headings, 9pt body, 8.5pt captions.
- **Cascadia Code, falling back to Consolas,** only for values copied from the system: hostnames, addresses, paths, tool output, tickets.
- Sentence case everywhere. No all-caps labels.

## Layout

- 14px side gutter. Fixed 96-DPI pixel values in code go through `S()` so they scale with the display.
- Results are a grid: status (mark + word) at 14px, test name at 100px, detail at 280px to the right edge. Rows are at least 24px with a 1px row line above each.
- Each group heading carries its count at the right edge: "9 checks · 1 warning".

## Elevation & Depth

None. Depth is tone only: the panel is lighter (dark: darker) than the window. No shadows, no gradients.

## Shapes

- Buttons: 4px corner radius, 1px border when on the plain surface, no border when filled.
- Inputs and panels: square.
- Status marks are 10px and differ by shape: circle = passed, triangle = warning, cross = failed, dash = skipped, ring = running.

## Components

- **Button** (`ThemedButton`): surface fill, text colour label. Hover blends 7% toward text, pressed 14%, disabled fades toward the window. Focus draws the border in primary.
- **Primary button:** one per screen (Run diagnostics); it is also the Enter-key default.
- **Danger button:** a normal button with the label in fail colour (Reset all, Delete run).
- **Tab:** bare text, dim when idle; the selected tab is bold with a 3px primary underline.
- **Result row:** mark and word in status colour; name and detail in text colour.
- **Ticket badge:** filled label in the Kerberos tickets pane; text uses on-primary.
- **Trace row** (DNS registration pane): the result row's three columns in a text pane, with the same mark shapes as characters (● ▲ ✕ –); a long detail wraps under the detail column.
- **Picker** (ZTNA adapter): a flat drop-down list on surface with a text-dim label to its left, in the action bar after the buttons. Its list is as wide as its longest entry.
- **Log line:** monospace, since every line is a system value. Time and source in text-dim, message in text, debug lines wholly in text-dim.

## Do's and Don'ts

- Do keep status colour on marks and status words; result details stay in text colour.
- Do give every status a shape or a word as well as a colour.
- Do add a `Themed(light, dark)` token for any new colour, list it here, and add it to `BackTokens` or `ForeTokens` if a control can hold it.
- Don't use raw colours (`Color.White`, hex literals) in controls.
- Don't use all-caps headings, pills or badges for metadata, hand cursors on buttons, gradients, shadows or emoji.
- Don't print whole lines in status colour or in monospace unless the line is a system value.
- Don't use box-drawing banners for headings; a bold heading and one rule is enough.
