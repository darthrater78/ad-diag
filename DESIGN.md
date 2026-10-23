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
- **Status:** pass #0f7b0f, warn #9d5d00, fail #c42b1c, skip #767676 (dark: #6ccb5f, #fce100, #ff99a4, #8a8a8a); info uses primary. Status colour goes on the mark and the status word only.
- **Text (#1b1b1b, dark #f2f2f2)** and **text-dim (#5f5f5f, dark #a3a3a3)** for captions, counts and skipped details.

## Typography

- **Segoe UI** for everything a person reads as interface: 11pt bold title, 9.5pt bold group headings, 9pt body, 8.5pt captions.
- **Cascadia Code, falling back to Consolas,** only for values copied from the system that stand alone: the Domain and DC fields, tool output in the Log, tickets.
- Result details (Results and the SMB pane) are Segoe UI 9pt in text colour: they mix sentences with values, and monospace made whole sentences read stark.
- Sentence case everywhere. No all-caps labels.

## Layout

- 14px side gutter. Fixed 96-DPI pixel values in code go through `S()` so they scale with the display.
- Results are a grid: status (mark + word) at 14px, test name at 100px, detail at 280px to the right edge. Rows are at least 24px with a 1px row line above each.
- Each group heading carries its verdict pill and counts in a fixed column, and its Run button at the right edge: "9 checks · 1 warning".
- At the top of the strip, under the header, a **Test** switch (a segmented control: Active Directory | SMB) picks the mode. The input row, the primary button, the summary and Runs bars, the tabs and the Results tab's content follow it; the Profile is shared.
- The input row starts with the **Profile** picker, 255px; the Domain and DC fields share the rest two to three, so the DC label has room for the suffix box beside it. On the Entra joined profile the Domain and DC fields give way to a text-dim line saying the domain checks are hidden and how to show them. In SMB mode **File server** and **Share (optional)** split the DC field's place, eleven to nine, each with example text and the Domain field stays on every profile, labelled **On-prem domain** on the Entra joined one.
- Tabs sit left to right in a fixed order and close up around one the mode or profile hides: the mode's own tabs (Active Directory: Results, Group Policy, Kerberos tickets, DNS registration, Intune policies; SMB: Results, Kerberos tickets), a 1px border-colour divider, then Guide and Log, which serve both.
- A tab's own actions (Group Policy, Kerberos tickets, DNS registration, Intune policies, Log) sit in a 34px bar at the top of the tab, under the run strip, never at the bottom of the window.
- Groups collapse to their heading. After a run every group is closed, unless "Expand all groups after a run" is ticked; a group the user opens or closes stays that way for that run, and a group run on its own opens (or stays open) to show its new results. The verdict pill and counts stay on a closed heading, so its state still reads.

## Window

The window's 1px outer border is primary (#005fb8, dark #4cc2ff), set through DWM on Windows 11 and following the theme switch; earlier Windows keeps its own.

## Elevation & Depth

None. Depth is tone only: the panel is lighter (dark: darker) than the window. No shadows, no gradients.

## Shapes

- Buttons: 4px corner radius, 1px border when on the plain surface, no border when filled.
- Inputs and panels: square.
- Status marks are 10px and differ by shape: circle = passed, triangle = warning, cross = failed, disc with an "i" cut out = info ("i" in the DNS registration pane), dash = skipped, ring = running.
- Warning means a problem to fix; Info means worth knowing with nothing broken, counted as notes and never lowering a verdict; Skipped means not checked, and its detail starts "Not checked:" with the reason.

## Components

- **Button** (`ThemedButton`): surface fill, text colour label. Hover blends 7% toward text, pressed 14%, disabled fades toward the window. Focus draws the border in primary.
- **Primary button:** one per mode, and it is the Enter-key default: Run diagnostics, or in SMB mode **Test connection** (a plain primary button, 156px, as wide as the split pair) in the same place. It is the left half of a split button: the right half is 26px, primary, with a white down chevron and a thin divider in a blend of the label colour, and opens its menu: "Run all sections", a rule, then each group by name. Only the pair's outer corners are rounded.
- **Connection path** (SMB mode, top of the Results tab, on the panel): the five steps (Name, Port 445, Kerberos, Sign-in, Share) spread evenly, each a 24px circle with a 2px border and the step's status mark at its centre, its name in bold under it and a text-dim caption (Passed, Passed on try 2, Warning, Failed, Failed here, Failed after 3 tries, Not reached, No share given, Checking…). A step not yet reached has a border-colour ring and no mark; the step being checked, a primary ring open on one side. A passed or warned step's circle takes a 14% tint of its status colour, and the 2px line leading to it its status colour; otherwise the line is row-line colour. Above it, the tab's 34px action bar: **Open share** (a normal button) and, when there is a fix, "See SMB in the Guide" in primary. Under the strip, the pane, drawn like Results (not a rich edit box, whose tab stops Windows doesn't keep): the target, the verdict line with its mark, a "Fix:" line as in the Guide, and each step as a group heading (name, verdict pill, counts) over rows in the results grid's columns.
- **Segmented control** (Log view: Sections | By time | Raw; the Test switch): buttons joined like the split button; the chosen one is primary with on-primary text, the other a normal surface button.
- **Menu:** surface fill, 1px border, body text; the hovered item takes a 20% blend toward primary. No icons or image margin.
- **Danger button:** a normal button with the label in fail colour (Reset all, Delete run).
- **Tab:** bare text, dim when idle; the selected tab is bold with a 3px primary underline.
- **Result row:** mark and word in status colour; name and detail in text colour.
- **Group heading** (Results): a 8px text-dim chevron (right when closed, down when open), the bold group name, then the **verdict pill** and the counts, and at the right edge the **Run button**. The counts start at a column as wide as the longest counts on show (at least 200px), with the pill just left of it, so both line up down the list. Verdict pill: the group's worst result once all its checks finish, the readiness line included — PASSED, WARNING or FAILED in 7.5pt bold capitals, in the status colour on a 16% tint of it, 16px tall, fully rounded, all as wide as WARNING. Run button: a capsule like the pills in primary (12% tint, 24% under the mouse), a lightning bolt and "Run again" in 8.5pt bold primary ("Run" on a group that hasn't run), right-aligned in an 88px slot; it runs that group alone and is always shown, faded to 40% and inactive while a run is going. Left of the slot the heading is the button that opens and closes the group; no hand cursor anywhere on it. A group run on its own adds " · run at HH:mm:ss" to its counts. A group that hasn't run shows its name in text-dim, no pill, and "Not run" for counts; it still opens and closes, to list the checks it will make, each "Not run" in text-dim by a text-dim ring, and it starts closed even with "Expand all groups after a run". Before any run, Results lists every group the profile runs this way, so what will be checked shows first. Up and Down move between headings and Run buttons, Enter or Space acts; the focused one draws a focus rectangle; a tooltip names the Run button's group.
- **Needs admin capsule:** on a group heading when a check in it was held back because the app isn't elevated, or, on a group that hasn't run, would be (the checks a standard user is always denied: the secure channel and Group Policy's computer scope): a 16px-tall capsule in the warning colour on a 16% tint, a 10px shield and "Needs admin" in 7.5pt bold ("Partially needs admin" when only some of the group's checks need it), ending 8px left of the verdict pill; just the shield where the name leaves no room. Its tooltip says the checks with a shield need it, and how to run as Administrator. The held-back row has the same shield, in the warning colour, after its check name; before a run its detail reads "Needs Run as Administrator".
- **Administrator indicator:** when the app is elevated, a 12px shield in primary and "Running as administrator" in text colour, 12px right of the version; the title bar starts "Administrator: ", as Windows marks elevated windows.
- **Readiness row:** a result row whose name is "Readiness" in bold and whose detail is the group's verdict in body text. When the verdict asks for action, a link in primary, underlined, follows it ("See the fixes in the Guide") and opens the Guide tab with that group's section open and at the top.
- **Fold mark** (Guide, Log, Intune tab): ▶ when folded, ▼ when open, in text-dim from Segoe UI Symbol 8pt, which draws both the same size (the monospace fonts drew ► much smaller than ▼). The Results grid draws its own line chevron.
- **Guide sections:** every section starts folded to its title (bold, 10.5pt) after a **fold mark**; a click or Enter on the title toggles it, keeping it where it was on screen. Folded titles sit together as a list; an open section has a blank line before and after.
- **Results bar:** above the results, on the panel: the "Expand all groups after a run" checkbox in text-dim on the left, "Expand all" and "Collapse all" links in primary on the right. Shown whenever Results lists groups, before a run too.
- **Ticket badge:** filled label in the Kerberos tickets pane; text uses on-primary.
- **PRT card:** the first card in the Kerberos tickets pane on an Entra or hybrid joined PC, in the ticket card's frame. Its badge (PRT, PRT EXPIRED or NO PRT) is filled with the status colour of the Results row for the token; labels in text-dim, padded to one column; a value with a status (Status, an expired Expires, the TGT flags on an Entra joined PC) takes that status colour.
- **Profile picker:** a flat drop-down list on surface under a text-dim "Profile" label, like the other inputs; the detected choice ends in "(detected)".
- **Intune policies pane:** laid out like the Group Policy pane: a bold section title over a rule in border colour; labels in text-dim, values in text; each setting a ● in pass (the value in force) or warn (another provider's value is in force), its name in text and its value in the monospace font.
- **Trace row** (DNS registration pane): the result row's three columns in a text pane, with the same mark shapes as characters (● ▲ ✕ –); a long detail wraps under the detail column.
- **Picker** (ZTNA adapter): a flat drop-down list on surface with a text-dim label to its left, in the action bar after the buttons. Its list is as wide as its longest entry.
- **Log line:** monospace, since every line is a system value. The time in text-dim (HH:mm:ss in Sections, with milliseconds in By time), then a 10-character kind column: a result's mark and status word in its status colour (● Passed, ▲ Warning, × Failed, i Info, – Skipped), or the line's source in text-dim. By time adds the line's section, by short name, in a text-dim column. A result's check name is bold and its detail follows in text; other messages in text, debug lines in text-dim without a DEBUG label. Wrapped text and raw tool output line up under the message, measured from the box itself. Raw: every line as saved, in text, no indents.
- **Times:** on screen (Runs strip, status, headings, report) times follow the Windows clock format; log line stamps stay 24-hour.
- **Log headings:** a run or another action (a Group Policy query, gpupdate, klist, a DNS registration) opens with its name and time in bold primary, then what it covered and its totals in text-dim. In the Sections view each results section inside it gets a bold heading in text with its counts in text-dim, indented 8px, and its lines indented 20px beneath; the run's own lines sit at 8px; "Started" and "Complete" are left out, since the heading carries both. Every run and section starts folded: a fold mark leads each heading, which a click or Enter toggles. A small gap goes before every heading. By time keeps one timeline and repeats a run's heading only where its lines resume after another's.

## Do's and Don'ts

- Do keep status colour on marks and status words; result details stay in text colour.
- Do give every status a shape or a word as well as a colour.
- Do add a `Themed(light, dark)` token for any new colour, list it here, and add it to `BackTokens` or `ForeTokens` if a control can hold it.
- Don't use raw colours (`Color.White`, hex literals) in controls.
- Don't use all-caps headings, pills or badges for metadata, hand cursors on buttons, gradients, shadows or emoji.
- Don't print whole lines in status colour or in monospace unless the line is a system value.
- Don't use box-drawing banners for headings; a bold heading and one rule is enough.
