# README screenshots

`run.sh` regenerates `docs/screenshots/*.png` from mock data (the `contoso.com` domain), so the README never shows a real environment.

It builds a harness from the app's own `MainForm.cs` and `Parsers.cs` plus `Shots.cs`, which is a separate entry point. `Shots.cs` fills the Results, Group Policy and Kerberos Tickets tabs with mock data through the app's own rendering methods, then captures each tab. The shipped app is unchanged. The harness runs under Wine on a virtual X display, so it works on a Linux machine with no Windows.

```
tools/screenshots/run.sh
```

Requires: .NET 10 SDK, `wine`, `xvfb-run`, `python3` (with `venv`), `curl`, `unzip` and DejaVu Sans (`fonts-dejavu-core`). The script downloads pinned, checksum-verified copies of Cascadia Code and Selawik, and installs `fonttools` and `pillow` into a private venv. Its working files (Wine prefix, fonts, build) go in `~/.cache/winforms-screenshots`; set `SHOTS_WORK` to use another folder.

The screenshots use the light theme. Passing `dark` as a second argument to the built harness renders the dark theme instead.

Change the mock data in `Shots.cs` (`MockResults`, `MockRsop`, `MockKlist`). The harness reaches the form's private fields and methods by name, so renaming one of those in `MainForm.cs` fails the `ScreenshotHarness_NamesStillExistInMainForm` unit test.

## How it differs from real Windows

- **Fonts:** Segoe UI isn't redistributable, so Selawik (Microsoft's open-source metric-compatible stand-in) takes its place. Cascadia Code is the real font.
- **Controls:** scrollbars and text box borders use Wine's classic style, and the rich text tabs show a horizontal scrollbar that Windows doesn't.

`prep.py` works around two Wine font issues: GDI+ doesn't find Cascadia Code by name, and the rich text control doesn't fall back to another font for glyphs Selawik lacks (`●`, `═`). See the comment at the top of that file.
