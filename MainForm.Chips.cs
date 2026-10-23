using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

#nullable enable
namespace AdDiag;

// A chip: one circle per step, lit with its result; the SMB tab joins them into its connection path (MainForm.Smb.cs).
partial class MainForm
{
    /// <summary>
    /// One chip: a 2px ring with the status mark at its centre and a 14% tint of the status colour behind it; no state
    /// (not run, not reached yet) is a border-colour ring; running is a primary ring open on one side.
    /// </summary>
    void DrawChip(Graphics g, int cx, int cy, int r, Status? state, bool running)
    {
        var circle = new Rectangle(cx - r, cy - r, 2 * r, 2 * r);
        Color tone = ChipTone(state);
        using (var fill = new SolidBrush(state is Status.Pass or Status.Warn or Status.Fail ? Blend(PanelColor, tone, 0.14) : PanelColor))
            g.FillEllipse(fill, circle);
        if (running)
        {
            using var ring = new Pen(AccentColor, S(2));
            g.DrawArc(ring, circle, -90, 280);
            return;
        }
        using var border = new Pen(state == null ? BorderColor : tone, S(2));
        g.DrawEllipse(border, circle);
        if (state is { } s) DrawStatusMark(g, new TestEntry("", s, "-"), cx - S(5), cy - S(5));
    }

    static Color ChipTone(Status? state) => state switch
    {
        Status.Pass => PassColor, Status.Warn => WarnColor, Status.Fail => FailColor, Status.Skip => SkipColor, _ => BorderColor,
    };
}
