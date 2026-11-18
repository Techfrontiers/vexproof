import asyncio
import json
import subprocess
import tempfile
import textwrap
from pathlib import Path

import edge_tts
import imageio_ffmpeg
from PIL import Image, ImageDraw, ImageFont

ROOT_DIR = Path(__file__).resolve().parent.parent
ASSETS_DIR = ROOT_DIR / "assets"

FONT_BOLD = r"C:\Windows\Fonts\segoeuib.ttf"
FONT_REG = r"C:\Windows\Fonts\segoeui.ttf"
FONT_MONO_BOLD = r"C:\Windows\Fonts\consolab.ttf"

VOICE = "en-US-ChristopherNeural"
FFMPEG_EXE = imageio_ffmpeg.get_ffmpeg_exe()

SCENES = [
    {
        "id": 1,
        "badge": "01 / 06  ·  EU CRA & THE SBOM NOISE CRISIS",
        "title": "Stop Triaging Unreachable CVEs Manually",
        "image": "scene1-hero.jpg",
        "narration": (
            "Under the European Union Cyber Resilience Act, software vendors face 24-hour active vulnerability "
            "reporting deadlines. Traditional SBOM scanners flood engineering teams with every CVE in a lockfile, "
            "even for functions never called at runtime, while enterprise reachability tools cost fifteen thousand dollars a year. "
            "Meet VEXProof, built for Kiroween 2026 in the Frankenstein category."
        ),
        "subtitle": (
            "EU Cyber Resilience Act requires rapid CVE proof. VEXProof stitches TypeScript AST call-graphs, "
            "live OSV.dev intel, and Ed25519 OpenVEX signing into one deterministic compiler."
        ),
    },
    {
        "id": 2,
        "badge": "02 / 06  ·  BUILT WITH KIRO (/.kiro)",
        "title": "Spec-Driven Engineering, Hooks & Native MCP",
        "image": "scene2-kiro.png",
        "narration": (
            "Every layer of VEXProof was engineered with Kiro inside our root dot-kiro directory. "
            "Steering files enforce zero-mock verification, EARS specs formalize reachability invariants verified by Vitest, "
            "PostFileSave hooks run compliance guards so dot-kiro is always tracked, "
            "and our native VEXProof MCP server exposes repo scanning directly to the Kiro auditor agent."
        ),
        "subtitle": (
            "Root /.kiro/ hosts Steering, EARS Specs, PostFileSave Hooks, VEX-Auditor Agent, "
            "and VEXProof's native stdio MCP Server (vexproof_scan_repo, vexproof_verify_vex)."
        ),
    },
    {
        "id": 3,
        "badge": "03 / 06  ·  LIVE OSV.DEV + AST CALL-GRAPH TRIAGE",
        "title": "14 Real OSV Alerts Reduced by 57% via Execution Paths",
        "image": "scene3-triage.png",
        "narration": (
            "Scanning our real multi-file gateway against live OSV.dev and FIRST EPSS matches fourteen vulnerabilities "
            "across five packages. VEXProof parses the TypeScript Compiler AST to trace runtime entrypoints, "
            "proving six calls are genuinely reachable like lodash.template and ejs.render with exact file and line evidence, "
            "while suppressing dead code and unused libraries."
        ),
        "subtitle": (
            "Live OSV.dev + TypeScript AST traces entrypoint -> caller -> symbol: 6 Affected proven with source lines, "
            "8 dead-code/unused CVEs suppressed (57% noise eliminated)."
        ),
    },
    {
        "id": 4,
        "badge": "04 / 06  ·  SYMBOL PRECISION & SOUNDNESS GUARD",
        "title": "Safe Subset Proof vs. Dynamic require() Safety Gate",
        "image": "scene4-fintech.png",
        "second_image": "scene4-dynamic.png",
        "narration": (
            "On the left, fintech-worker depends on vulnerable lodash, yet invokes only safe lodash.chunk — achieving "
            "one hundred percent VEX suppression. On the right, legacy-dynamic-plugin uses dynamic require. "
            "Our soundness guard refuses to lie and flags it as under investigation instead of suppressing hidden risk."
        ),
        "subtitle": (
            "Left: Safe lodash.chunk -> 100% Not Affected proof. Right: Dynamic require(moduleName) -> "
            "honest under_investigation guard prevents false negative suppression."
        ),
    },
    {
        "id": 5,
        "badge": "05 / 06  ·  ED25519 SIGNED OPENVEX & TAMPER TEST",
        "title": "Cryptographic Integrity Built for Auditors",
        "image": "scene5-verified.png",
        "second_image": "scene5-tampered.png",
        "narration": (
            "VEXProof compiles canonical OpenVEX version zero-two documents and signs their SHA-256 digest with Ed25519 keys. "
            "When an intact bundle is checked on the left, cryptographic verification succeeds. "
            "Change even one character in a statement on the right, and tamper detection rejects the artifact immediately."
        ),
        "subtitle": (
            "Canonical SHA-256 + Ed25519 signatures verify intact OpenVEX v0.2.0 bundles (left) "
            "and catch 1-byte statement tampering immediately (right)."
        ),
    },
    {
        "id": 6,
        "badge": "06 / 06  ·  MINIMAL SAFE-UPGRADE PR & LIVE SANDBOX",
        "title": "Patch Only What's Reachable — Live at GitHub Pages",
        "image": "scene6-patch.png",
        "narration": (
            "Finally, VEXProof computes the minimum fixed versions strictly for reachable dependencies and generates a clean "
            "package-dot-json diff ready for a pull request, excluding suppressed libraries. "
            "Try the live browser compiler, CLI, or MIT open-source repository on GitHub today."
        ),
        "subtitle": (
            "Minimal Upgrade PR targets only reachable CVEs. Try live: https://techfrontiers.github.io/vexproof/ "
            "| MIT Open Source: https://github.com/Techfrontiers/vexproof"
        ),
    },
]


async def synth_audio(out_dir: Path):
    for s in SCENES:
        mp3_path = out_dir / f"scene_{s['id']:02d}.mp3"
        comm = edge_tts.Communicate(s["narration"], VOICE, rate="+4%")
        await comm.save(str(mp3_path))
        print("Synthesized:", mp3_path.name)


def get_duration(media_path: Path) -> float:
    proc = subprocess.run(
        [FFMPEG_EXE, "-i", str(media_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )
    for line in proc.stderr.splitlines():
        if "Duration:" in line:
            part = line.split("Duration:")[1].split(",")[0].strip()
            h, m, sec = part.split(":")
            return int(h) * 3600 + int(m) * 60 + float(sec)
    return 15.0


def render_slide(scene: dict, out_path: Path):
    W, H = 1920, 1080
    TOP_H = 88
    BOT_H = 128
    VIEW_H = H - TOP_H - BOT_H

    canvas = Image.new("RGBA", (W, H), (8, 11, 16, 255))
    d = ImageDraw.Draw(canvas)

    d.rectangle([(0, 0), (W, TOP_H)], fill=(15, 20, 29, 255))
    d.line([(0, TOP_H), (W, TOP_H)], fill=(35, 45, 63, 255), width=2)

    font_badge = ImageFont.truetype(FONT_MONO_BOLD, 18)
    font_title = ImageFont.truetype(FONT_BOLD, 27)
    font_sub = ImageFont.truetype(FONT_REG, 26)
    font_brand = ImageFont.truetype(FONT_MONO_BOLD, 17)

    bw = int(d.textlength(scene["badge"], font=font_badge)) + 30
    d.rounded_rectangle([(28, 20), (28 + bw, 68)], radius=10, fill=(10, 42, 34), outline=(16, 185, 129), width=2)
    d.text((28 + bw // 2, 44), scene["badge"], font=font_badge, fill=(110, 231, 183), anchor="mm")

    d.text((28 + bw + 24, 44), scene["title"], font=font_title, fill=(230, 237, 247), anchor="lm")

    d.rounded_rectangle([(W - 318, 20), (W - 28, 68)], radius=10, fill=(21, 28, 40), outline=(6, 182, 212), width=2)
    d.text((W - 173, 44), "VEXProof · Frankenstein", font=font_brand, fill=(103, 232, 249), anchor="mm")

    if "second_image" in scene:
        im1 = Image.open(ASSETS_DIR / scene["image"]).convert("RGBA")
        im2 = Image.open(ASSETS_DIR / scene["second_image"]).convert("RGBA")
        panel_w = (W - 72) // 2
        im1.thumbnail((panel_w, VIEW_H - 24), Image.Resampling.LANCZOS)
        im2.thumbnail((panel_w, VIEW_H - 24), Image.Resampling.LANCZOS)
        y1 = TOP_H + (VIEW_H - im1.height) // 2
        y2 = TOP_H + (VIEW_H - im2.height) // 2
        x1 = 24 + (panel_w - im1.width) // 2
        x2 = 48 + panel_w + (panel_w - im2.width) // 2
        canvas.alpha_composite(im1, (x1, y1))
        canvas.alpha_composite(im2, (x2, y2))
        d.rounded_rectangle([(x1 - 2, y1 - 2), (x1 + im1.width + 2, y1 + im1.height + 2)], radius=12, outline=(16, 185, 129), width=3)
        d.rounded_rectangle([(x2 - 2, y2 - 2), (x2 + im2.width + 2, y2 + im2.height + 2)], radius=12, outline=(239, 68, 68), width=3)
    else:
        im = Image.open(ASSETS_DIR / scene["image"]).convert("RGBA")
        scale = min((W - 48) / im.width, (VIEW_H - 16) / im.height)
        nw, nh = int(im.width * scale), int(im.height * scale)
        im_r = im.resize((nw, nh), Image.Resampling.LANCZOS)
        ox = (W - nw) // 2
        oy = TOP_H + (VIEW_H - nh) // 2
        canvas.alpha_composite(im_r, (ox, oy))

    by0 = H - BOT_H
    d.rectangle([(0, by0), (W, H)], fill=(8, 11, 16, 250))
    d.line([(0, by0), (W, by0)], fill=(16, 185, 129, 190), width=3)

    lines = textwrap.wrap(scene["subtitle"], width=96)[:2]
    if len(lines) == 1:
        d.text((W // 2, by0 + BOT_H // 2), lines[0], font=font_sub, fill=(230, 237, 247), anchor="mm")
    else:
        d.text((W // 2, by0 + 42), lines[0], font=font_sub, fill=(230, 237, 247), anchor="mm")
        d.text((W // 2, by0 + 86), lines[1], font=font_sub, fill=(230, 237, 247), anchor="mm")

    canvas.convert("RGB").save(out_path, "PNG")


def build_video():
    out_video = ASSETS_DIR / "vexproof-demo.mp4"

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        asyncio.run(synth_audio(tmp_dir))

        seg_files = []
        for s in SCENES:
            mp3_path = tmp_dir / f"scene_{s['id']:02d}.mp3"
            dur = get_duration(mp3_path)
            slide_png = tmp_dir / f"slide_{s['id']:02d}.png"
            seg_mp4 = tmp_dir / f"seg_{s['id']:02d}.mp4"
            render_slide(s, slide_png)

            cmd = [
                FFMPEG_EXE,
                "-y",
                "-loop", "1",
                "-i", str(slide_png),
                "-i", str(mp3_path),
                "-c:v", "libx264",
                "-tune", "stillimage",
                "-pix_fmt", "yuv420p",
                "-r", "30",
                "-c:a", "aac",
                "-b:a", "192k",
                "-af", "apad",
                "-t", f"{dur + 0.45:.3f}",
                str(seg_mp4),
            ]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            seg_files.append(seg_mp4)
            print(f"Encoded scene {s['id']}: {dur:.2f}s")

        concat_txt = tmp_dir / "concat.txt"
        concat_txt.write_text("\n".join(f"file '{p.as_posix()}'" for p in seg_files), encoding="utf-8")

        subprocess.run(
            [
                FFMPEG_EXE,
                "-y",
                "-f", "concat",
                "-safe", "0",
                "-i", str(concat_txt),
                "-c", "copy",
                str(out_video),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    final_dur = get_duration(out_video)
    size_mb = out_video.stat().st_size / (1024 * 1024)
    print(json.dumps({
        "output": str(out_video),
        "duration_sec": round(final_dur, 2),
        "size_mb": round(size_mb, 2),
        "under_3min": final_dur < 180.0,
    }))


if __name__ == "__main__":
    build_video()
