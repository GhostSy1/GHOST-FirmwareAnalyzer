import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from tools.ghost_extension import run


def ask(label, default=None, required=True):
    while True:
        suffix = f" [{default}]" if default else ""
        value = input(f"{label}{suffix}: ").strip()
        if value:
            return value
        if default is not None:
            return default
        if not required:
            return ""
        print("A value is required.")


def interactive_args():
    args = ["--input", ask("Input file or directory")]
    args.extend(["--output", ask("JSON report path", "report.json")])
    if True:
        csv_path = ask("CSV report path, leave empty to skip", "", False)
        if csv_path:
            args.extend(["--csv", csv_path])
    if True:
        sarif_path = ask("SARIF report path, leave empty to skip", "", False)
        if sarif_path:
            args.extend(["--sarif", sarif_path])
    if True:
        pdf_path = ask("PDF report path, leave empty to skip", "", False)
        if pdf_path:
            args.extend(["--pdf", pdf_path])
    return args


if __name__ == "__main__":
    if len(sys.argv) > 1 or not sys.stdin.isatty():
        raise SystemExit(run())
    raise SystemExit(run(interactive_args()))
