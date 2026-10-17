"""Command-line scanner. Works even if Streamlit/FastAPI cannot be installed on your server.

  python scan_cli.py url "http://paypal.secure-login.xyz/verify"
  python scan_cli.py message "URGENT: verify your password at http://bit.ly/x"
  python scan_cli.py image screenshot.png
"""
import json
import mimetypes
import sys

from ai.explainer import explain
from scanners.image_scanner import scan_image
from scanners.message_scanner import scan_message
from scanners.url_scanner import scan_url


def main(argv):
    if len(argv) < 3 or argv[1] not in ("url", "message", "image"):
        print(__doc__)
        return 2
    kind, arg = argv[1], argv[2]
    if kind == "url":
        r = scan_url(arg)
    elif kind == "message":
        r = scan_message(arg)
    else:
        try:
            data = open(arg, "rb").read()
        except OSError as e:
            print(f"Cannot read file: {e.strerror}")
            return 1
        r = scan_image(arg, mimetypes.guess_type(arg)[0], data)
    if not r["ok"]:
        print("Error:", r["error"])
        return 1
    exp = explain(r)
    print(f"Risk score: {r['risk_score']}/100  [{r['display_category']}]")
    for i in r["indicators"]:
        print(f"  {i['weight']:+d}  {i['label']}")
    print("\n" + exp["summary"])
    print("Next step:", exp["safest_next_step"])
    print("\nLimitations:\n  - " + "\n  - ".join(r["limitations"]))
    if "--json" in argv:
        print(json.dumps(r, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
