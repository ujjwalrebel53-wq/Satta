#!/usr/bin/env python3
"""Deploy repo image to CSJMU WordPress when credentials are available."""
import argparse
import http.cookiejar
import mimetypes
import os
import ssl
import sys
import urllib.error
import urllib.request

DEFAULT_IMAGE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "Picsart_26-06-15_13-36-31-059.jpg",
)

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def wp_login(base: str, user: str, password: str):
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPSHandler(context=CTX),
    )
    data = (
        f"log={urllib.request.quote(user)}&pwd={urllib.request.quote(password)}"
        f"&wp-submit=Log+In&redirect_to={urllib.request.quote(base + '/wp-admin/')}"
        f"&testcookie=1"
    ).encode()
    req = urllib.request.Request(
        f"{base}/wp-login.php",
        data=data,
        headers={
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": "wordpress_test_cookie=WP+Cookie+check",
        },
        method="POST",
    )
    r = opener.open(req, timeout=30)
    body = r.read().decode("utf-8", "ignore")
    cookies = {c.name for c in cj}
    if not any("wordpress_logged_in" in k for k in cookies):
        raise RuntimeError("Login failed — no wordpress_logged_in cookie")
    return opener, cj


def upload_media(opener, base: str, image_path: str, title: str = "REBEL INTELLIGENCE"):
    with open(image_path, "rb") as f:
        data = f.read()
    fn = os.path.basename(image_path)
    boundary = "----RebelDeploy"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{fn}"\r\n'
        f"Content-Type: image/jpeg\r\n\r\n"
    ).encode() + data + f"\r\n--{boundary}\r\n".encode()
    body += (
        f'Content-Disposition: form-data; name="title"\r\n\r\n{title}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="status"\r\n\r\ninherit\r\n'
        f"--{boundary}--\r\n"
    ).encode()
    req = urllib.request.Request(
        f"{base}/wp-json/wp/v2/media",
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "Mozilla/5.0",
        },
        method="POST",
    )
    r = opener.open(req, timeout=60)
    import json

    return json.loads(r.read().decode())


def main():
    p = argparse.ArgumentParser(description="Upload repo image to CSJMU WP")
    p.add_argument("--base", default="https://innovation.csjmu.ac.in")
    p.add_argument("--user", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--image", default=DEFAULT_IMAGE)
    args = p.parse_args()

    if not os.path.isfile(args.image):
        print(f"Image not found: {args.image}", file=sys.stderr)
        sys.exit(1)

    print(f"Logging in to {args.base} as {args.user}...")
    opener, _ = wp_login(args.base, args.user, args.password)
    print("Login OK. Uploading media...")
    result = upload_media(opener, args.base, args.image)
    print("Uploaded:", result.get("source_url") or result.get("guid", {}).get("rendered"))
    print("Media ID:", result.get("id"))
    print("\nNext: WP Admin → Appearance → Customize → Site Identity / Header image")
    print("      Or Elementor → Homepage → replace banner images with uploaded URL")


if __name__ == "__main__":
    main()
