from io import BytesIO

from PIL import Image


def application(environ, start_response):
    if environ["REQUEST_METHOD"] != "POST" or environ["PATH_INFO"] != "/thumbnail":
        start_response("404 Not Found", [])
        return []
    size = 64 * 64 * 3
    pixels = environ["wsgi.input"].read(size + 1)
    if len(pixels) != size:
        start_response("400 Bad Request", [])
        return []
    output = BytesIO()
    Image.frombytes("RGB", (64, 64), pixels).save(output, format="WEBP", lossless=True)
    start_response("200 OK", [("Content-Type", "image/webp")])
    return [output.getvalue()]
