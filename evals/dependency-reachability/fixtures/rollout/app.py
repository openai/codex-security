from io import BytesIO

from PIL import Image


def application(environ, start_response):
    if environ["REQUEST_METHOD"] != "POST" or environ["PATH_INFO"] != "/thumbnail":
        start_response("404 Not Found", [])
        return []
    with Image.open(BytesIO(environ["wsgi.input"].read())) as image:
        image.load()
        image.thumbnail((64, 64))
        output = BytesIO()
        image.save(output, format="PNG")
    start_response("200 OK", [("Content-Type", "image/png")])
    return [output.getvalue()]
