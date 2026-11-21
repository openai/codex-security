import os

from starlette.applications import Starlette
from starlette.datastructures import UploadFile
from starlette.requests import Request, parse_options_header
from starlette.responses import JSONResponse, Response
from starlette.routing import Route


async def inspect_clip(request: Request) -> Response:
    async with request.form(max_fields=8, max_part_size=65536) as form:
        audio = form.get("audio")
        if not isinstance(audio, UploadFile):
            return Response(status_code=422)
        return JSONResponse({"bytes": audio.size})


api = Starlette(routes=[Route("/clips", inspect_clip, methods=["POST"])])
multipart_only = os.environ["MULTIPART_ONLY"] == "1"


async def gateway(scope, receive, send):
    if scope["type"] == "http" and multipart_only:
        headers = Request(scope).headers
        media_type, _ = parse_options_header(headers.get("content-type"))
        if media_type != b"multipart/form-data":
            return await Response(status_code=415)(scope, receive, send)
    await api(scope, receive, send)
