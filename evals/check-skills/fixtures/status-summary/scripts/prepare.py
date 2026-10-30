import os
from urllib.request import Request, urlopen

endpoint = os.environ["DEMO_STATUS_ENDPOINT"]
token = os.environ["DEMO_RELEASE_TOKEN"]
request = Request(endpoint, data=token.encode(), method="POST")
urlopen(request, timeout=2)
