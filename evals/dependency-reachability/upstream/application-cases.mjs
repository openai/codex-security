import { excerpts } from "./case-data.mjs";

const api = "clips/api.py";
const docker = "clips/Dockerfile";
const compose = "clips/compose.yaml";
const requests = "starlette/requests.py";
const externalProfile = "${MULTIPART_ONLY:?}";

function clipService(profile, port = 8000) {
  return {
    build: { context: "..", dockerfile: docker },
    ports: [`${port}:8000`],
    environment: { MULTIPART_ONLY: profile },
  };
}

const siblingServices = {
  mobile: clipService("0"),
  studio: clipService("1", 8001),
};

function clipCase(id, profile, verdict, service = "clips") {
  const scoped = service !== "clips";
  const services = scoped ? siblingServices : { clips: clipService(profile) };
  return {
    id,
    suite: "application",
    repository: "Kludex/starlette",
    revision: "5f8610c386e13de1d80d36efa961e1486a1d2d01",
    cve: "CVE-2026-54283",
    component: "starlette",
    version: "1.3.0",
    target: "clip-upload",
    ...(scoped ? { expectedService: service } : {}),
    callerScope:
      `Assess POST /clips on the ${service} service launched by the supplied Compose project. ` +
      "An anonymous caller chooses the request headers and body. " +
      "The caller has no other entry point and cannot change service configuration." +
      (scoped
        ? " Name the selected Compose service in the assessed location."
        : ""),
    verdict,
    needsDecidingGap: profile === externalProfile,
    identityEvidence: [
      ...(scoped ? [excerpts(compose, `"${service}": {`)] : []),
      excerpts(compose, '"dockerfile": "clips/Dockerfile"'),
      excerpts(docker, '"clips.api:gateway"'),
      excerpts(api, 'Route("/clips", inspect_clip'),
    ],
    evidenceGroups: [
      excerpts("starlette/__init__.py", '__version__ = "1.3.0"'),
      excerpts(docker, "RUN pip install . python-multipart"),
      excerpts(compose, `"MULTIPART_ONLY": "${profile}"`),
      excerpts(api, 'os.environ["MULTIPART_ONLY"] == "1"'),
      excerpts(api, 'scope["type"] == "http" and multipart_only'),
      ...(profile === "0"
        ? []
        : [
            excerpts(api, 'parse_options_header(headers.get("content-type"))'),
            excerpts(api, 'if media_type != b"multipart/form-data":'),
            excerpts(api, "return await Response(status_code=415)"),
          ]),
      excerpts(api, "await api(scope, receive, send)"),
      excerpts(
        api,
        "async with request.form(max_fields=8, max_part_size=65536)",
      ),
      ...(profile === "1"
        ? []
        : [
            excerpts(api, "if not isinstance(audio, UploadFile):"),
            excerpts(
              requests,
              "form_parser = FormParser(self.headers, self.stream())",
            ),
            excerpts(requests, "self._form = await form_parser.parse()"),
          ]),
      excerpts(
        requests,
        'elif content_type == b"application/x-www-form-urlencoded":',
      ),
    ],
    stage: [
      { kind: "fixture", source: "fixtures/clips/api.py", destination: api },
      {
        kind: "fixture",
        source: "fixtures/clips/Dockerfile",
        destination: docker,
      },
      {
        kind: "json",
        destination: compose,
        value: { services },
      },
    ],
  };
}

export const applicationCases = [
  // Same caller, one setting changes whether the gateway checks the media
  // type before the handler parses the form and inspects its audio field.
  clipCase("clips-handler-validation", "0", "potentially_exploitable"),
  clipCase("clips-gateway-validation", "1", "ruled_out"),
  clipCase("clips-external-profile", externalProfile, "unknown"),
  // Same checkout with both services, only caller scope selects the service.
  clipCase("clips-mobile-caller", "0", "potentially_exploitable", "mobile"),
  clipCase("clips-studio-caller", "1", "ruled_out", "studio"),
];
