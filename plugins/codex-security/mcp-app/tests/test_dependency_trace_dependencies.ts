import assert from "node:assert/strict";
import test from "node:test";
import {
  dependencyEvidence,
  isDependencyManifest,
} from "../src/dependency-trace/dependencies.ts";

test("a manifest declares a dependency at the actual key, including in compact JSON", () => {
  const source = "apps/viewer/package.json";
  const name = "@example/codec";
  for (const map of [
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
  ]) {
    const manifest = {
      scripts: { [name]: "test" },
      [map]: { [name]: "^2.1.0" },
    };
    for (const [indent, line] of [
      [0, 1],
      [2, 6],
    ]) {
      assert.deepEqual(
        dependencyEvidence(
          JSON.stringify(manifest, null, indent),
          source,
          name,
        ),
        [
          {
            source,
            line,
            step: {
              from: { kind: "file", name: source },
              relation: "depends_on",
              to: { kind: "package", name, scope: source },
            },
          },
        ],
      );
    }
  }
});

test("duplicate declarations share a manifest while other copies keep their own identity", () => {
  const manifest =
    '{"devDependencies":{"codec":"^1"},"dependencies":{"codec":"2"}}';
  const copies = ["a/package.json", "b/package.json"].flatMap((file) =>
    dependencyEvidence(manifest, file, "codec"),
  );
  assert.deepEqual(
    copies.map(({ step }) => step.to?.scope),
    ["a/package.json", "b/package.json"],
  );
});

test("the declared key distinguishes package identities on a shared source line", () => {
  const file = "package.json";
  const compact =
    '{"dependencies":{"codec":"^2","renderer":"1"},"scripts":{"preview":"codec"}}';
  for (const name of ["codec", "renderer"]) {
    const [fact] = dependencyEvidence(compact, file, name);
    assert.equal(fact?.line, 1);
    assert.deepEqual(fact?.step.to, { kind: "package", name, scope: file });
  }
  assert.deepEqual(dependencyEvidence(compact, file, "preview"), []);
});

test("line citations follow effective JSON keys, including escaped and duplicate names", () => {
  const contents = [
    '{"dependencies":{"codec":"1"},',
    '"description":"examples like {\\"codec\\":null}",',
    '"dependencies":{"codec":"2",',
    '"\\u0063odec":',
    '"^3"},',
    '"nested":[{"codec":"example"}]}',
  ].join("\n");
  const [fact] = dependencyEvidence(contents, "package.json", "codec");
  assert.equal(fact?.line, 4);
});

test("npm evidence requires a direct dependency key and a strict manifest", () => {
  for (const contents of [
    '{"name":"codec","description":"depends on codec","scripts":{"codec":"codec"}}',
    '{"packages":{"":{"dependencies":{"codec":"1"}}}}',
    '{"overrides":{"codec":"1"},"dependencies":{"other":"npm:codec@^2","codec-extra":"3"}}',
    '{"dependencies":{"codec":"npm:other@1"}}',
    '{"dependencies":{"codec":"file:../other"}}',
    '{"dependencies":{"codec":"other.tgz"}}',
    '{"dependencies":{"codec":{"version":"1"}}}',
    '{"dependencies":{"codec":"1"},}',
    '{"dependencies":{"codec":"1"},"dependencies":{}}',
    'dependencies: {codec: "1"}',
    "null",
  ]) {
    assert.deepEqual(
      dependencyEvidence(contents, "package.json", "codec"),
      [],
      contents,
    );
  }
  assert.deepEqual(
    dependencyEvidence('{"dependencies":{}}', "package.json", "constructor"),
    [],
  );
  for (const file of ["package-lock.json", "README.md", "Dockerfile.txt"]) {
    assert.equal(isDependencyManifest(file), false);
    assert.deepEqual(
      dependencyEvidence('{"dependencies":{"codec":"1"}}', file, "codec"),
      [],
    );
  }
});

test("a build declares one package per explicit installing stage and consuming file", () => {
  const recipe = [
    "FROM debian:stable AS build",
    "RUN apt-get install -y xz-utils ffmpeg",
    "RUN apt-get install ffmpeg",
    "FROM alpine",
    "RUN apk add --no-cache ffmpeg",
    "FROM scratch AS final",
    "COPY --from=build /work/output /app",
  ].join("\n");
  const files = ["apps/video/Dockerfile", "tools/Containerfile"];
  const copies = files.flatMap((file) =>
    dependencyEvidence(recipe, file, "ffmpeg"),
  );
  assert.deepEqual(
    copies,
    files.flatMap((file) =>
      [
        [2, "stage build", `${file}#FROM line 1`],
        [5, "stage at line 4", `${file}#FROM line 4`],
      ].map(([line, name, scope]) => ({
        source: file,
        line,
        step: {
          from: { kind: "build", name, scope },
          relation: "depends_on",
          to: { kind: "package", name: "ffmpeg", scope },
        },
      })),
    ),
  );
});

test("only complete literal RUN instructions in a known stage yield build facts", () => {
  for (const directive of [
    "# RUN apt-get install ffmpeg",
    "CMD apt-get install ffmpeg",
    "ONBUILD RUN apt-get install ffmpeg",
    'LABEL example="RUN apt-get install ffmpeg"',
    "RUN echo apt-get install ffmpeg",
    "RUN sh -c 'apt-get install ffmpeg'",
    'RUN ["echo","apt-get install ffmpeg"]',
    "RUN if true; then apt-get install ffmpeg; fi",
    "RUN apt-get update && apt-get install ffmpeg",
    "RUN apt-get install ffmpeg && echo done",
    "RUN apt-get install ffmpeg | cat",
    "RUN apt-get install ffmpeg # optional",
    "RUN apt-get install -s ffmpeg",
    "RUN apt-get install ffmpeg-",
    "RUN apt-get install ffmpeg-tools",
    "RUN apk add $PKG ffmpeg",
    "RUN apk add --virtual ffmpeg",
    "RUN apk add `echo ffmpeg`",
    "COPY <<EOF /example\nRUN apt-get install ffmpeg\nEOF",
    "RUN cat <<'EOF'\nRUN apt-get install ffmpeg\nEOF",
    "LABEL example=\\\nRUN apt-get install ffmpeg",
    'SHELL ["/bin/echo"]\nRUN apt-get install ffmpeg',
    "FROM ${BASE}\nRUN apt-get install ffmpeg",
    "An example:\n```dockerfile\nFROM debian\nRUN apt-get install ffmpeg\n```",
  ]) {
    assert.deepEqual(
      dependencyEvidence("FROM debian\n" + directive, "Dockerfile", "ffmpeg"),
      [],
      directive,
    );
  }
  assert.deepEqual(
    dependencyEvidence("RUN apt-get install ffmpeg", "Containerfile", "ffmpeg"),
    [],
  );
  assert.deepEqual(
    dependencyEvidence(
      "FROM debian\nRUN apt-get install ffmpeg",
      "notes.md",
      "ffmpeg",
    ),
    [],
  );
  assert.deepEqual(
    dependencyEvidence(
      "# escape=`\nFROM windows\nLABEL x=`\nRUN apt-get install ffmpeg",
      "Dockerfile",
      "ffmpeg",
    ),
    [],
  );
});

test("reported build evidence survives an unsupported instruction later in the file", () => {
  const recipe = [
    "# syntax=docker/dockerfile:1",
    "FROM debian AS tools",
    "RUN apt-get install -y ffmpeg",
    "FROM scratch",
    "COPY <<EOF /example",
    "RUN apt-get install ffmpeg",
    "EOF",
  ].join("\n");
  const facts = dependencyEvidence(recipe, "Dockerfile", "ffmpeg");
  assert.deepEqual(
    facts.map(({ line }) => line),
    [3],
  );
});
