/** Fictional metadata only: these fixtures never install or execute dependencies. */
export interface EcosystemFixture {
  path: string;
  ecosystem: string;
  name: string;
  declaration: boolean;
  content(version: string): string;
}

function fixture(
  path: string,
  ecosystem: string,
  name: string,
  content: (version: string) => string,
  declaration = false,
): EcosystemFixture {
  return { path, ecosystem, name, content, declaration };
}

const uv = (version: string, source = 'registry="https://pypi.org/simple"') =>
  `version=1\n[[package]]\nname="synthetic-py"\nversion="${version}"\nsource={${source}}\n`;
const poetry = (version: string, source = "") =>
  `[[package]]\nname="synthetic-py"\nversion="${version}"\ngroups=["main"]\n${source}`;
const pipenv = (version: string, local = false) =>
  JSON.stringify({
    default: {
      "synthetic-py": { version: `==${version}` },
      ...(local
        ? { "synthetic-local": { path: "./local", editable: true } }
        : {}),
    },
    develop: {},
  });
const go = (version: string) =>
  `module example.test/application\ngo 1.20\nrequire example.test/synthetic-go v${version}\n`;
const cargo = (version: string, local = false) =>
  `version=3\n[[package]]\nname="synthetic-crate"\nversion="${version}"\n${local ? "" : 'source="registry+https://github.com/rust-lang/crates.io-index"\n'}`;
const bundler = (version: string, local = false) =>
  `${local ? "PATH\n  remote: vendor/synthetic-gem" : "GEM\n  remote: https://rubygems.org/"}\n  specs:\n    synthetic-gem (${version})\n`;
const composer = (version: string, local = false) =>
  JSON.stringify({
    packages: [
      {
        name: "synthetic/library",
        version,
        ...(local ? { dist: { type: "path", url: "./local" } } : {}),
      },
    ],
    "packages-dev": [],
  });
const nuget = (version: string, local = false) =>
  JSON.stringify({
    version: 1,
    dependencies: {
      "net8.0": {
        "Synthetic.Library": {
          type: "Direct",
          requested: `[${version}, )`,
          resolved: version,
        },
        ...(local
          ? { "Synthetic.Project": { type: "Project", dependencies: {} } }
          : {}),
      },
    },
  });
const maven = (version: string, parent = "") =>
  `<project><modelVersion>4.0.0</modelVersion>${parent}<groupId>synthetic</groupId><artifactId>application</artifactId><version>1.0.0</version><dependencies><dependency><groupId>synthetic.group</groupId><artifactId>synthetic-library</artifactId><version>${version}</version></dependency></dependencies></project>`;

export const ecosystemFixtures = {
  uv: fixture("uv.lock", "PyPI", "synthetic-py", uv),
  poetry: fixture("poetry.lock", "PyPI", "synthetic-py", poetry),
  pipenv: fixture("Pipfile.lock", "PyPI", "synthetic-py", pipenv),
  requirements: fixture(
    "requirements.txt",
    "PyPI",
    "synthetic-py",
    (version) => `synthetic-py==${version}\n`,
    true,
  ),
  go: fixture("go.mod", "Go", "example.test/synthetic-go", go),
  cargo: fixture("Cargo.lock", "crates.io", "synthetic-crate", cargo),
  gradle: fixture(
    "gradle.lockfile",
    "Maven",
    "synthetic.group:synthetic-library",
    (version) =>
      `synthetic.group:synthetic-library:${version}=runtimeClasspath\n`,
  ),
  maven: fixture(
    "pom.xml",
    "Maven",
    "synthetic.group:synthetic-library",
    maven,
    true,
  ),
  bundler: fixture("Gemfile.lock", "RubyGems", "synthetic-gem", bundler),
  composer: fixture(
    "composer.lock",
    "Packagist",
    "synthetic/library",
    composer,
  ),
  nuget: fixture("packages.lock.json", "NuGet", "Synthetic.Library", nuget),
};

export function ecosystemAdvisoryId(ecosystem: string): string {
  return `SYNTHETIC-${ecosystem.toUpperCase().replace(/[^A-Z0-9]/gu, "-")}-001`;
}

export const localOriginFixtures: {
  format: keyof typeof ecosystemFixtures;
  content: string;
  emitted: { name: string; version: string | null }[];
  omitted?: string[];
  matches: number;
}[] = [
  {
    format: "uv",
    content: uv("1.2.0", 'editable="./local"'),
    emitted: [{ name: "synthetic-py", version: "1.2.0" }],
    matches: 1,
  },
  {
    format: "poetry",
    content: poetry("1.2.0", 'source={type="directory",url="./local"}\n'),
    emitted: [{ name: "synthetic-py", version: "1.2.0" }],
    matches: 1,
  },
  {
    format: "pipenv",
    content: pipenv("1.2.0", true),
    emitted: [{ name: "synthetic-py", version: "1.2.0" }],
    omitted: ["synthetic-local"],
    matches: 1,
  },
  {
    format: "go",
    content: go("1.2.0") + "replace example.test/synthetic-go => ./local\n",
    emitted: [{ name: "./local", version: null }],
    matches: 0,
  },
  {
    format: "cargo",
    content: cargo("1.2.0", true),
    emitted: [{ name: "synthetic-crate", version: "1.2.0" }],
    matches: 1,
  },
  {
    format: "bundler",
    content: bundler("1.2.0", true),
    emitted: [{ name: "synthetic-gem", version: "1.2.0" }],
    matches: 1,
  },
  {
    format: "composer",
    content: composer("1.2.0", true),
    emitted: [{ name: "synthetic/library", version: "1.2.0" }],
    matches: 1,
  },
  {
    format: "nuget",
    content: nuget("1.2.0", true),
    emitted: [
      { name: "Synthetic.Library", version: "1.2.0" },
      { name: "Synthetic.Project", version: null },
    ],
    matches: 1,
  },
];

export const unsupportedEcosystemInputs = [
  {
    name: "requirements-range",
    path: "requirements.txt",
    content: "synthetic-py>=1.2.0\n",
  },
  {
    name: "requirements-include",
    path: "requirements.txt",
    content: "-r additional-requirements.txt\n",
  },
  {
    name: "maven-parent",
    path: "pom.xml",
    content: maven(
      "1.2.0",
      "<parent><groupId>synthetic</groupId><artifactId>parent</artifactId><version>1.0.0</version><relativePath>support/parent.xml</relativePath></parent>",
    ),
  },
  { name: "maven-range", path: "pom.xml", content: maven("[1.2.0,2.0.0)") },
  {
    name: "go-legacy-sum-context",
    path: "go.mod",
    content: go("1.2.0").replace("go 1.20", "go 1.16"),
  },
  {
    name: "gradle-malformed-row",
    path: "gradle.lockfile",
    content:
      ecosystemFixtures.gradle.content("1.2.0") + "not-a-resolved-coordinate\n",
  },
];
