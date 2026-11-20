export const reportStyles = `
:root {
  color-scheme: light;
  --sans:
    "Geist", "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --mono:
    "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --ink: #202330;
  --body: #414652;
  --subtle: #5e6371;
  --paper: #fff;
  --rail: #f6f6f9;
  --line: #dcdde5;
  --rule: #c8cad6;
  --accent: #5145a6;
  --selected: #edecfc;
  --selected-line: #cac7ed;
  --risk: #a33934;
  --possible: #965217;
  --unknown: #805b14;
  --excluded: #18704e;
  --hover: #efeff5;
  --risk-bg: #faeae8;
  --possible-bg: #fff0e6;
  --unknown-bg: #fff4da;
  --excluded-bg: #e7f5ed;
  --role-source: #136254;
  --role-sink: #8c4338;
  --syntax-related: #f1f1fb;
  --mast-height: 2.875rem;
  --rail-width: clamp(13.5rem, 21vw, 19rem);
  --rail-inset: clamp(1rem, 1.65vw, 1.625rem);
  --syntax-bg: #fafafe;
  --syntax-fg: #242636;
  --syntax-subtle: #606274;
  --syntax-highlight: #e8e7ff;
  --syntax-rule: #5341a9;
  --syntax-match-fg: #4a310b;
  --syntax-match: #ffdf96;
  --syntax-keyword: #71368b;
  --syntax-string: #116249;
  --syntax-number: #944017;
  --syntax-property: #26548b;
}

@media screen and (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --ink: #f0eff5;
    --body: #d6d5df;
    --subtle: #b5b3c1;
    --paper: #222226;
    --rail: #1c1c20;
    --hover: #2b2b31;
    --line: #3b3b43;
    --rule: #515159;
    --accent: #cabdff;
    --selected: #36314a;
    --selected-line: #5d507e;
    --risk: #ffa79c;
    --risk-bg: #482927;
    --possible: #ffbd8a;
    --possible-bg: #473226;
    --unknown: #f0cc84;
    --unknown-bg: #413621;
    --excluded: #8ddbb6;
    --excluded-bg: #253c34;
    --role-source: #8bdaca;
    --role-sink: #ffc09f;
    --syntax-bg: #18181c;
    --syntax-fg: #efedf5;
    --syntax-subtle: #b6b4c0;
    --syntax-highlight: #35314d;
    --syntax-related: #272530;
    --syntax-rule: #c8b8ff;
    --syntax-match-fg: #ffe1a7;
    --syntax-match: #5c4724;
    --syntax-keyword: #d2b7ff;
    --syntax-string: #a6dfbe;
    --syntax-number: #ffc996;
    --syntax-property: #9bd5ff;
  }
}

* {
  box-sizing: border-box;
}
html {
  scroll-padding-top: 1rem;
}
body {
  margin: 0;
  background: var(--paper);
  color: var(--ink);
  font: 0.9375rem/1.55 var(--sans);
}
h1,
h2,
h3,
h4,
h5,
h6,
p,
ol,
ul,
dl,
dd,
figure {
  margin: 0;
}
h1,
h2,
h3,
h4,
h5,
h6 {
  font-weight: 600;
  line-height: 1.25;
}
p,
li,
dd,
dt,
summary,
h1,
h2,
h3,
h4,
h5,
h6,
a {
  overflow-wrap: anywhere;
}
p + p {
  margin-top: 0.65em;
}
button,
input,
select,
textarea {
  font: inherit;
  color: inherit;
}
button,
select,
summary {
  cursor: pointer;
}
button,
select,
input {
  accent-color: var(--accent);
}
button:disabled {
  cursor: default;
}
code,
pre,
kbd,
samp {
  font-family: var(--mono);
}
code {
  font-size: 0.91em;
  font-variant-ligatures: none;
}
a {
  color: var(--accent);
  text-underline-offset: 0.17em;
}
strong {
  font-weight: 600;
}
:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 3px;
}
[hidden] {
  display: none !important;
}
.sr-only {
  position: absolute;
  overflow: hidden;
  white-space: nowrap;
  width: 1px;
  height: 1px;
  clip-path: inset(50%);
}

/* The rail and reading surface have independent scroll positions. */
.masthead {
  position: sticky;
  top: 0;
  z-index: 5;
  display: flex;
  align-items: center;
  gap: 1rem;
  padding-inline: var(--rail-inset);
  min-height: var(--mast-height);
  background: var(--paper);
  border-bottom: 1px solid var(--line);
}
.brand {
  flex-shrink: 0;
  color: var(--ink);
  font-size: 1.0625rem;
  font-weight: 650;
  letter-spacing: -0.045em;
}
.product {
  flex-shrink: 0;
  padding-inline-start: 1rem;
  border-inline-start: 1px solid var(--line);
  color: var(--body);
  font-size: 0.875rem;
}
.workspace {
  display: grid;
  grid-template-columns: var(--rail-width) minmax(0, 1fr);
  align-items: start;
}
.rail {
  position: sticky;
  top: var(--mast-height);
  height: calc(100vh - var(--mast-height));
  height: calc(100dvh - var(--mast-height));
  min-width: 0;
  overflow: auto;
  scrollbar-width: thin;
  border-inline-end: 1px solid var(--line);
  background: var(--rail);
}
.rail-toggle {
  display: none;
}
.rail-body {
  padding-block: 1.35rem 2rem;
}
.rail-heading {
  padding-inline: var(--rail-inset);
  margin-bottom: 0.55rem;
  display: flex;
  align-items: baseline;
  gap: 0.625rem;
}
.rail-heading h2,
.rail-toggle {
  font-size: 1rem;
  font-weight: 620;
  letter-spacing: -0.025em;
}
.count {
  font: 0.75rem/1.4 var(--mono);
  color: var(--subtle);
}
.rail-tools {
  position: sticky;
  top: 0;
  z-index: 1;
  background: var(--rail);
  display: grid;
  gap: 0.5rem;
  padding: 0.5rem var(--rail-inset) 0.9rem;
}
.rail-tools input,
.rail-tools select {
  width: 100%;
  min-width: 0;
  height: 2.125rem;
  padding-inline: 0.625rem;
  border: 1px solid var(--rule);
  border-radius: 5px;
  background-color: var(--paper);
  font-size: 0.8125rem;
}
.rail-tools input::placeholder {
  color: var(--subtle);
  opacity: 1;
}
.queue-title {
  padding: 1.1rem var(--rail-inset) 0.55rem;
  color: var(--subtle);
  font: 0.75rem/1.4 var(--mono);
}
.queue-group {
  border-bottom: 1px solid var(--line);
}
.queue-item {
  display: grid;
  gap: 3px;
  padding: 0.95rem var(--rail-inset);
  border-top: 1px solid var(--line);
  color: var(--ink);
  text-decoration: none;
}
.queue-item:hover {
  background-color: var(--hover);
}
.queue-item[aria-current="true"] {
  box-shadow: inset 3px 0 var(--accent);
  background-color: var(--selected);
}
.queue-item[aria-current="true"] .queue-file {
  color: var(--accent);
}
.queue-item:focus-visible {
  outline-offset: -3px;
}
.queue-file {
  font: 600 0.8125rem/1.45 var(--mono);
  letter-spacing: -0.025em;
}
.queue-name {
  color: var(--body);
  font-size: 0.8125rem;
  line-height: 1.45;
}
.queue-context {
  color: var(--subtle);
  font-size: 0.75rem;
  line-height: 1.45;
}
.queue-item .status {
  justify-self: start;
  margin-top: 0.2rem;
  font-size: 0.75rem;
}
.rail [data-empty] {
  padding-inline: var(--rail-inset);
  font-size: 0.8125rem;
  color: var(--subtle);
}
.reader {
  min-width: 0;
  padding: 1.35rem clamp(1.25rem, 2.8vw, 3.25rem) 4rem;
  container-type: inline-size;
}
.reader > * {
  max-width: 68rem;
  margin-inline: auto;
}
.reader [id] {
  scroll-margin-top: calc(var(--mast-height) + 1rem);
}
.advisory + .advisory {
  padding-top: 2rem;
}
.enhanced .advisory + .advisory {
  padding-top: 0;
}

.site-group-title {
  padding: 0.95rem var(--rail-inset) 0.3rem;
  border-top: 1px solid var(--line);
}
.site-group .queue-item {
  padding-block: 0.6rem;
  padding-inline-start: calc(var(--rail-inset) + 0.8rem);
  border: 0;
}
.site-group:not(:has(.queue-item:not([hidden]))) {
  display: none;
}
.site-group:has([aria-current="true"]) > .site-group-title {
  color: var(--accent);
}

/* The advisory sets the question; the finding identifies the particular use. */
.advisory-head {
  padding-bottom: 1rem;
  border-bottom: 1px solid var(--line);
}
.eyebrow {
  color: var(--subtle);
  font: 500 0.75rem/1.45 var(--mono);
}
.advisory-head .eyebrow {
  margin-bottom: 0.4rem;
  color: var(--accent);
}
.advisory-head h1 {
  max-width: 56ch;
  font-size: clamp(1.45rem, 1.85vw, 1.8125rem);
  line-height: 1.16;
  letter-spacing: -0.045em;
  text-wrap: pretty;
}
.overview {
  margin-top: 0.45rem;
  max-width: 81ch;
  color: var(--body);
}
.advisory-more {
  margin-top: 0.65rem;
}
.advisory-more > summary {
  color: var(--accent);
  font-size: 0.8125rem;
}
.finding {
  padding-block: 1.1rem 0;
}
.finding + .finding {
  margin-top: 2rem;
  border-top: 1px solid var(--line);
}
.enhanced .finding + .finding {
  margin-top: 0;
  border-top: 0;
}
.finding-head {
  margin-bottom: 0.95rem;
}
.finding-line {
  display: flex;
  gap: 0.5rem 1rem;
  align-items: center;
  flex-wrap: wrap;
}
.finding-line h2 {
  min-width: 0;
  max-width: 100%;
  font: 570 clamp(1rem, 1.35vw, 1.1875rem)/1.35 var(--mono);
  letter-spacing: -0.045em;
}
.finding-line h2 code {
  font: inherit;
}
.finding-scope {
  margin-top: 0.25rem;
  font-size: 0.8125rem;
  color: var(--subtle);
}
.decision {
  margin-top: 0.45rem;
  max-width: 80ch;
  color: var(--ink);
}
[data-verdict="exploitable"] {
  --signal: var(--risk);
  --signal-bg: var(--risk-bg);
}
[data-verdict="potentially_exploitable"] {
  --signal: var(--possible);
  --signal-bg: var(--possible-bg);
}
[data-verdict="ruled_out"],
[data-condition="ruled_out"] {
  --signal: var(--excluded);
  --signal-bg: var(--excluded-bg);
}
[data-verdict="unknown"],
[data-condition="unknown"] {
  --signal: var(--unknown);
  --signal-bg: var(--unknown-bg);
}
[data-condition="met"] {
  --signal: var(--body);
}
.status,
.condition-state {
  display: inline-flex;
  align-items: baseline;
  gap: 0.44rem;
  color: var(--signal, var(--subtle));
  font: 550 0.8125rem/1.4 var(--sans);
}
.status::before,
.condition-state::before {
  content: "";
  width: 6px;
  height: 6px;
  flex-shrink: 0;
  border-radius: 50%;
  background: currentColor;
  transform: translateY(-1px);
}
.finding-line .status {
  padding: 0.25rem 0.65rem;
  border-radius: 100px;
  background: var(--signal-bg, var(--rail));
}

.input-line {
  margin-top: 0.6rem;
  font-size: 0.8125rem;
  color: var(--body);
}
.input-line strong {
  margin-inline-end: 0.35rem;
}
.input-line code {
  font-size: inherit;
}

.checkout {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 0.25rem 1rem;
  margin-inline-start: auto;
  font-size: 0.8125rem;
  color: var(--subtle);
}
.checkout-repo,
.checkout-commit {
  min-width: 0;
  overflow-wrap: anywhere;
}
.checkout code {
  color: var(--body);
  font-size: 0.75rem;
}
.checkout-commit > summary {
  width: fit-content;
}
.checkout-commit > summary:hover code {
  color: var(--accent);
}
.checkout-commit > code {
  display: block;
  margin-top: 0.25rem;
}

/* Frames stay in order while the reader opens a cited line in place. */
.inspector {
  border: 1px solid var(--rule);
  border-radius: 7px;
  overflow: clip;
}
.inspector-head {
  position: sticky;
  top: var(--mast-height);
  z-index: 1;
  background: var(--paper);
  box-shadow: 0 1px var(--line);
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.75rem;
  padding: 0.72rem 1rem;
}
.inspector-head .eyebrow {
  margin-bottom: 0.15rem;
}
.inspector-head h3,
.conditions h3 {
  font-size: 1.125rem;
  letter-spacing: -0.035em;
}
.inspector-tools {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.35rem;
}
.inspector-tools button {
  border: 1px solid var(--rule);
  border-radius: 5px;
  padding: 0.25rem 0.6rem;
  min-height: 1.875rem;
  background: var(--paper);
  font-size: 0.75rem;
  font-weight: 530;
}
.inspector-tools button:hover:enabled,
.inspector-tools button[aria-pressed="true"] {
  border-color: var(--selected-line);
  color: var(--accent);
  background: var(--selected);
}
.inspector-tools button:disabled {
  opacity: 0.46;
}
.inspector-tools [data-position] {
  padding-inline: 0.25rem;
  color: var(--subtle);
  font: 0.75rem/1.4 var(--mono);
  font-variant-numeric: tabular-nums;
}
.inspector-tools [data-range] {
  margin-inline-end: 0.4rem;
}
.path-list {
  margin: 0;
  padding: 0;
  list-style: none;
}
.frame {
  border-top: 1px solid var(--line);
}
.reader .frame[id],
.frame > summary {
  scroll-margin-top: calc(var(--mast-height) + 7rem);
}
.frame > summary {
  display: grid;
  grid-template-columns: 0.6rem 5.1rem minmax(0, 1fr) minmax(0, auto);
  align-items: baseline;
  column-gap: 0.7rem;
  padding: 0.58rem 1rem;
  list-style: none;
}
.frame > summary::-webkit-details-marker,
.audit > summary::-webkit-details-marker,
.advisory-more > summary::-webkit-details-marker,
.rail-toggle::-webkit-details-marker {
  display: none;
}
.frame > summary::before,
.audit > summary::before,
.advisory-more > summary::before,
.rail-toggle::before {
  content: "";
  width: 0.32rem;
  height: 0.32rem;
  border-block-start: 1.5px solid currentColor;
  border-inline-end: 1.5px solid currentColor;
  color: var(--subtle);
  transform: translateY(-1px) rotate(45deg);
}
.frame[open] > summary::before,
.audit[open] > summary::before,
.advisory-more[open] > summary::before,
.rail-disclosure[open] > .rail-toggle::before {
  transform: translateY(-2px) rotate(135deg);
}
.frame > summary:hover {
  background: var(--rail);
}
.frame > summary:focus-visible {
  outline-offset: -3px;
}
.frame-role {
  font: 520 0.75rem/1.4 var(--sans);
  color: var(--subtle);
}
.frame[data-role="source"] .frame-role {
  color: var(--role-source);
}
.frame[data-role="sink"] .frame-role,
.frame[data-role="query_sink"] .frame-role {
  color: var(--role-sink);
}
.frame-name {
  font: 560 0.875rem/1.45 var(--mono);
  letter-spacing: -0.03em;
}
.frame-location {
  max-width: 28ch;
  color: var(--subtle);
  font: 0.75rem/1.55 var(--mono);
  text-align: end;
}
.frame:has(> summary[aria-current="step"]) {
  border-top-color: var(--selected-line);
}
html:not(.enhanced) .frame[open] > summary,
.frame > summary[aria-current="step"] {
  background: var(--selected);
  box-shadow: inset 3px 0 var(--accent);
}
.frame > summary[aria-current="step"] .frame-name,
.frame > summary[aria-current="step"]::before {
  color: var(--accent);
}
.frame-body {
  border-top: 1px solid var(--selected-line);
  background: var(--syntax-bg);
}
.code-meta {
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.25rem 0.7rem;
  padding: 0.72rem 1rem 0;
  color: var(--subtle);
  font: 0.75rem/1.5 var(--mono);
  overflow-wrap: anywhere;
}
.code-meta code {
  font-size: inherit;
}
.unavailable,
.frame-detail,
.inspector-notes {
  padding: 0.75rem 1.125rem;
  color: var(--body);
  font-size: 0.8125rem;
}
.inspector-notes {
  border-top: 1px solid var(--line);
}
.frame-body p + p {
  margin-top: 0;
}
.gap {
  padding: 0.48rem 1.125rem;
  font-size: 0.75rem;
  color: var(--subtle);
  background: var(--rail);
  border-top: 1px dashed var(--rule);
}

.code-meta a {
  color: inherit;
  text-decoration-color: var(--rule);
}
.code-meta a:hover {
  color: var(--accent);
}
.inspector-tools [data-prev],
.inspector-tools [data-next] {
  min-width: 1.875rem;
}

/* The code listing keeps a stable gutter as the inspected line changes. */
.code-listing {
  margin: 0;
  padding: 14px 0;
  overflow: auto;
  overscroll-behavior-x: contain;
  tab-size: 4;
  font: 0.8125rem/1.75 var(--mono);
  color: var(--syntax-fg);
  background: var(--syntax-bg);
}
.code-listing > code {
  display: block;
  width: max-content;
  min-width: 100%;
  font: inherit;
}
.code-row {
  display: grid;
  grid-template-columns: 4.5ch 1fr;
  gap: 2ch;
  min-height: 1.75em;
  padding-inline: 0 18px;
  white-space: pre;
}
.code-number {
  color: var(--syntax-subtle);
  text-align: end;
  font-variant-numeric: tabular-nums;
  user-select: none;
}
.code-text {
  padding: 0;
}
.code-row[data-related] {
  background-color: var(--syntax-related);
}
.code-row[data-highlighted] {
  box-shadow: inset 3px 0 var(--syntax-rule);
  background-color: var(--syntax-highlight);
}
.code-row[data-highlighted] .code-number {
  color: var(--syntax-rule);
}
.trace-argument {
  border-radius: 2px;
  color: var(--syntax-match-fg);
  background: var(--syntax-match);
}
.trace-argument span {
  color: inherit;
}
.tok-comment {
  color: var(--syntax-subtle);
}
.tok-keyword {
  color: var(--syntax-keyword);
}
.tok-string {
  color: var(--syntax-string);
}
.tok-number,
.tok-literal {
  color: var(--syntax-number);
}
.tok-property {
  color: var(--syntax-property);
}
.code-row:has(> [data-follow]) {
  grid-template-columns: 4.5ch max-content 1fr;
}
[data-follow] {
  display: inline-grid;
  place-items: center;
  justify-self: start;
  align-self: center;
  min-width: 1.5rem;
  min-height: 1.5rem;
  margin-inline-start: 0.45rem;
  padding: 0 0.25rem;
  border: 1px solid var(--selected-line);
  border-radius: 4px;
  background: var(--syntax-bg);
  color: var(--accent);
  font: 600 0.875rem/1 var(--sans);
}
.code-row > [data-follow] {
  margin-inline-start: 0;
}
[data-follow]:hover {
  background: var(--accent);
  color: var(--paper);
}

.conditions {
  margin-top: 1.75rem;
}
.condition-list {
  margin-top: 0.75rem;
  list-style: none;
  padding: 0;
}
.condition-list > li {
  display: grid;
  grid-template-columns: 5.25rem minmax(0, 1fr);
  align-items: baseline;
  gap: 1rem;
  padding-block: 0.78rem;
  border-top: 1px solid var(--line);
  font-size: 0.875rem;
}
.condition-list p {
  margin-top: 0.15rem;
  max-width: 78ch;
  color: var(--body);
}
.audit {
  border-top: 1px solid var(--line);
}
.finding:has(> .inspector:last-child, > .conditions:last-child) {
  margin-block-end: 1.25rem;
}
.inspector + .audit,
.conditions + .audit {
  margin-block: 1.25rem 0;
}
.audit > summary,
.advisory-more > summary {
  display: flex;
  gap: 0.7rem;
  align-items: baseline;
  list-style: none;
  font-weight: 530;
}
.audit > summary {
  padding-block: 0.85rem;
  font-size: 0.875rem;
}
.advisory-more > summary {
  width: fit-content;
}
.audit > summary:hover,
.advisory-more > summary:hover {
  color: var(--accent);
}
.audit-body,
.advisory-more > :not(summary) {
  font-size: 0.875rem;
  color: var(--body);
}
.advisory-more > :not(summary) {
  margin-top: 0.7rem;
}
.audit-body {
  padding: 0.25rem 0 1.5rem;
  overflow-wrap: anywhere;
}
.audit-body h4 {
  font-size: 0.875rem;
  color: var(--ink);
}
.audit-body * + h4 {
  margin-top: 1.25rem;
}
.audit-body h4 + * {
  margin-top: 0.5rem;
}
.audit-body > :where(ul, ol),
.advisory-more > :where(ul, ol) {
  padding-inline-start: 1.2rem;
}
.audit-body li + li {
  margin-top: 0.4rem;
}
.audit-body .code-listing {
  border: 1px solid var(--line);
  border-radius: 4px;
}
.audit-body pre:not(.code-listing) {
  padding: 0.75rem;
  background: var(--rail);
  white-space: pre-wrap;
}
.facts {
  display: grid;
  grid-template-columns: minmax(6rem, 9rem) minmax(0, 1fr);
  gap: 0.4rem 1rem;
  font-size: 0.8125rem;
}
.facts > div {
  display: contents;
}
.facts dt {
  color: var(--subtle);
}
.facts dd {
  color: var(--ink);
}

.condition-refs {
  font: 0.75rem/1.65 var(--mono);
}
.condition-refs a {
  text-decoration-color: var(--selected-line);
}
.deciding-check {
  padding: 0.85rem 0 1.35rem;
}
.deciding-check h3 {
  font-size: 1rem;
  letter-spacing: -0.025em;
}
.deciding-check p {
  margin-top: 0.35rem;
  max-width: 78ch;
  color: var(--body);
  font-size: 0.875rem;
}

@media screen {
  .workspace.is-focused {
    grid-template-columns: minmax(0, 1fr);
  }
  .workspace.is-focused
    :is(
      .rail,
      .audit,
      .conditions,
      .advisory-more,
      .decision,
      .overview,
      .deciding-check
    ) {
    display: none;
  }
  .workspace.is-focused .reader > * {
    max-width: 75rem;
  }
  .workspace.is-focused .advisory-head {
    padding-bottom: 0;
    border: 0;
  }
  .workspace.is-focused .advisory-head h1 {
    font-size: 1rem;
    max-width: none;
  }
  .workspace.is-focused .finding {
    padding-top: 0.6rem;
  }
}
@container (max-width: 38rem) {
  .frame > summary {
    grid-template-columns: 0.6rem 4.5rem minmax(0, 1fr);
  }
  .frame-location {
    grid-column: 3;
    text-align: start;
    max-width: none;
  }
  .finding-line {
    align-items: baseline;
  }
}
@media (max-width: 720px) {
  :root {
    --mast-height: 3rem;
    --rail-inset: 1.2rem;
  }
  .masthead {
    position: static;
    flex-wrap: wrap;
    row-gap: 0.25rem;
    padding-block: 0.65rem;
  }
  .checkout {
    flex-basis: 100%;
  }
  .inspector-head {
    top: 0;
  }
  .workspace {
    display: block;
  }
  .rail {
    height: auto;
    position: static;
    border-inline-end: 0;
    border-bottom: 1px solid var(--line);
  }
  .rail-toggle {
    display: flex;
    align-items: baseline;
    gap: 0.7rem;
    list-style: none;
    padding: 0.72rem var(--rail-inset);
    font-size: 0.875rem;
  }
  .rail-heading {
    display: none;
  }
  .rail-body {
    padding: 0;
  }
  .rail-body nav {
    max-height: 45vh;
    overflow: auto;
  }
  .rail-tools {
    grid-template-columns: 1fr 1fr;
    padding-bottom: 0.75rem;
  }
  .rail-tools input,
  .rail-tools select {
    font-size: 1rem;
    height: 2.5rem;
  }
  .queue-group:last-child {
    border-bottom: 0;
  }
  .reader {
    padding: 1.4rem var(--rail-inset) 3rem;
  }
}
@media (max-width: 450px) {
  :root {
    --rail-inset: 1rem;
  }

  .advisory-head h1 {
    font-size: 1.5rem;
  }
  .inspector-head {
    padding: 0.8rem;
  }
  .frame > summary {
    padding: 0.7rem 0.8rem;
    column-gap: 0.5rem;
    grid-template-columns: 0.45rem 3.75rem minmax(0, 1fr);
  }
  .frame-location {
    grid-column: 3;
    max-width: none;
    text-align: start;
  }
  .code-meta,
  .frame-detail,
  .gap,
  .unavailable,
  .inspector-notes {
    padding-inline: 0.8rem;
  }
  .condition-list > li {
    grid-template-columns: 4.65rem 1fr;
    gap: 0.65rem;
  }
  .facts {
    grid-template-columns: 1fr;
    gap: 0;
  }
  .facts dd + dt {
    margin-top: 0.45rem;
  }
}
@container (max-width: 36rem) {
  .code-listing > code {
    width: auto;
  }
  .code-row {
    grid-template-columns: 3.5ch minmax(0, 1fr);
    gap: 1.25ch;
    padding-inline-end: 0.7rem;
  }
  .code-row:has(> [data-follow]) {
    grid-template-columns: 3.5ch minmax(0, 1fr) auto;
  }
  .code-text {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
}
@media (pointer: coarse) {
  .inspector-tools button {
    min-height: 2.5rem;
  }
}
@media (forced-colors: active) {
  .queue-item[aria-current="true"],
  .frame[open] > summary,
  .code-row[data-highlighted] {
    outline: 2px solid Highlight;
    outline-offset: -2px;
  }
}
@media print {
  .rail,
  .inspector-tools,
  [data-follow],
  [data-no-results] {
    display: none !important;
  }
  .masthead {
    position: static;
    min-height: auto;
    padding: 0 0 0.65rem;
  }
  .inspector-head {
    position: static;
  }
  .workspace {
    display: block;
  }
  .reader {
    padding: 1.25rem 0;
    container-type: normal;
  }
  .reader > * {
    max-width: none;
  }
  .advisory[hidden],
  .finding[hidden],
  .frame[hidden],
  .gap[hidden] {
    display: block !important;
  }
  .advisory + .advisory {
    break-before: page;
  }
  .enhanced .finding + .finding {
    margin-top: 1.25rem;
    border-top: 1px solid var(--rule);
  }
  h1,
  h2,
  h3,
  h4,
  summary,
  .inspector-head {
    break-after: avoid;
  }
  .frame > summary,
  .condition-list > li,
  .code-row {
    break-inside: avoid;
  }
  details::details-content {
    content-visibility: visible;
  }
  .audit > summary::before,
  .advisory-more > summary::before,
  .frame > summary::before {
    visibility: hidden;
  }
  .frame,
  .inspector,
  .code-listing {
    overflow: visible;
  }
  .code-listing > code {
    width: auto;
  }
  .code-row:has(> [data-follow]) {
    grid-template-columns: 4.5ch 1fr;
  }
  .code-text {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .code-row[data-highlighted] {
    border-inline-start: 2px solid var(--accent);
  }
  .trace-argument {
    font-weight: bold;
    text-decoration: underline;
  }
}
`;
