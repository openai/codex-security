/** Self-contained assets for the offline incident report. No network resources. */
export const reportStyles = `
:root {
  color-scheme: light;
  --ink: #20221f;
  --muted: #626661;
  --line: #dedfd9;
  --paper: #fff;
  --wash: #f7f7f4;
  --accent: #32584c;
  --warn: #8b4b18;
  --red: #9b302b;
  --green: #27634e;
  --mono: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
}
* {
  box-sizing: border-box;
}
html {
  scroll-padding-top: 1.5rem;
}
body {
  margin: 0;
  background: var(--wash);
  color: var(--ink);
  font:
    15px/1.55 system-ui,
    -apple-system,
    BlinkMacSystemFont,
    "Segoe UI",
    sans-serif;
}
a {
  color: inherit;
  text-decoration-color: #abbab2;
  text-underline-offset: 0.17em;
}
button,
input,
select {
  font: inherit;
}
button,
a,
input,
select,
summary {
  outline-offset: 3px;
}
:focus-visible {
  outline: 3px solid #42796a;
}
code {
  font: inherit;
  font-family: var(--mono);
  font-size: 0.88em;
  overflow-wrap: anywhere;
}
p,
ul,
ol,
dl {
  margin: 0;
}
p + p {
  margin-top: 0.65rem;
}
h1,
h2,
h3,
h4 {
  line-height: 1.2;
  letter-spacing: -0.025em;
  margin: 0;
  font-weight: 650;
}
h1 {
  font-size: clamp(1.65rem, 3vw, 2.5rem);
}
h2 {
  font-size: 1.4rem;
}
h3 {
  font-size: 1.1rem;
}
h4 {
  font-size: 0.94rem;
}
small,
.muted {
  color: var(--muted);
}
[hidden] {
  display: none !important;
}
.shell {
  max-width: 1500px;
  margin: auto;
  padding: 0 3.2rem 5rem;
}
.masthead {
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--line);
  padding: 1.35rem 0;
  gap: 1rem;
}
.brand {
  font-weight: 700;
  letter-spacing: -0.025em;
  font-size: 1rem;
}
.brand span {
  color: var(--accent);
}
.report-label {
  color: var(--muted);
  font-size: 0.78rem;
  letter-spacing: 0.07em;
  text-transform: uppercase;
}
.intro {
  padding: 2.4rem 0 1.7rem;
}
.eyebrow {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.11em;
  color: var(--muted);
  font-weight: 700;
  margin-bottom: 0.55rem;
}
.intro p {
  margin-top: 0.6rem;
  color: var(--muted);
  max-width: 64ch;
}
.advisory-tabs {
  display: grid;
  gap: 0.65rem;
  margin: 0 0 1.4rem;
}
.advisory-links,
.view-switch,
.mode-switch {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
}
.view-switch {
  margin: 0 0 1.5rem;
}
.view-switch button,
.mode-switch button {
  border: 1px solid var(--line);
  background: white;
  color: var(--ink);
  border-radius: 4px;
  padding: 0.4rem 0.75rem;
  cursor: pointer;
  font-size: 0.82rem;
  font-weight: 600;
}
.view-switch button[aria-pressed="true"],
.mode-switch button[aria-pressed="true"] {
  background: var(--ink);
  border-color: var(--ink);
  color: white;
}
.advisory-tabs label,
.overview-head label {
  display: grid;
  gap: 0.25rem;
  max-width: 26rem;
  color: var(--muted);
  font-size: 0.8rem;
  font-weight: 600;
}
.advisory-tabs input,
.overview-head input {
  border: 1px solid #899388;
  border-radius: 4px;
  padding: 0.5rem;
  background: white;
  color: var(--ink);
}
.advisory-tabs a {
  font-size: 0.85rem;
  border: 1px solid var(--line);
  border-radius: 5px;
  padding: 0.4rem 0.7rem;
  text-decoration: none;
  background: white;
}
.advisory-tabs a[aria-current="true"] {
  background: var(--ink);
  color: white;
  border-color: var(--ink);
}
.check {
  scroll-margin-top: 1rem;
}
.check-heading {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 1rem;
  padding: 0 0 1rem;
}
.check-heading h2 {
  font-size: 1.15rem;
}
.totals {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem 1.25rem;
  align-items: center;
  padding: 1rem 0 1.3rem;
  border-top: 1px solid var(--line);
}
.metric {
  font-size: 0.86rem;
  color: var(--muted);
}
.metric strong {
  font-size: 1.15rem;
  color: var(--ink);
  font-variant-numeric: tabular-nums;
  margin-right: 0.25rem;
}
.metric.status strong {
  font-size: 1rem;
}
.dot {
  display: inline-block;
  width: 0.43rem;
  height: 0.43rem;
  border-radius: 50%;
  background: currentColor;
  margin-right: 0.4rem;
  vertical-align: 0.12em;
}
.status[data-verdict="unknown"] {
  color: var(--warn);
}
.status[data-verdict="ruled_out"] {
  color: var(--green);
}
.status[data-verdict="exploitable"] {
  color: var(--red);
}
.status[data-verdict="potentially_exploitable"] {
  color: #944323;
}
.coverage-status {
  color: #5b5f82;
}
.brief {
  background: white;
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 1.1rem 1.35rem;
  margin-bottom: 1.5rem;
}
.brief-title {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 0.6rem;
}
.brief p {
  max-width: 100ch;
}
.brief .symbols {
  display: flex;
  gap: 0.4rem;
  flex-wrap: wrap;
  margin-top: 0.8rem;
}
.symbols code {
  background: #eef1ed;
  border-radius: 3px;
  padding: 0.15rem 0.35rem;
}
.brief details {
  margin-top: 0.75rem;
}
.workspace {
  display: grid;
  grid-template-columns: minmax(235px, 285px) minmax(0, 1fr);
  gap: 2.25rem;
  align-items: start;
}
.sidebar {
  position: sticky;
  top: 1rem;
  max-height: calc(100vh - 2rem);
  overflow: auto;
  padding-right: 0.2rem;
}
.service-navigation > summary {
  font-size: 0.84rem;
  font-weight: 700;
  cursor: pointer;
  margin-bottom: 0.75rem;
}
.service-navigation:not([open]) > summary {
  margin-bottom: 0;
}
.filters {
  border-bottom: 1px solid var(--line);
  padding-bottom: 1rem;
  margin-bottom: 0.8rem;
  display: grid;
  gap: 0.55rem;
}
.filters label {
  font-size: 0.74rem;
  font-weight: 650;
  color: var(--muted);
  display: grid;
  gap: 0.2rem;
}
.filters input,
.filters select {
  width: 100%;
  border: 1px solid #899388;
  background: #fff;
  color: var(--ink);
  border-radius: 5px;
  padding: 0.48rem 0.55rem;
  min-width: 0;
}
.service-list {
  display: grid;
  gap: 0.12rem;
  list-style: none;
  padding: 0;
}
.service-link {
  display: block;
  text-decoration: none;
  padding: 0.7rem 0.75rem;
  border-radius: 5px;
  border: 1px solid transparent;
  overflow-wrap: anywhere;
}
.service-link:hover {
  background: #ecefe9;
}
.service-link[aria-current="true"] {
  background: #e7ece7;
  border-color: #70876e;
}
.service-name {
  display: block;
  font-weight: 650;
  font-size: 0.9rem;
}
.service-counts {
  display: block;
  font-size: 0.76rem;
  color: var(--muted);
  margin-top: 0.2rem;
}
.service-exposure {
  display: block;
  color: var(--muted);
  font-size: 0.72rem;
  margin-top: 0.2rem;
}
.service-breakdown {
  display: flex;
  gap: 0.3rem 0.65rem;
  flex-wrap: wrap;
  font-size: 0.72rem;
  margin-top: 0.25rem;
}
.reading {
  min-width: 0;
}
.reading-head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 1rem;
  margin: 0 0 0.85rem;
}
.reading-head p {
  font-size: 0.8rem;
  color: var(--muted);
}
.counting {
  font-size: 0.77rem;
  color: var(--muted);
  margin-bottom: 1rem;
}
.finding {
  background: var(--paper);
  border: 1px solid var(--line);
  border-radius: 7px;
  margin: 0 0 0.65rem;
  scroll-margin-top: 1rem;
  overflow: hidden;
}
.finding > details > summary {
  display: grid;
  grid-template-columns:
    minmax(0, 1.45fr) minmax(0, 1fr) minmax(0, 1fr) minmax(0, 1.35fr)
    1rem;
  gap: 0.85rem;
  cursor: pointer;
  list-style: none;
  padding: 0.8rem 1rem;
}
.triage-heading {
  display: grid;
  grid-template-columns:
    minmax(0, 1.45fr) minmax(0, 1fr) minmax(0, 1fr) minmax(0, 1.35fr)
    1rem;
  gap: 0.85rem;
  padding: 0.4rem 1rem;
  color: var(--muted);
  font-size: 0.72rem;
  font-weight: 700;
}
.triage-row > span {
  min-width: 0;
  font-size: 0.81rem;
  overflow-wrap: anywhere;
}
.triage-row strong {
  font-weight: 650;
  display: block;
}
.triage-secondary {
  display: block;
  color: var(--muted);
  font-size: 0.76rem;
  line-height: 1.4;
  margin-top: 0.22rem;
}
.triage-label {
  display: none;
  color: var(--muted);
  font-size: 0.7rem;
  margin-bottom: 0.2rem;
}
.code-mode {
  display: none;
}
.check[data-mode="code"] .instance-mode {
  display: none;
}
.check[data-mode="code"] .code-mode {
  display: block;
}
.exposure[data-source-exposure="internet"] {
  color: var(--red);
}
.exposure[data-source-exposure="unknown"] {
  color: var(--muted);
}
.finding > details > summary::-webkit-details-marker {
  display: none;
}
.finding > details > summary:after {
  content: "+";
  font-size: 1.1rem;
  align-self: start;
  color: var(--muted);
  grid-column: 5;
  grid-row: 1;
}
.finding > details[open] > summary:after {
  content: "−";
}
.finding > details[open] > summary {
  border-bottom: 1px solid var(--line);
  background: #fdfdfc;
}
.finding-title {
  font-size: 0.9rem;
  font-weight: 680;
  letter-spacing: -0.02em;
  overflow-wrap: anywhere;
  display: block;
}
.service-overview {
  padding: 0.6rem 0 3rem;
}
.overview-head {
  display: flex;
  align-items: end;
  justify-content: space-between;
  gap: 2rem;
  margin-bottom: 1.2rem;
}
.overview-head p {
  color: var(--muted);
  margin-top: 0.4rem;
  max-width: 75ch;
}
.overview-list,
.overview-service ul {
  list-style: none;
  margin: 0;
  padding: 0;
}
.overview-service {
  display: grid;
  grid-template-columns: minmax(12rem, 0.7fr) minmax(0, 2fr);
  gap: 2rem;
  border-top: 1px solid var(--line);
  padding: 1.1rem 0;
}
.overview-service li {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.4rem 0;
  border-bottom: 1px solid #eee;
}
.overview-service li span {
  color: var(--muted);
  font-size: 0.8rem;
  text-align: right;
}
.overview-service li a {
  font-weight: 650;
}
.finding-sub {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.45rem 0.9rem;
  font-size: 0.77rem;
  color: var(--muted);
  margin-top: 0.4rem;
}
.status {
  font-weight: 650;
  font-size: 0.77rem;
  white-space: normal;
}
.body {
  padding: 1.3rem 1.4rem 1.45rem;
  display: grid;
  gap: 1.35rem;
}
.lead {
  font-size: 1rem;
  line-height: 1.55;
  max-width: 90ch;
}
.scope-line {
  display: flex;
  gap: 0.4rem 0.8rem;
  flex-wrap: wrap;
  font-size: 0.78rem;
  color: var(--muted);
}
.scope-line span + span:before {
  content: "·";
  margin-right: 0.8rem;
  color: #a5aaa4;
}
.section-title {
  margin-bottom: 0.55rem;
}
.need {
  border-left: 3px solid #bb854f;
  padding: 0.08rem 0 0.08rem 1rem;
}
.need h4 {
  color: #67441e;
  margin-bottom: 0.6rem;
}
.questions {
  list-style: none;
  padding: 0;
  display: grid;
  gap: 0.9rem;
}
.question {
  font-weight: 650;
}
.question-detail {
  margin-top: 0.3rem;
  font-size: 0.87rem;
  color: #52584f;
}
.question-detail b {
  color: var(--ink);
  font-weight: 650;
}
.fact-list {
  display: grid;
  gap: 0.65rem;
  list-style: none;
  padding: 0;
}
.fact-list li {
  border-top: 1px solid #eceee8;
  padding-top: 0.6rem;
}
.fact-list li:first-child {
  border: 0;
  padding-top: 0;
}
.fact-kind {
  font-size: 0.7rem;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  font-weight: 750;
  color: var(--muted);
  margin-right: 0.5rem;
}
.fact-kind.met {
  color: var(--green);
}
.fact-kind.ruled_out {
  color: var(--green);
}
.fact-kind.unknown {
  color: var(--warn);
}
.fact-explanation {
  color: #50564f;
  font-size: 0.88rem;
  margin-top: 0.2rem;
}
.path {
  display: flex;
  align-items: stretch;
  gap: 0.5rem;
  list-style: none;
  padding: 0;
  overflow-x: auto;
  max-width: 100%;
}
.path li {
  flex: 1;
  min-width: 115px;
  padding: 0.6rem 0.7rem;
  border: 1px solid var(--line);
  border-radius: 4px;
  background: #fafbf8;
  position: relative;
}
.path li + li:before {
  content: "→";
  position: absolute;
  left: -0.5rem;
  transform: translateX(-50%);
  top: 32%;
  background: white;
  color: #848d83;
}
.path small {
  display: block;
  font-size: 0.68rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
.path strong {
  font-size: 0.82rem;
  font-weight: 650;
  overflow-wrap: anywhere;
}
.path a {
  text-decoration: none;
}
.path a:hover {
  text-decoration: underline;
}
.handoff {
  border-left: 2px solid #b0b6c4;
  padding-left: 0.9rem;
}
.handoff > p + p {
  margin-top: 0.45rem;
}
.inspection-list {
  list-style: none;
  padding: 0;
  display: grid;
  gap: 0.75rem;
}
.inspection {
  border-top: 1px solid var(--line);
  padding-top: 0.75rem;
}
.inspection:first-child {
  border: 0;
  padding-top: 0;
}
.inspection-head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 1rem;
}
.outcome {
  font-size: 0.72rem;
  font-weight: 700;
  flex-shrink: 0;
}
.inspection p {
  font-size: 0.87rem;
}
.inspection-target {
  margin: 0.25rem 0;
  color: var(--muted);
  font-size: 0.8rem;
}
.inspection-meta {
  font-size: 0.76rem;
  color: var(--muted);
  margin-top: 0.3rem;
}
.metadata {
  display: grid;
  grid-template-columns: minmax(7.5rem, auto) minmax(0, 1fr);
  gap: 0.35rem 1rem;
  font-size: 0.84rem;
}
.metadata dt {
  color: var(--muted);
}
.metadata dd {
  margin: 0;
  min-width: 0;
  overflow-wrap: anywhere;
}
.disclosure {
  border-top: 1px solid var(--line);
  padding-top: 0.75rem;
}
.disclosure > summary {
  font-weight: 650;
  font-size: 0.86rem;
  cursor: pointer;
}
.disclosure[open] > summary {
  margin-bottom: 0.75rem;
}
.evidence-list {
  list-style: none;
  padding: 0;
  display: grid;
  gap: 0.8rem;
}
.evidence-list > li {
  padding-left: 0.8rem;
  border-left: 2px solid #e4e8e1;
  scroll-margin-top: 1rem;
}
.evidence-ref {
  font-size: 0.8rem;
  color: var(--muted);
}
.source-snippet {
  margin: 0.45rem 0;
}
.source-snippet > summary {
  font: 0.78rem var(--mono);
  cursor: pointer;
}
.code-listing {
  margin: 0.4rem 0 0;
  background: #f5f6f3;
  border: 1px solid #e6e8e1;
  border-radius: 4px;
  overflow: auto;
  padding: 0.55rem 0;
  font: 12px/1.65 var(--mono);
  tab-size: 4;
  color: #303630;
}
.code-row {
  display: flex;
  min-width: max-content;
  padding: 0 0.8rem 0 0;
}
.code-row[data-highlighted] {
  background: #fff0bd;
  box-shadow: inset 3px 0 #ba8c2d;
}
.code-number {
  color: #656b64;
  user-select: none;
  min-width: 3.7em;
  text-align: right;
  padding: 0 0.8rem 0 0.4rem;
}
.code-text {
  white-space: pre;
}
.tok-comment {
  color: #626d5f;
}
.tok-keyword {
  color: #6c3c8b;
  font-weight: 600;
}
.tok-string {
  color: #176344;
}
.tok-number,
.tok-literal {
  color: #975119;
}
.tok-property {
  color: #2b5e7d;
}
.receipt-meta {
  display: flex;
  gap: 0.25rem 0.7rem;
  flex-wrap: wrap;
  font-size: 0.75rem;
  color: var(--muted);
}
.empty {
  padding: 1.5rem;
  border: 1px dashed #cdd2ca;
  border-radius: 6px;
  color: var(--muted);
  background: #fff;
}
.reset {
  border: 1px solid var(--line);
  border-radius: 4px;
  background: #fff;
  padding: 0.35rem 0.65rem;
  cursor: pointer;
  margin-top: 0.7rem;
}
.report-end {
  margin-top: 2rem;
  padding: 1.1rem 0;
  border-top: 1px solid var(--line);
}
.report-end h3 {
  font-size: 0.95rem;
  margin-bottom: 0.6rem;
}
.report-end ul {
  padding-left: 1.1rem;
}
.report-end li {
  margin: 0.35rem 0;
  font-size: 0.86rem;
}
.end-caption {
  color: var(--muted);
  font-size: 0.78rem;
}
.footer {
  border-top: 1px solid var(--line);
  margin-top: 2.5rem;
  padding-top: 1rem;
  color: var(--muted);
  font-size: 0.75rem;
}
.skip {
  position: absolute;
  left: 1rem;
  top: -5rem;
  background: white;
  padding: 0.5rem;
  z-index: 20;
}
.skip:focus {
  top: 1rem;
}
@media (max-width: 1180px) {
  .triage-heading {
    display: none;
  }
  .finding > details > summary {
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    padding-right: 2.5rem;
    position: relative;
  }
  .finding > details > summary:after {
    position: absolute;
    right: 1rem;
    top: 0.7rem;
  }
  .triage-label {
    display: block;
  }
}
@media (max-width: 900px) {
  .shell {
    padding-left: 1.4rem;
    padding-right: 1.4rem;
  }
  .workspace {
    grid-template-columns: minmax(190px, 230px) minmax(0, 1fr);
    gap: 1.25rem;
  }
}
@media (max-width: 650px) {
  body {
    font-size: 14px;
  }
  .shell {
    padding: 0 1rem 3rem;
  }
  .masthead {
    padding: 1rem 0;
    align-items: start;
  }
  .intro {
    padding: 1.6rem 0 1.2rem;
  }
  .workspace {
    display: block;
  }
  .sidebar {
    position: static;
    max-height: none;
    overflow: visible;
    margin-bottom: 1.25rem;
  }
  .service-list {
    display: grid;
    max-height: 45vh;
    overflow: auto;
    gap: 0.2rem;
  }
  .service-list li {
    min-width: 0;
  }
  .filters {
    grid-template-columns: 1fr 1fr;
  }
  .filters label:first-child {
    grid-column: 1/-1;
  }
  .reading-head {
    align-items: start;
    flex-wrap: wrap;
  }
  .finding > details > summary {
    padding: 0.85rem 1rem;
    padding-right: 2.5rem;
  }
  .triage-target,
  .triage-decision {
    grid-column: 1/-1;
  }
  .overview-head {
    display: block;
  }
  .overview-head label {
    margin-top: 1rem;
  }
  .overview-service {
    display: block;
  }
  .overview-service ul {
    margin-top: 0.6rem;
  }
  .overview-service li {
    display: block;
  }
  .overview-service li span {
    display: block;
    text-align: left;
  }
  .body {
    padding: 1rem;
    gap: 1.1rem;
  }
  .metadata {
    grid-template-columns: 1fr;
    gap: 0.1rem;
  }
  .metadata dd {
    margin-bottom: 0.45rem;
  }
  .path {
    flex-direction: column;
  }
  .path li + li:before {
    content: "↓";
    left: 1rem;
    top: -0.6rem;
    transform: none;
  }
  .inspection-head {
    align-items: start;
  }
  .totals {
    gap: 0.4rem 1rem;
  }
}
@media print {
  body {
    background: #fff;
    font-size: 10pt;
  }
  .shell {
    max-width: none;
    padding: 0;
  }
  .masthead,
  .intro {
    padding: 0.5rem 0;
  }
  .workspace {
    display: block;
  }
  .sidebar,
  .filters,
  .advisory-tabs,
  .view-switch,
  .mode-switch,
  .service-overview,
  .triage-heading,
  .reset,
  .skip {
    display: none !important;
  }
  .check[hidden],
  .finding[hidden],
  [data-advisory-view][hidden] {
    display: block !important;
  }
  .finding {
    break-inside: auto;
    border: 1px solid #ddd;
  }
  .finding > details > summary {
    break-after: avoid;
  }
  .body {
    padding: 0.6rem;
  }
  .code-listing {
    white-space: pre-wrap;
  }
  .code-row {
    min-width: 0;
  }
  .code-text {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .footer {
    margin-top: 1rem;
  }
}
`;

export const reportInteractions = `
(() => {
  const checks = [...document.querySelectorAll("[data-check]")];
  const tabs = [...document.querySelectorAll("[data-check-link]")];
  const byAdvisory = document.querySelector("[data-advisory-view]");
  const byService = document.querySelector("[data-service-view]");
  const viewControls = document.querySelector("[data-view-controls]");
  const state = new Map();
  const primaryClick = (event) =>
    event.button === 0 &&
    !event.metaKey &&
    !event.ctrlKey &&
    !event.shiftKey &&
    !event.altKey;
  const setParam = (url, key, value) =>
    value ? url.searchParams.set(key, value) : url.searchParams.delete(key);
  const members = (entry, service) =>
    service === "all" || entry.dataset.services.split(" ").includes(service);
  const plural = (n, one, many) => n + " " + (n === 1 ? one : many);
  const ncounts = (entries) => ({
    uses: entries.filter((e) => e.dataset.kind === "use").length,
    coverage: entries.filter((e) => e.dataset.kind === "coverage").length,
    exposed: entries.filter((e) => e.dataset.exposure === "internet").length,
    unverified: entries.filter((e) => e.dataset.exposure === "unknown").length,
  });
  const countLabel = (c) =>
    plural(c.uses, "reviewed use", "reviewed uses") +
    (c.coverage
      ? " · " + plural(c.coverage, "unresolved item", "unresolved items")
      : "");
  const exposureLabel = (c) =>
    [
      c.exposed ? c.exposed + " internet exposed" : "",
      c.unverified ? c.unverified + " exposure unverified" : "",
    ]
      .filter(Boolean)
      .join(" · ");
  if (viewControls) viewControls.hidden = false;

  for (const check of checks) {
    const controls = check.querySelector("[data-filters]");
    if (!controls) continue;
    const entries = [...check.querySelectorAll("[data-finding]")];
    const text = new Map(
      entries.map((entry) => [entry, entry.textContent.toLocaleLowerCase()]),
    );
    const links = [...check.querySelectorAll("[data-service-link]")];
    const search = controls.querySelector("[data-search]");
    const verdict = controls.querySelector("[data-verdict-filter]");
    const deployment = controls.querySelector("[data-deployment-filter]");
    const exposure = controls.querySelector("[data-exposure-filter]");
    const tag = controls.querySelector("[data-tag-filter]");
    const modeControls = check.querySelector("[data-mode-controls]");
    const navigation = check.querySelector("[data-service-navigation]");
    const heading = check.querySelector("[data-reading-title]");
    const count = check.querySelector("[data-visible-count]");
    const empty = check.querySelector("[data-no-results]");
    const info = {
      check,
      entries,
      links,
      search,
      verdict,
      deployment,
      exposure,
      tag,
      service: "all",
      defaultMode: check.dataset.mode,
      mode: check.dataset.mode,
    };
    state.set(check.id, info);
    controls.hidden = false;
    if (modeControls) modeControls.hidden = false;
    if (matchMedia("(max-width:650px)").matches && navigation)
      navigation.open = false;

    function apply() {
      const q = search.value.trim().toLocaleLowerCase();
      const base = entries.filter(
        (entry) =>
          (!verdict.value ||
            (verdict.value === "unresolved"
              ? entry.dataset.kind === "coverage"
              : entry.dataset.verdict === verdict.value)) &&
          (!deployment.value ||
            entry.dataset.deployment === deployment.value) &&
          (!exposure.value || entry.dataset.exposure === exposure.value) &&
          (!tag?.value || entry.dataset.tags.split(" ").includes(tag.value)) &&
          text.get(entry).includes(q),
      );
      const selected = base.filter((entry) => members(entry, info.service));
      const selectedSet = new Set(selected);
      for (const entry of entries) entry.hidden = !selectedSet.has(entry);
      for (const link of links) {
        const group = base.filter((entry) =>
          members(entry, link.dataset.service),
        );
        const c = ncounts(group);
        const active = link.dataset.service === info.service;
        if (active) link.setAttribute("aria-current", "true");
        else link.removeAttribute("aria-current");
        link.closest("li").hidden =
          !active && link.dataset.service !== "all" && !group.length;
        const label = link.querySelector(".service-counts");
        if (label) label.textContent = countLabel(c);
        const exp = link.querySelector(".service-exposure");
        if (exp) {
          exp.textContent = exposureLabel(c);
          exp.hidden = !exp.textContent;
        }
        for (const status of link.querySelectorAll(
          ".service-breakdown [data-verdict]",
        )) {
          const key = status.dataset.verdict,
            n = group.filter((e) => e.dataset.verdict === key).length;
          const name =
            verdict.querySelector('option[value="' + key + '"]')?.textContent ||
            key;
          status.textContent = n + " " + name;
          status.hidden = !n;
        }
      }
      heading.textContent =
        links.find((link) => link.dataset.service === info.service)?.dataset
          .name || "All services";
      count.textContent = countLabel(ncounts(selected)) + " shown";
      empty.hidden = selected.length > 0;
      check.dataset.mode = info.mode;
      for (const b of modeControls?.querySelectorAll("[data-mode-button]") ||
        [])
        b.setAttribute(
          "aria-pressed",
          String(b.dataset.modeButton === info.mode),
        );
      check.querySelector("[data-target-heading]").textContent =
        info.mode === "code" ? "Operation / call site" : "Instance / target";
      check.querySelector("[data-runtime-heading]").textContent =
        info.mode === "code" ? "Call path" : "Launch / mitigation";
    }
    info.apply = apply;
    function urlForSelection() {
      const url = new URL(location.href);
      url.searchParams.set("check", check.id);
      url.searchParams.set("service", info.service);
      url.searchParams.delete("view");
      for (const [key, value] of [
        ["q", search.value],
        ["verdict", verdict.value],
        ["deployment", deployment.value],
        ["exposure", exposure.value],
        ["tag", tag?.value || ""],
        ["mode", info.mode === info.defaultMode ? "" : info.mode],
      ])
        setParam(url, key, value);
      return url;
    }
    info.url = urlForSelection;
    function syncFilter() {
      apply();
      const url = urlForSelection();
      const target = document.getElementById(
        decodeURIComponent(url.hash.slice(1)),
      );
      if (target?.closest("[data-finding]")?.hidden)
        url.hash = "#reading-" + check.id.slice(6);
      history.replaceState(null, "", url);
    }
    for (const control of [search, verdict, deployment, exposure, tag].filter(
      Boolean,
    ))
      control.addEventListener(
        control === search ? "input" : "change",
        syncFilter,
      );
    check.querySelector("[data-reset]")?.addEventListener("click", () => {
      search.value = "";
      verdict.value = "";
      deployment.value = "";
      exposure.value = "";
      if (tag) tag.value = "";
      syncFilter();
    });
    for (const b of modeControls?.querySelectorAll("[data-mode-button]") || [])
      b.addEventListener("click", () => {
        info.mode = b.dataset.modeButton;
        apply();
        history.replaceState(null, "", urlForSelection());
      });
    for (const link of links)
      link.addEventListener("click", (event) => {
        if (!primaryClick(event)) return;
        event.preventDefault();
        info.service = link.dataset.service;
        apply();
        const url = urlForSelection();
        url.hash = "#reading-" + check.id.slice(6);
        history.pushState(null, "", url);
        if (matchMedia("(max-width:650px)").matches) {
          navigation.open = false;
          heading.setAttribute("tabindex", "-1");
          heading.focus({ preventScroll: true });
          heading.scrollIntoView({ block: "start" });
        }
      });
    for (const entry of entries) {
      const detail = entry.querySelector("details");
      detail.querySelector("summary").addEventListener("click", (event) => {
        if (!primaryClick(event)) return;
        const url = urlForSelection();
        url.hash = detail.open
          ? "#reading-" + check.id.slice(6)
          : "#" + entry.id;
        history.pushState(null, "", url);
      });
    }
  }

  const advisorySearch = document.querySelector("[data-advisory-search]");
  if (advisorySearch) {
    document.querySelector("[data-advisory-controls]").hidden = false;
    advisorySearch.addEventListener("input", () => {
      const q = advisorySearch.value.trim().toLocaleLowerCase();
      let found = 0;
      for (const tab of tabs) {
        tab.hidden = !tab.textContent.toLocaleLowerCase().includes(q);
        if (!tab.hidden) found++;
      }
      document.querySelector("[data-advisory-empty]").hidden = found > 0;
    });
  }
  const serviceSearch = document.querySelector("[data-global-service-search]");
  function filterServices() {
    if (!serviceSearch) return;
    const q = serviceSearch.value.trim().toLocaleLowerCase();
    let n = 0;
    for (const row of document.querySelectorAll("[data-overview-service]")) {
      row.hidden = !row.textContent.toLocaleLowerCase().includes(q);
      if (!row.hidden) n++;
    }
    const empty = document.querySelector("[data-overview-empty]");
    if (empty) empty.hidden = n > 0;
  }
  if (serviceSearch) {
    document.querySelector("[data-global-service-controls]").hidden = false;
    serviceSearch.addEventListener("input", () => {
      filterServices();
      const url = new URL(location.href);
      setParam(url, "serviceq", serviceSearch.value);
      history.replaceState(null, "", url);
    });
  }

  function restore() {
    const url = new URL(location.href);
    let id;
    try {
      id = decodeURIComponent(url.hash.slice(1));
    } catch {
      id = url.hash.slice(1);
    }
    const target = document.getElementById(id);
    const targetCheck = target?.closest("[data-check]");
    const requestedCheck = targetCheck?.id || url.searchParams.get("check");
    const active =
      checks.find((c) => c.id === requestedCheck)?.id || checks[0]?.id;
    const view =
      byService && url.searchParams.get("view") === "service" && !targetCheck
        ? "service"
        : "cve";
    if (byAdvisory) byAdvisory.hidden = view !== "cve";
    if (byService) byService.hidden = view !== "service";
    for (const b of viewControls?.querySelectorAll("[data-view-button]") || [])
      b.setAttribute("aria-pressed", String(b.dataset.viewButton === view));
    for (const c of checks) c.hidden = c.id !== active;
    for (const tab of tabs) {
      if (tab.dataset.checkLink === active)
        tab.setAttribute("aria-current", "true");
      else tab.removeAttribute("aria-current");
    }
    if (serviceSearch) {
      serviceSearch.value = url.searchParams.get("serviceq") || "";
      filterServices();
    }
    const info = state.get(active);
    if (!info) return;
    const requested = url.searchParams.get("service"),
      finding = target?.closest("[data-finding]");
    info.service =
      requested && info.links.some((l) => l.dataset.service === requested)
        ? requested
        : "all";
    if (finding && info.service !== "all" && !members(finding, info.service))
      info.service = "all";
    for (const [key, control] of [
      ["q", info.search],
      ["verdict", info.verdict],
      ["deployment", info.deployment],
      ["exposure", info.exposure],
      ["tag", info.tag],
    ])
      if (control) control.value = url.searchParams.get(key) || "";
    const mode = url.searchParams.get("mode");
    info.mode =
      mode === "code" || mode === "instances" ? mode : info.defaultMode;
    info.apply();
    if (finding?.hidden) {
      for (const c of [
        info.search,
        info.verdict,
        info.deployment,
        info.exposure,
        info.tag,
      ].filter(Boolean))
        c.value = "";
      info.apply();
    }
    if (finding) finding.querySelector("details").open = true;
    for (
      let detail = target?.closest("details");
      detail;
      detail = detail.parentElement?.closest("details")
    )
      detail.open = true;
  }
  for (const b of viewControls?.querySelectorAll("[data-view-button]") || [])
    b.addEventListener("click", () => {
      const url = new URL(location.href);
      if (b.dataset.viewButton === "service") {
        url.searchParams.set("view", "service");
        url.hash = "#services-view";
      } else {
        url.searchParams.delete("view");
        url.hash =
          "#" + (url.searchParams.get("check") || checks[0]?.id || "report");
      }
      history.pushState(null, "", url);
      restore();
    });
  for (const tab of tabs)
    tab.addEventListener("click", (event) => {
      if (!primaryClick(event)) return;
      event.preventDefault();
      const url = new URL(location.href);
      url.search = "";
      url.hash = "#" + tab.dataset.checkLink;
      history.pushState(null, "", url);
      restore();
    });
  for (const link of document.querySelectorAll("[data-overview-link]"))
    link.addEventListener("click", (event) => {
      if (!primaryClick(event)) return;
      event.preventDefault();
      const url = new URL(location.href);
      url.search = "";
      url.searchParams.set("check", link.dataset.checkSelection);
      url.searchParams.set("service", link.dataset.serviceSelection);
      url.hash = "#reading-" + link.dataset.checkSelection.slice(6);
      history.pushState(null, "", url);
      restore();
    });
  addEventListener("popstate", restore);
  addEventListener("hashchange", restore);
  restore();
  let closed = [];
  addEventListener("beforeprint", () => {
    closed = [...document.querySelectorAll("details:not([open])")];
    for (const d of closed) d.open = true;
  });
  addEventListener("afterprint", () => {
    for (const d of closed) d.open = false;
    closed = [];
  });
})();
`;
