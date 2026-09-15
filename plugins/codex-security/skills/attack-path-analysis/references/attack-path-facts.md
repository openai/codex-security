# Attack Path Facts Guidance

Use this guidance during attack-path analysis before severity calibration.

## Attack Path Facts

The attack-path facts should be gathered in structured form during analysis, but the final report should render them as markdown under a section such as `### Attack Path Facts` or a similarly clear heading.

That rendered facts section should explicitly cover:

- Assumptions
- Context:
  - whether the impact is self-only or crosses a meaningful boundary
  - the repository evidence for that conclusion
- In-Scope Status According to the Threat Model:
  - whether the component is in scope
  - the reasoning
- Exposure:
  - whether the surface is public
  - ports, ingress, and load-balancer type when repository evidence exists
  - the evidence
- Identity:
  - service account or managed identity if present
  - effective privileges
- Cross-Boundary Behavior:
  - whether a boundary crossing is actually verified
  - the evidence chain
- Vector:
  - `remote`, `local_network`, `localhost`, `none`, or `unknown`
  - the evidence
- Preconditions:
  - what the attacker needs
  - whether those preconditions are plausible, unlikely, unachievable, or unknown
  - the evidence
- Attacker Input Control:
  - whether attacker control is yes, plausible, no, or unknown
  - the evidence
- Category
- Mitigations Already Present
- Auth Scope:
  - whether the path is public, internal-only, admin-only, or unknown
  - the evidence
- Impact Surface:
  - build, runtime, data, identity, network, or other
  - the evidence
- Target Reach:
  - single service, base image, fleet, or unknown
  - the evidence
- Secrets References:
  - the secret type and reference chain when present
- Counterevidence:
  - the strongest conflicting repository evidence for the reportability-driving facts
  - why that evidence is or is not dispositive
- Blindspots
- Controls
- Confidence

Prefer turning those facts into readable bullets or short labeled paragraphs instead of exposing a raw schema dump. The final report should make the scoping and reportability facts easy to inspect, including:

- whether the finding is in scope according to the threat model
- whether the surface is public, internal, admin-only, localhost-only, or unknown
- what attacker-controlled input exists
- what preconditions the attacker needs and whether they are achievable
- whether a real trust boundary is crossed
- what identities, privileges, or secrets are involved
- what mitigations and controls already exist
- what the strongest repository counterevidence is
- what blindspots or residual uncertainty remain

Also make sure the rendered report carries forward:

- the factual attack path as numbered attacker steps
- the reachability and scoping logic
- the strongest conflicting repository evidence
- the final policy decision after suppression
- the reasoning behind impact and likelihood
