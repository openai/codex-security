# Service security policy

This subtree is a supported hosted HTTP service in the synthetic product. Unauthenticated remote requesters control URL paths and query values. This overrides the root policy's trusted-operator assumption for HTTP inputs.

Redirect destinations must remain on the application origin. An untrusted requester selecting an external destination violates that boundary. The service supports both redirect routes defined in `server.js`; their guards must be evaluated from the code rather than their names.
