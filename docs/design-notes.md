# Design Notes – Password Policy Enforcer

## Threat Model
- Brute-force and credential-stuffing attacks
- Password reuse and weak patterns
- Predictable user-generated passwords

## Design Decisions
- JSON-based policy for flexibility
- Heuristic entropy estimation to avoid heavy dependencies in v1
- Separation of validation logic from CLI

## Limitations
- Entropy estimation is approximate
- No breached-password detection in v1
- No client-side validation

These limitations will be intentionally addressed in future iterations.
