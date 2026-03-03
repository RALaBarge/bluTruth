# 2600/ — Design Notes & Theory Crafting

This directory is for the big-picture thinking: architecture decisions, design philosophy, reference material. Named after the magazine, because good hacks start with understanding the system.

## Files

| File | What's in it |
|---|---|
| `architecture.md` | Overall architecture, every major design decision with the "why", current build state, planned phases |
| `hci_event_taxonomy.md` | Complete breakdown of HCI event types — direction markers, event classification, lifecycle stages, btmon quirks |
| `collector_design.md` | The Collector ABC, capabilities() contract, subprocess pattern, per-collector implementation notes |

## What Belongs Here

- Reasoning behind architectural choices (not just what we did, but why)
- Reference material about the protocols and tools we're instrumenting
- Notes on observability gaps and what it would take to close them
- Design decisions for the Rust port — schema contracts, interface guarantees
- Session notes on interesting things discovered during active debugging

## What Doesn't Belong Here

- Implementation details that are obvious from reading the code
- TODO lists (use issues/FUTURE comments in code)
- Anything that will change frequently (keep that near the code)
