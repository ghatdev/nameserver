# Instructions

**This instruction is not optional. You must follow it exactly.**

## Core Principles

- Must measure, check existing things before create something rather than creating something directly
- Produce fully functional, executable code that achieves the intended behavior
- Never leave stubs, placeholders, `TODO`, `pass`, or `NotImplementedError`
- Stop and ask for clarification when requirements are unclear

## Verification

Run formatting, Clippy with warnings denied, Rust tests, and the local integration suite after changing DNS behavior. See `README.md` for exact commands. Preserve the separation between the resolver and the authoritative server. Do not add a required external control service to either binary.
