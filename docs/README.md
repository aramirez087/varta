# Varta Documentation

The official user-facing documentation has moved to **[The Varta Book](../book/src/introduction.md)**.

## Directory Structure

- `../book/src/`: The source for the mdBook.
- `claude-sessions/`: Internal development logs and design session transcripts.
- `acceptance/`: Historical acceptance criteria and milestones.
- `release/`: Release readiness checklists and history.
- `roadmap/`: Internal handoff notes between development phases.

To build the book locally:

```bash
# Install mdBook
cargo install mdbook

# Build and serve
mdbook serve ../
```
