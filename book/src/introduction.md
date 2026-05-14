# Introduction

**Varta** is a zero-dependency, zero-allocation health protocol designed for distributed local agents and networked clusters.

## The Problem: "The Observer Gap"

In high-performance or safety-critical systems, monitoring process health is often surprisingly expensive or dangerously imprecise. 
- **Expensive**: Monitoring agents that consume 5-10% CPU just to check if others are alive.
- **Imprecise**: TCP-based health checks that fail due to network congestion, not process failure.
- **Fragile**: Monitoring systems that crash when the target process panics or deadlocks.

## The Varta Philosophy: "Zero-Everything"

Varta was built to bridge this gap by providing a protocol that is:
- **Zero Dependencies**: Production crates have empty `[dependencies]` sections.
- **Zero Allocations**: After initialization, the beat path never touches the heap.
- **Zero Block**: The agent never waits for the observer. If the observer is busy, the heartbeat is simply dropped.

## How it Works

1. **Agents** emit a 32-byte fixed-layout frame (VLP) over a Unix Domain Socket or UDP.
2. **The Observer** (`varta-watch`) polls these frames, tracks per-pid state machines, and triggers recovery actions if a "stall" is detected.

Ready to get started? Check out the [Installation](./installation.md) guide.
