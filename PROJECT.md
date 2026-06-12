# ARX Ecosystem - arx-dns

This repository is a sub-project of the **ARX** ecosystem.

## Architecture Philosophy

ARX is a decentralized, self-hosted network and identity management platform. The architecture is strictly modular.

## Module Scope: arx-dns

An enterprise-grade, universal DNS server built from scratch. It functions as a high-concurrency authoritative server, recursive resolver, and DNS firewall.

## Core Directives

- **Performance First:** Built in Go with system-level I/O optimization and zero-allocation packet parsing where possible.
- **Deployment:** Native binary execution, designed to scale across multi-core container nodes.
- **Data Sovereignty:** Operates entirely locally. Eliminates reliance on external upstream resolvers when running in full recursive mode.
