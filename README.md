<p align="center">
<img src="https://github.com/crowdsecurity/crowdsec/raw/master/docs/static/img/crowdsec_logo.png" alt="CrowdSec" title="CrowdSec" width="280" height="300" />
</p>
<p align="center">
<img src="https://img.shields.io/badge/build-pass-green">
<img src="https://img.shields.io/badge/tests-pass-green">
</p>
<p align="center">
&#x1F4DA; <a href="#installation/">Documentation</a>
&#x1F4A0; <a href="https://hub.crowdsec.net">Hub</a>
&#128172; <a href="https://discourse.crowdsec.net">Discourse </a>
</p>

# CrowdSec Envoy Bouncer

A Rust WebAssembly bouncer for Envoy.

## How does it work ?

This bouncer leverages Envoy's proxy-wasm interface using Rust and WebAssembly.

It consists of two WASM modules: an updater that streams decisions from CrowdSec LAPI and distributes them to filter instances, and a filter that processes HTTP requests and blocks banned IPs with a **403** response.

The bouncer supports both IPv4/IPv6 addresses and CIDR ranges, with optional WAF integration for application-layer analysis.

# Installation

Please follow the [official documentation](https://docs.crowdsec.net/docs/bouncers/envoy).