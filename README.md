# Murmur3

A pure Swift implementation of MurmurHash3 (x64, 128-bit) with zero heap allocations.

## Features

- **One-shot hashing** — hash `Data`, `[UInt8]`, or `String` in a single call
- **File hashing** — hash files of any size without loading them into memory
- **Streaming** — feed data incrementally via `update()`, finalize with `digest()`
- **No heap allocations** — block and tail buffers use inline tuple storage
- **Configurable seed** — pass a `UInt32` seed to any hashing method

## Usage

### One-shot

```swift
import Murmur3

let hash = Murmur3Hash.digestHex("hello world")
// "35b642a29aed1e590e3f3f1b1073ece4"

let digest = Murmur3Hash.digest([0x01, 0x02, 0x03])
// [UInt64, UInt64]
```

### File hashing

```swift
let hex = try Murmur3Hash.digestHex(fileAt: URL(fileURLWithPath: "/path/to/file"))
```

### Streaming

```swift
var hasher = Murmur3Hash()
hasher.update("hello ")
hasher.update("world")
let hex = hasher.digestHex()
```

You can call `digest()` / `digestHex()` multiple times without consuming the state.

## Installation

Add the package to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/unibas-medfak/swift-murmur3", from: "1.0.0"),
],
targets: [
    .target(
        name: "MyTarget",
        dependencies: ["Murmur3"]
    ),
]
```

## Requirements

- Swift 6.1+

## Acknowledgements

Copyright (c) Daisuke TONOSAKI. Based on [MurmurHash-Swift](https://github.com/daisuke-t-jp/MurmurHash-Swift). Heavily optimized (~25x) by Claude AI — replacing heap-allocated arrays with inline tuple storage, using `loadUnaligned` for direct memory reads, and adding `@inline(__always)` on hot paths.
