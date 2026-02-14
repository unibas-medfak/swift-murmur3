import Foundation

// MARK: - Murmur3Hash x64 128-bit
//
// A Swift implementation of Murmur3Hash's 128-bit variant optimized for 64-bit
// platforms. Murmur3Hash is a non-cryptographic hash function designed for high
// throughput. It processes input in 16-byte blocks, mixing two 64-bit state
// variables (h1, h2) that are combined to produce a 128-bit digest.
//
// Performance notes:
// - All hot-path functions use @inline(__always) to eliminate call overhead.
// - Block reads use loadUnaligned to read UInt64 directly from memory instead
//   of assembling bytes one at a time.
// - The streaming API uses inline tuple storage (not heap-allocated arrays) for
//   both the 16-byte block buffer and the 15-byte tail buffer.
// - Data/[UInt8]/String inputs are accessed via withUnsafeBytes to avoid copies.

// MARK: - Core hash primitives

/// 64-bit left rotation. Used throughout the mixing steps to spread bit
/// influence across the full width of each state variable.
@inline(__always)
private func rotl64(_ x: UInt64, r: UInt64) -> UInt64 {
    (x &<< r) | (x &>> (64 &- r))
}

/// Finalization mix for a single 64-bit value. Applies a series of
/// multiply-xorshift steps to ensure all bits of the input affect all bits
/// of the output — eliminates systematic bias from the body rounds.
@inline(__always)
private func fmix64(_ k: UInt64) -> UInt64 {
    var k = k
    k ^= k &>> 33
    k &*= 0xff51_afd7_ed55_8ccd
    k ^= k &>> 33
    k &*= 0xc4ce_b9fe_1a85_ec53
    k ^= k &>> 33
    return k
}

/// Mixing constants chosen by the original Murmur3Hash authors for good
/// avalanche behavior (each input bit affects ~50% of output bits).
private let c1: UInt64 = 0x87c3_7b91_1142_53d5
private let c2: UInt64 = 0x4cf5_ad43_2745_937f

/// Processes one 16-byte block, mixing it into the running hash state (h1, h2).
/// Each block is split into two 64-bit keys (k1, k2) which are independently
/// scrambled with c1/c2 and then folded into h1/h2. The cross-addition
/// (h1 += h2, h2 += h1) ensures that information from both halves propagates
/// to the other, producing good diffusion across the full 128-bit state.
@inline(__always)
private func bodyRound(h1: inout UInt64, h2: inout UInt64, k1: UInt64, k2: UInt64) {
    var k1 = k1
    var k2 = k2

    k1 &*= c1
    k1 = rotl64(k1, r: 31)
    k1 &*= c2
    h1 ^= k1

    h1 = rotl64(h1, r: 27)
    h1 &+= h2
    h1 = h1 &* 5 &+ 0x52dc_e729

    k2 &*= c2
    k2 = rotl64(k2, r: 33)
    k2 &*= c1
    h2 ^= k2

    h2 = rotl64(h2, r: 31)
    h2 &+= h1
    h2 = h2 &* 5 &+ 0x3849_5ab5
}

/// Iterates over all complete 16-byte blocks in the input, reading two UInt64
/// values per block directly from memory using loadUnaligned (which avoids
/// the overhead of byte-by-byte assembly and handles unaligned addresses).
@inline(__always)
private func processBody(_ ptr: UnsafeRawPointer, nblocks: Int, h1: inout UInt64, h2: inout UInt64) {
    for i in 0..<nblocks {
        let k1 = ptr.loadUnaligned(fromByteOffset: i &* 16, as: UInt64.self)
        let k2 = ptr.loadUnaligned(fromByteOffset: i &* 16 &+ 8, as: UInt64.self)
        bodyRound(h1: &h1, h2: &h2, k1: k1, k2: k2)
    }
}

/// Handles the remaining 0–15 bytes that don't fill a complete 16-byte block,
/// then performs finalization. The tail bytes are loaded one at a time and
/// shifted into position within k1 (bytes 0–7) and k2 (bytes 8–14). The
/// fallthrough switch ensures that each case accumulates all bytes at or above
/// its index. Finalization XORs the total length into both halves, adds them
/// together, and applies fmix64 to produce the final 128-bit digest.
@inline(__always)
private func tailAndFinalize(_ tailPtr: UnsafeRawPointer, tailLen: Int, totalLen: Int, h1: inout UInt64, h2: inout UInt64) {
    var k1: UInt64 = 0
    var k2: UInt64 = 0

    switch tailLen {
    case 15:
        k2 ^= UInt64(tailPtr.load(fromByteOffset: 14, as: UInt8.self)) &<< 48
        fallthrough
    case 14:
        k2 ^= UInt64(tailPtr.load(fromByteOffset: 13, as: UInt8.self)) &<< 40
        fallthrough
    case 13:
        k2 ^= UInt64(tailPtr.load(fromByteOffset: 12, as: UInt8.self)) &<< 32
        fallthrough
    case 12:
        k2 ^= UInt64(tailPtr.load(fromByteOffset: 11, as: UInt8.self)) &<< 24
        fallthrough
    case 11:
        k2 ^= UInt64(tailPtr.load(fromByteOffset: 10, as: UInt8.self)) &<< 16
        fallthrough
    case 10:
        k2 ^= UInt64(tailPtr.load(fromByteOffset: 9, as: UInt8.self)) &<< 8
        fallthrough
    case 9:
        k2 ^= UInt64(tailPtr.load(fromByteOffset: 8, as: UInt8.self))
        k2 &*= c2
        k2 = rotl64(k2, r: 33)
        k2 &*= c1
        h2 ^= k2
        fallthrough
    case 8:
        k1 ^= UInt64(tailPtr.load(fromByteOffset: 7, as: UInt8.self)) &<< 56
        fallthrough
    case 7:
        k1 ^= UInt64(tailPtr.load(fromByteOffset: 6, as: UInt8.self)) &<< 48
        fallthrough
    case 6:
        k1 ^= UInt64(tailPtr.load(fromByteOffset: 5, as: UInt8.self)) &<< 40
        fallthrough
    case 5:
        k1 ^= UInt64(tailPtr.load(fromByteOffset: 4, as: UInt8.self)) &<< 32
        fallthrough
    case 4:
        k1 ^= UInt64(tailPtr.load(fromByteOffset: 3, as: UInt8.self)) &<< 24
        fallthrough
    case 3:
        k1 ^= UInt64(tailPtr.load(fromByteOffset: 2, as: UInt8.self)) &<< 16
        fallthrough
    case 2:
        k1 ^= UInt64(tailPtr.load(fromByteOffset: 1, as: UInt8.self)) &<< 8
        fallthrough
    case 1:
        k1 ^= UInt64(tailPtr.load(fromByteOffset: 0, as: UInt8.self))
        k1 &*= c1
        k1 = rotl64(k1, r: 31)
        k1 &*= c2
        h1 ^= k1
    default: break
    }

    // Finalization: fold the total input length into the state, mix the two
    // halves together, and apply fmix64 to eliminate any remaining structure.
    h1 ^= UInt64(totalLen)
    h2 ^= UInt64(totalLen)

    h1 &+= h2
    h2 &+= h1

    h1 = fmix64(h1)
    h2 = fmix64(h2)

    h1 &+= h2
    h2 &+= h1
}

// MARK: - Public API

/// Murmur3Hash x64 128-bit hasher.
///
/// Supports two usage modes:
///
/// **One-shot** — hash an entire input at once via the static methods:
/// ```swift
/// let digest = Murmur3Hash.digest(myData)
/// let hex    = Murmur3Hash.digestHex(myData)
/// ```
///
/// **Streaming** — feed data incrementally, then finalize:
/// ```swift
/// var hasher = Murmur3Hash()
/// hasher.update(chunk1)
/// hasher.update(chunk2)
/// let hex = hasher.digestHex()
/// ```
///
/// The struct uses only inline (stack-allocated) storage — no heap allocations
/// occur during hashing. The 16-byte block buffer is stored as a `(UInt64, UInt64)`
/// tuple, and the 15-byte tail buffer is stored as a 15-element `UInt8` tuple.
public struct Murmur3Hash {

    // Running total of bytes fed into the hasher.
    private var totalLen: Int = 0

    // Two 64-bit state variables that accumulate the hash. Initialized to the
    // seed value and updated by each 16-byte block via bodyRound().
    private var h1: UInt64 = 0
    private var h2: UInt64 = 0

    // Bytes from the current incomplete 16-byte block. When bufferCount reaches
    // 16, the block is processed via bodyRound() and the buffer is emptied.
    // Stored as a tuple of two UInt64s to avoid heap allocation.
    private var bufferCount: Int = 0
    private var buffer: (UInt64, UInt64) = (0, 0)

    // The last 15 bytes of all input seen so far. Murmur3Hash's finalization
    // needs the trailing 0–15 bytes (totalLen % 16) that don't form a complete
    // block. We maintain a rolling window so that digest() can be called at any
    // point without re-scanning the input. Stored as a 15-element UInt8 tuple
    // to keep everything on the stack.
    private var tailBuf = (
        UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0),
        UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0)
    )
    private var tailCount: Int = 0

    public var seed: UInt32 {
        didSet { reset() }
    }

    /// Creates a new hasher with the given seed (default 0).
    public init(_ seed: UInt32 = 0) {
        self.seed = seed
        h1 = UInt64(seed)
        h2 = UInt64(seed)
    }

    /// Resets the hasher to its initial state, preserving the current seed.
    public mutating func reset() {
        totalLen = 0
        h1 = UInt64(seed)
        h2 = UInt64(seed)
        bufferCount = 0
        buffer = (0, 0)
        tailBuf = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        tailCount = 0
    }

    // MARK: - One-shot API
    //
    // These static methods hash an entire input in a single call. They access
    // the raw bytes directly via withUnsafeBytes to avoid intermediate copies.

    /// Hashes a byte array and returns the 128-bit digest as two UInt64 values.
    static public func digest(_ array: [UInt8], seed: UInt32 = 0) -> [UInt64] {
        var h1 = UInt64(seed)
        var h2 = UInt64(seed)

        array.withUnsafeBytes { buf in
            let ptr = buf.baseAddress!
            let nblocks = array.count / 16
            processBody(ptr, nblocks: nblocks, h1: &h1, h2: &h2)
            tailAndFinalize(ptr + nblocks * 16, tailLen: array.count & 15, totalLen: array.count, h1: &h1, h2: &h2)
        }

        return [h1, h2]
    }

    /// Hashes a String by accessing its UTF-8 bytes directly when possible,
    /// falling back to copying into an array for non-contiguous storage.
    static public func digest(_ string: String, seed: UInt32 = 0) -> [UInt64] {
        var h1 = UInt64(seed)
        var h2 = UInt64(seed)

        let utf8 = string.utf8
        utf8.withContiguousStorageIfAvailable { buf in
            let ptr = UnsafeRawPointer(buf.baseAddress!)
            let count = buf.count
            let nblocks = count / 16
            processBody(ptr, nblocks: nblocks, h1: &h1, h2: &h2)
            tailAndFinalize(ptr + nblocks * 16, tailLen: count & 15, totalLen: count, h1: &h1, h2: &h2)
        }
            ?? {
                let arr = Array(utf8)
                let result = digest(arr, seed: seed)
                h1 = result[0]
                h2 = result[1]
            }()

        return [h1, h2]
    }

    /// Hashes a Foundation Data value by accessing its underlying bytes directly.
    static public func digest(_ data: Data, seed: UInt32 = 0) -> [UInt64] {
        var h1 = UInt64(seed)
        var h2 = UInt64(seed)

        data.withUnsafeBytes { buf in
            guard let ptr = buf.baseAddress else { return }
            let count = buf.count
            let nblocks = count / 16
            processBody(ptr, nblocks: nblocks, h1: &h1, h2: &h2)
            tailAndFinalize(ptr + nblocks * 16, tailLen: count & 15, totalLen: count, h1: &h1, h2: &h2)
        }

        return [h1, h2]
    }

    /// One-shot convenience that returns the digest as a 32-character hex string.
    static public func digestHex(_ array: [UInt8], seed: UInt32 = 0) -> String {
        let h = digest(array, seed: seed)
        return String(format: "%016lx%016lx", h[0], h[1])
    }

    /// One-shot convenience that returns the digest as a 32-character hex string.
    static public func digestHex(_ string: String, seed: UInt32 = 0) -> String {
        let h = digest(string, seed: seed)
        return String(format: "%016lx%016lx", h[0], h[1])
    }

    /// One-shot convenience that returns the digest as a 32-character hex string.
    static public func digestHex(_ data: Data, seed: UInt32 = 0) -> String {
        let h = digest(data, seed: seed)
        return String(format: "%016lx%016lx", h[0], h[1])
    }

    // MARK: - Streaming API
    //
    // Feed data in arbitrary-sized chunks via update(), then call digest() or
    // digestHex() to finalize. The hasher maintains a 16-byte block buffer for
    // incomplete blocks and a 15-byte rolling tail window for finalization.
    // You can call digest()/digestHex() multiple times without consuming the
    // state — they snapshot h1/h2 and compute finalization on the copies.

    /// Feeds a Foundation Data chunk into the hasher.
    public mutating func update(_ data: Data) {
        data.withUnsafeBytes { buf in
            guard let baseAddress = buf.baseAddress else { return }
            updateRaw(baseAddress, count: buf.count)
        }
    }

    /// Feeds a byte array chunk into the hasher.
    public mutating func update(_ array: [UInt8]) {
        array.withUnsafeBytes { buf in
            updateRaw(buf.baseAddress!, count: buf.count)
        }
    }

    /// Feeds a String chunk into the hasher via its UTF-8 representation.
    public mutating func update(_ string: String) {
        let utf8 = string.utf8
        utf8.withContiguousStorageIfAvailable { buf in
            updateRaw(UnsafeRawPointer(buf.baseAddress!), count: buf.count)
        }
            ?? {
                update(Array(utf8))
            }()
    }

    /// Core streaming update. Operates directly on a raw pointer to avoid copies.
    ///
    /// Algorithm:
    /// 1. If there are leftover bytes in the block buffer from a previous update,
    ///    try to fill it to 16 bytes. If we can, process that block immediately.
    /// 2. Process as many full 16-byte blocks as possible directly from the input
    ///    pointer — no buffering or copying needed for these.
    /// 3. Copy any remaining bytes (< 16) into the block buffer for next time.
    /// 4. Update the rolling tail window with the last up-to-15 bytes of this chunk.
    private mutating func updateRaw(_ ptr: UnsafeRawPointer, count: Int) {
        totalLen += count
        var offset = 0

        // Step 1: Complete a partial block if one exists from a previous update.
        if bufferCount > 0 {
            let needed = 16 - bufferCount
            if count < needed {
                // Still not enough to fill a block — just append and return.
                withUnsafeMutableBytes(of: &buffer) { bufPtr in
                    (bufPtr.baseAddress! + bufferCount).copyMemory(from: ptr, byteCount: count)
                }
                bufferCount += count
                updateTail(ptr, count: count)
                return
            }
            // Enough data to complete the block — fill, process, and continue.
            withUnsafeMutableBytes(of: &buffer) { bufPtr in
                (bufPtr.baseAddress! + bufferCount).copyMemory(from: ptr, byteCount: needed)
                let k1 = bufPtr.loadUnaligned(fromByteOffset: 0, as: UInt64.self)
                let k2 = bufPtr.loadUnaligned(fromByteOffset: 8, as: UInt64.self)
                bodyRound(h1: &h1, h2: &h2, k1: k1, k2: k2)
            }
            offset = needed
            bufferCount = 0
        }

        // Step 2: Process full 16-byte blocks directly from the input pointer.
        let remaining = count - offset
        let nblocks = remaining / 16
        if nblocks > 0 {
            processBody(ptr + offset, nblocks: nblocks, h1: &h1, h2: &h2)
            offset += nblocks * 16
        }

        // Step 3: Buffer any remaining bytes (0–15) for the next update call.
        let leftover = count - offset
        if leftover > 0 {
            withUnsafeMutableBytes(of: &buffer) { bufPtr in
                bufPtr.baseAddress!.copyMemory(from: ptr + offset, byteCount: leftover)
            }
            bufferCount = leftover
        }

        // Step 4: Maintain the rolling 15-byte tail window for finalization.
        updateTail(ptr, count: count)
    }

    /// Maintains a rolling window of the last 15 bytes seen across all update()
    /// calls. Murmur3Hash finalization needs access to the trailing bytes that
    /// don't form a complete 16-byte block (0 to 15 bytes, i.e. totalLen % 16).
    /// Rather than re-scanning input at digest time, we keep this window updated
    /// incrementally.
    private mutating func updateTail(_ ptr: UnsafeRawPointer, count: Int) {
        if count >= 15 {
            // New chunk is large enough to replace the entire tail window.
            withUnsafeMutableBytes(of: &tailBuf) { tailPtr in
                tailPtr.baseAddress!.copyMemory(from: ptr + count - 15, byteCount: 15)
            }
            tailCount = 15
        }
        else {
            let total = tailCount + count
            if total > 15 {
                // Combined old+new exceeds 15 bytes — shift old bytes left, append new.
                let keep = 15 - count
                withUnsafeMutableBytes(of: &tailBuf) { tailPtr in
                    let base = tailPtr.baseAddress!
                    base.copyMemory(from: base + (tailCount - keep), byteCount: keep)
                    (base + keep).copyMemory(from: ptr, byteCount: count)
                }
                tailCount = 15
            }
            else {
                // Room to simply append the new bytes.
                withUnsafeMutableBytes(of: &tailBuf) { tailPtr in
                    (tailPtr.baseAddress! + tailCount).copyMemory(from: ptr, byteCount: count)
                }
                tailCount += count
            }
        }
    }

    /// Computes the final 128-bit digest from the current streaming state.
    /// This does not consume or modify the hasher — you can continue calling
    /// update() afterward (though the digest will change). Works by copying
    /// h1/h2 to local variables, then applying tail processing and finalization.
    public func digest() -> [UInt64] {
        let tailLen = totalLen & 15
        var h1 = self.h1
        var h2 = self.h2

        // Copy tailBuf to a local so we can take its address without mutating self.
        var tail = tailBuf
        withUnsafeBytes(of: &tail) { tailPtr in
            let offset = tailCount - tailLen
            tailAndFinalize(tailPtr.baseAddress! + offset, tailLen: tailLen, totalLen: totalLen, h1: &h1, h2: &h2)
        }

        return [h1, h2]
    }

    /// Returns the current digest as a 32-character lowercase hex string.
    public func digestHex() -> String {
        let h = digest()
        return String(format: "%016lx%016lx", h[0], h[1])
    }
}
