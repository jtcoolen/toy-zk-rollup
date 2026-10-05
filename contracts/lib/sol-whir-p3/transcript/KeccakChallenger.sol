// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library KeccakChallenger {
    uint256 internal constant KOALABEAR_MODULUS = 0x7f000001;
    uint256 internal constant KOALABEAR_SAMPLE_MASK = 0x7fffffff;
    uint256 internal constant DIGEST_BYTES = 32;
    uint256 internal constant INITIAL_CAPACITY = 64;

    struct State {
        bytes inputBuffer;
        uint256 inputLen;
        bytes32 outputBlock;
        uint256 outputIndex;
    }

    function observeBytes(State memory self, bytes memory data) internal pure {
        self.outputIndex = 0;
        _appendBytes(self, data);
    }

    function observeBytesCalldata(
        State memory self,
        bytes calldata data,
        uint256 offset,
        uint256 len
    ) internal pure {
        self.outputIndex = 0;
        _appendBytesCalldata(self, data, offset, len);
    }

    function observeBase(State memory self, uint256 value) internal pure {
        require(value < KOALABEAR_MODULUS, "BASE_RANGE");
        // Any buffered output is now invalid: p3 HashChallenger::observe clears the
        // output buffer, so the next sample flushes rather than resuming a block that
        // was produced before this value existed. observeBytes already does this;
        // observeBase omitted it, which desynchronised every later sample after an
        // observe-follows-sample. Pinned by contracts/test/WhirSemanticProgram.t.sol.
        self.outputIndex = 0;
        _appendBaseLE(self, uint32(value));
    }

    /// Absorb `nWords` field words from `data` (starting at byte `off`, four
    /// bytes per word, stored as the prover transcript wrote them) in one pass.
    ///
    /// Byte-identical to `nWords` sequential `observeBase` calls on the same
    /// values: each word is range-checked against the KoalaBear modulus and
    /// appended little-endian, and the output buffer is invalidated once up
    /// front (every per-word append would do it anyway). The per-word Solidity
    /// call, require, and capacity machinery collapse into one assembly loop -
    /// the WHIR verifier absorbs framing constants in bulk through here, where
    /// the per-element overhead dominated the initial phase transcript cost.
    error BasesRange();

    function observeBasesLE(
        State memory self,
        bytes memory data,
        uint256 off,
        uint256 nWords
    ) internal pure {
        if (off + nWords * 4 > data.length) {
            revert BasesRange();
        }
        // An empty absorb must be a no-op, exactly like the per-word loop it
        // replaces: zero appends never invalidated the buffered output block.
        if (nWords == 0) {
            return;
        }
        self.outputIndex = 0;
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + nWords * 4;
        _ensureCapacity(self, newLen);
        bytes memory buffer = self.inputBuffer;
        uint256 p = KOALABEAR_MODULUS;
        assembly ("memory-safe") {
            let src := add(add(data, 0x20), off)
            let dst := add(buffer, add(0x20, oldLen))
            let end := add(src, shl(2, nWords))
            for { } lt(src, end) { } {
                // The blob stores each word little-endian; the top four bytes of
                // the aligned load are the word in big-endian order.
                let be := shr(224, mload(src))
                // The range check is on the VALUE the old per-word path checked:
                // the little-endian interpretation of the stored bytes (the old
                // path byte-swapped the aligned load before observeBase).
                let v := or(
                    shr(24, be),
                    or(
                        and(shr(8, be), 0xff00),
                        or(and(shl(8, be), 0xff0000), shl(24, and(be, 0xff)))
                    )
                )
                if iszero(lt(v, p)) {
                    mstore(0, 0x454e5200) // ENR0 - out-of-range base word
                    revert(0, 4)
                }
                mstore(dst, shl(224, be))
                src := add(src, 4)
                dst := add(dst, 4)
            }
        }
        self.inputLen = newLen;
    }

    /// Absorb one packed extension element - four canonical limbs at bits
    /// 224/192/160/128 - as four Montgomery-converted base words in one pass.
    ///
    /// Byte-identical to four `observeBase(toMontgomery(limb))` calls: each
    /// limb is reduced mod p (which also enforces the range check the per-word
    /// path performed), converted with the Montgomery factor, and appended
    /// little-endian. The low 128 bits of `packed` are padding and ignored.
    function observeExt4Mont(State memory self, uint256 packed) internal pure {
        self.outputIndex = 0;
        uint256 oldLen = self.inputLen;
        _ensureCapacity(self, oldLen + 16);
        bytes memory buffer = self.inputBuffer;
        uint256 p = KOALABEAR_MODULUS;
        uint256 r = 0x01ff_fffe; // Montgomery R for KoalaBear
        assembly ("memory-safe") {
            let dst := add(buffer, add(0x20, oldLen))
            for { let i := 0 } lt(i, 4) { i := add(i, 1) } {
                let limb := and(shr(sub(224, shl(5, i)), packed), 0xffffffff)
                // mod p, Montgomery, then the 4 bytes LITTLE-endian - the old
                // path appended via _appendBaseLE, which byte-swaps.
                let m := mulmod(mod(limb, p), r, p)
                let be := or(
                    shr(24, m),
                    or(
                        and(shr(8, m), 0xff00),
                        or(and(shl(8, m), 0xff0000), shl(24, and(m, 0xff)))
                    )
                )
                mstore(add(dst, shl(2, i)), shl(224, be))
            }
        }
        self.inputLen = oldLen + 16;
    }

    function observeHashU8Digest(State memory self, bytes32 digest) internal pure {
        _appendDigest32(self, digest);
    }

    function observeHashU64Digest(State memory self, bytes32 digest) internal pure {
        _appendDigestU64LE(self, digest);
    }

    function observeValidatedPackedExt4(State memory self, uint256 packed) internal pure {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 16;
        _ensureCapacity(self, newLen);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function validateAndEncode(x, modulus, mask) -> encoded {
                if and(x, sub(shl(128, 1), 1)) {
                    revertPacked(x)
                }

                let x0 := shr(224, x)
                if iszero(lt(x0, modulus)) {
                    revertPacked(x)
                }

                let x1 := and(shr(192, x), mask)
                if iszero(lt(x1, modulus)) {
                    revertPacked(x)
                }

                let x2 := and(shr(160, x), mask)
                if iszero(lt(x2, modulus)) {
                    revertPacked(x)
                }

                let x3 := and(shr(128, x), mask)
                if iszero(lt(x3, modulus)) {
                    revertPacked(x)
                }

                encoded := or(
                    or(shl(224, bswap32(x0)), shl(192, bswap32(x1))),
                    or(shl(160, bswap32(x2)), shl(128, bswap32(x3)))
                )
            }

            let modulus := 0x7f000001
            let mask := 0xffffffff
            let dst := add(add(buffer, 0x20), oldLen)

            mstore(dst, validateAndEncode(packed, modulus, mask))
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeValidatedPackedExt4Pair(State memory self, uint256 first, uint256 second)
        internal
        pure
    {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 32;
        _ensureCapacity(self, newLen + 16);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function validateAndEncode(x, modulus, mask) -> encoded {
                if and(x, sub(shl(128, 1), 1)) {
                    revertPacked(x)
                }

                let x0 := shr(224, x)
                if iszero(lt(x0, modulus)) {
                    revertPacked(x)
                }

                let x1 := and(shr(192, x), mask)
                if iszero(lt(x1, modulus)) {
                    revertPacked(x)
                }

                let x2 := and(shr(160, x), mask)
                if iszero(lt(x2, modulus)) {
                    revertPacked(x)
                }

                let x3 := and(shr(128, x), mask)
                if iszero(lt(x3, modulus)) {
                    revertPacked(x)
                }

                encoded := or(
                    or(shl(224, bswap32(x0)), shl(192, bswap32(x1))),
                    or(shl(160, bswap32(x2)), shl(128, bswap32(x3)))
                )
            }

            let modulus := 0x7f000001
            let mask := 0xffffffff
            let dst := add(add(buffer, 0x20), oldLen)

            mstore(dst, validateAndEncode(first, modulus, mask))
            mstore(add(dst, 0x10), validateAndEncode(second, modulus, mask))
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeValidatedPackedExt5Slice(State memory self, uint256[] calldata values)
        internal
        pure
    {
        uint256 oldLen = self.inputLen;
        uint256 appendLen = values.length * 20;
        uint256 newLen = oldLen + appendLen;
        _ensureCapacity(self, newLen + 12);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function validateAndEncode(x, mask) -> encoded {
                let highBitMask :=
                    0x8000000080000000800000008000000080000000000000000000000000000000
                let low31Mask := 0x7fffffff7fffffff7fffffff7fffffff7fffffff000000000000000000000000
                let bias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000
                if or(
                    or(and(x, sub(shl(96, 1), 1)), and(x, highBitMask)),
                    and(add(and(x, low31Mask), bias), highBitMask)
                ) { revertPacked(x) }

                let x0 := shr(224, x)
                let x1 := and(shr(192, x), mask)
                let x2 := and(shr(160, x), mask)
                let x3 := and(shr(128, x), mask)
                let x4 := and(shr(96, x), mask)

                encoded := or(
                    or(
                        or(shl(224, bswap32(x0)), shl(192, bswap32(x1))),
                        or(shl(160, bswap32(x2)), shl(128, bswap32(x3)))
                    ),
                    shl(96, bswap32(x4))
                )
            }

            let mask := 0xffffffff
            let src := values.offset
            let end := add(src, shl(5, values.length))
            let dst := add(add(buffer, 0x20), oldLen)

            for { } lt(src, end) {
                src := add(src, 0x20)
                dst := add(dst, 20)
            } {
                mstore(dst, validateAndEncode(calldataload(src), mask))
            }
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeValidatedPackedExt5(State memory self, uint256 packed) internal pure {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 20;
        _ensureCapacity(self, newLen + 12);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function validateAndEncode(x, mask) -> encoded {
                let highBitMask :=
                    0x8000000080000000800000008000000080000000000000000000000000000000
                let low31Mask := 0x7fffffff7fffffff7fffffff7fffffff7fffffff000000000000000000000000
                let bias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000
                if or(
                    or(and(x, sub(shl(96, 1), 1)), and(x, highBitMask)),
                    and(add(and(x, low31Mask), bias), highBitMask)
                ) { revertPacked(x) }

                let x0 := shr(224, x)
                let x1 := and(shr(192, x), mask)
                let x2 := and(shr(160, x), mask)
                let x3 := and(shr(128, x), mask)
                let x4 := and(shr(96, x), mask)

                encoded := or(
                    or(
                        or(shl(224, bswap32(x0)), shl(192, bswap32(x1))),
                        or(shl(160, bswap32(x2)), shl(128, bswap32(x3)))
                    ),
                    shl(96, bswap32(x4))
                )
            }

            let mask := 0xffffffff
            let dst := add(add(buffer, 0x20), oldLen)
            mstore(dst, validateAndEncode(packed, mask))
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeValidatedPackedExt5Pair(State memory self, uint256 first, uint256 second)
        internal
        pure
    {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 40;
        _ensureCapacity(self, newLen + 24);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function validateAndEncode(x, mask) -> encoded {
                let highBitMask :=
                    0x8000000080000000800000008000000080000000000000000000000000000000
                let low31Mask := 0x7fffffff7fffffff7fffffff7fffffff7fffffff000000000000000000000000
                let bias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000
                if or(
                    or(and(x, sub(shl(96, 1), 1)), and(x, highBitMask)),
                    and(add(and(x, low31Mask), bias), highBitMask)
                ) { revertPacked(x) }

                let x0 := shr(224, x)
                let x1 := and(shr(192, x), mask)
                let x2 := and(shr(160, x), mask)
                let x3 := and(shr(128, x), mask)
                let x4 := and(shr(96, x), mask)

                encoded := or(
                    or(
                        or(shl(224, bswap32(x0)), shl(192, bswap32(x1))),
                        or(shl(160, bswap32(x2)), shl(128, bswap32(x3)))
                    ),
                    shl(96, bswap32(x4))
                )
            }

            let mask := 0xffffffff
            let dst := add(add(buffer, 0x20), oldLen)
            mstore(dst, validateAndEncode(first, mask))
            mstore(add(dst, 20), validateAndEncode(second, mask))
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeValidatedPackedExt4Slice(State memory self, uint256[] calldata values)
        internal
        pure
    {
        uint256 oldLen = self.inputLen;
        uint256 appendLen = values.length * 16;
        uint256 newLen = oldLen + appendLen;
        _ensureCapacity(self, newLen + 16);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function validateAndEncode(x, modulus, mask) -> encoded {
                if and(x, sub(shl(128, 1), 1)) {
                    revertPacked(x)
                }

                let x0 := shr(224, x)
                if iszero(lt(x0, modulus)) {
                    revertPacked(x)
                }

                let x1 := and(shr(192, x), mask)
                if iszero(lt(x1, modulus)) {
                    revertPacked(x)
                }

                let x2 := and(shr(160, x), mask)
                if iszero(lt(x2, modulus)) {
                    revertPacked(x)
                }

                let x3 := and(shr(128, x), mask)
                if iszero(lt(x3, modulus)) {
                    revertPacked(x)
                }

                encoded := or(
                    or(shl(224, bswap32(x0)), shl(192, bswap32(x1))),
                    or(shl(160, bswap32(x2)), shl(128, bswap32(x3)))
                )
            }

            let modulus := 0x7f000001
            let mask := 0xffffffff
            let src := values.offset
            let end := add(src, shl(5, values.length))
            let dst := add(add(buffer, 0x20), oldLen)

            for { } lt(src, end) {
                src := add(src, 0x20)
                dst := add(dst, 0x10)
            } {
                mstore(dst, validateAndEncode(calldataload(src), modulus, mask))
            }
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeValidatedPackedExt8(State memory self, uint256 packed) internal pure {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 32;
        _ensureCapacity(self, newLen);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function validateAndEncode(x, modulus, mask) -> encoded {
                let x0 := shr(224, x)
                if iszero(lt(x0, modulus)) {
                    revertPacked(x)
                }
                let x1 := and(shr(192, x), mask)
                if iszero(lt(x1, modulus)) {
                    revertPacked(x)
                }
                let x2 := and(shr(160, x), mask)
                if iszero(lt(x2, modulus)) {
                    revertPacked(x)
                }
                let x3 := and(shr(128, x), mask)
                if iszero(lt(x3, modulus)) {
                    revertPacked(x)
                }
                let x4 := and(shr(96, x), mask)
                if iszero(lt(x4, modulus)) {
                    revertPacked(x)
                }
                let x5 := and(shr(64, x), mask)
                if iszero(lt(x5, modulus)) {
                    revertPacked(x)
                }
                let x6 := and(shr(32, x), mask)
                if iszero(lt(x6, modulus)) {
                    revertPacked(x)
                }
                let x7 := and(x, mask)
                if iszero(lt(x7, modulus)) {
                    revertPacked(x)
                }

                encoded := or(
                    or(
                        or(shl(224, bswap32(x0)), shl(192, bswap32(x1))),
                        or(shl(160, bswap32(x2)), shl(128, bswap32(x3)))
                    ),
                    or(
                        or(shl(96, bswap32(x4)), shl(64, bswap32(x5))),
                        or(shl(32, bswap32(x6)), bswap32(x7))
                    )
                )
            }

            mstore(
                add(add(buffer, 0x20), oldLen),
                validateAndEncode(packed, 0x7f000001, 0xffffffff)
            )
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeValidatedPackedExt8Pair(State memory self, uint256 first, uint256 second)
        internal
        pure
    {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 64;
        _ensureCapacity(self, newLen + 32);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function swap32Lanes(x) -> swapped {
                swapped := or(
                    shl(
                        8,
                        and(x, 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)
                    ),
                    shr(
                        8,
                        and(x, 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)
                    )
                )
                swapped := or(
                    shl(
                        16,
                        and(
                            swapped,
                            0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff
                        )
                    ),
                    shr(
                        16,
                        and(
                            swapped,
                            0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000
                        )
                    )
                )
            }

            function validate(x) {
                let highBitMask :=
                    0x8000000080000000800000008000000080000000800000008000000080000000
                let low31Mask := 0x7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff
                let bias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff
                // The largest per-lane sum is 0x80fffffe, below 2^32.
                if or(and(x, highBitMask), and(add(and(x, low31Mask), bias), highBitMask)) {
                    revertPacked(x)
                }
            }

            function validateAndEncode(x) -> encoded {
                validate(x)
                encoded := swap32Lanes(x)
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            let dst := add(add(buffer, 0x20), oldLen)
            mstore(dst, validateAndEncode(first))
            mstore(add(dst, 0x20), validateAndEncode(second))
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeValidatedPackedExt8Slice(State memory self, uint256[] calldata values)
        internal
        pure
    {
        uint256 oldLen = self.inputLen;
        uint256 appendLen = values.length * 32;
        uint256 newLen = oldLen + appendLen;
        _ensureCapacity(self, newLen + 32);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function validateAndEncode(x, modulus, mask) -> encoded {
                let x0 := shr(224, x)
                if iszero(lt(x0, modulus)) {
                    revertPacked(x)
                }
                let x1 := and(shr(192, x), mask)
                if iszero(lt(x1, modulus)) {
                    revertPacked(x)
                }
                let x2 := and(shr(160, x), mask)
                if iszero(lt(x2, modulus)) {
                    revertPacked(x)
                }
                let x3 := and(shr(128, x), mask)
                if iszero(lt(x3, modulus)) {
                    revertPacked(x)
                }
                let x4 := and(shr(96, x), mask)
                if iszero(lt(x4, modulus)) {
                    revertPacked(x)
                }
                let x5 := and(shr(64, x), mask)
                if iszero(lt(x5, modulus)) {
                    revertPacked(x)
                }
                let x6 := and(shr(32, x), mask)
                if iszero(lt(x6, modulus)) {
                    revertPacked(x)
                }
                let x7 := and(x, mask)
                if iszero(lt(x7, modulus)) {
                    revertPacked(x)
                }

                encoded := or(
                    or(
                        or(shl(224, bswap32(x0)), shl(192, bswap32(x1))),
                        or(shl(160, bswap32(x2)), shl(128, bswap32(x3)))
                    ),
                    or(
                        or(shl(96, bswap32(x4)), shl(64, bswap32(x5))),
                        or(shl(32, bswap32(x6)), bswap32(x7))
                    )
                )
            }

            let src := values.offset
            let end := add(src, shl(5, values.length))
            let dst := add(add(buffer, 0x20), oldLen)

            for { } lt(src, end) {
                src := add(src, 0x20)
                dst := add(dst, 0x20)
            } {
                mstore(dst, validateAndEncode(calldataload(src), 0x7f000001, 0xffffffff))
            }
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeReadValidatedPackedExt4Le(
        State memory self,
        bytes calldata data,
        uint256 offset
    ) internal pure returns (uint256 packed) {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 16;
        _ensureCapacity(self, newLen);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            let raw := calldataload(add(data.offset, offset))
            let modulus := 0x7f000001
            let x0 := bswap32(shr(224, raw))
            if iszero(lt(x0, modulus)) {
                revertPacked(raw)
            }
            let x1 := bswap32(and(shr(192, raw), 0xffffffff))
            if iszero(lt(x1, modulus)) {
                revertPacked(raw)
            }
            let x2 := bswap32(and(shr(160, raw), 0xffffffff))
            if iszero(lt(x2, modulus)) {
                revertPacked(raw)
            }
            let x3 := bswap32(and(shr(128, raw), 0xffffffff))
            if iszero(lt(x3, modulus)) {
                revertPacked(raw)
            }

            packed := or(or(shl(224, x0), shl(192, x1)), or(shl(160, x2), shl(128, x3)))

            mstore(add(add(buffer, 0x20), oldLen), raw)
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeReadValidatedPackedExt4LePair(
        State memory self,
        bytes calldata data,
        uint256 offset
    ) internal pure returns (uint256 first, uint256 second) {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 32;
        _ensureCapacity(self, newLen + 16);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function decodeAndValidate(raw) -> packed {
                let modulus := 0x7f000001
                let x0 := bswap32(shr(224, raw))
                if iszero(lt(x0, modulus)) {
                    revertPacked(raw)
                }
                let x1 := bswap32(and(shr(192, raw), 0xffffffff))
                if iszero(lt(x1, modulus)) {
                    revertPacked(raw)
                }
                let x2 := bswap32(and(shr(160, raw), 0xffffffff))
                if iszero(lt(x2, modulus)) {
                    revertPacked(raw)
                }
                let x3 := bswap32(and(shr(128, raw), 0xffffffff))
                if iszero(lt(x3, modulus)) {
                    revertPacked(raw)
                }

                packed := or(or(shl(224, x0), shl(192, x1)), or(shl(160, x2), shl(128, x3)))
            }

            let src := add(data.offset, offset)
            let raw0 := calldataload(src)
            let raw1 := calldataload(add(src, 0x10))

            first := decodeAndValidate(raw0)
            second := decodeAndValidate(raw1)

            let dst := add(add(buffer, 0x20), oldLen)
            mstore(dst, raw0)
            mstore(add(dst, 0x10), raw1)
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeReadValidatedPackedExt8Le(
        State memory self,
        bytes calldata data,
        uint256 offset
    ) internal pure returns (uint256 packed) {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 32;
        _ensureCapacity(self, newLen);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            let raw := calldataload(add(data.offset, offset))
            let swapped :=
                or(
                    shl(
                        8,
                        and(raw, 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)
                    ),
                    shr(
                        8,
                        and(raw, 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)
                    )
                )
            packed := or(
                shl(
                    16,
                    and(swapped, 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)
                ),
                shr(
                    16,
                    and(swapped, 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000)
                )
            )

            let highBitMask := 0x8000000080000000800000008000000080000000800000008000000080000000
            let low31Mask := 0x7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff
            let bias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff
            // The largest per-lane sum is 0x80fffffe, below 2^32.
            if or(and(packed, highBitMask), and(add(and(packed, low31Mask), bias), highBitMask)) {
                revertPacked(raw)
            }

            mstore(add(add(buffer, 0x20), oldLen), raw)
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeReadValidatedPackedExt8LePair(
        State memory self,
        bytes calldata data,
        uint256 offset
    ) internal pure returns (uint256 first, uint256 second) {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 64;
        _ensureCapacity(self, newLen + 32);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function decodeAndValidate(raw) -> packed {
                let swapped :=
                    or(
                        shl(
                            8,
                            and(
                                raw,
                                0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff
                            )
                        ),
                        shr(
                            8,
                            and(
                                raw,
                                0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00
                            )
                        )
                    )
                packed := or(
                    shl(
                        16,
                        and(
                            swapped,
                            0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff
                        )
                    ),
                    shr(
                        16,
                        and(
                            swapped,
                            0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000
                        )
                    )
                )

                let highBitMask :=
                    0x8000000080000000800000008000000080000000800000008000000080000000
                let low31Mask := 0x7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff
                let bias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff
                // The largest per-lane sum is 0x80fffffe, below 2^32.
                if or(
                    and(packed, highBitMask),
                    and(add(and(packed, low31Mask), bias), highBitMask)
                ) {
                    revertPacked(raw)
                }
            }

            let src := add(data.offset, offset)
            let raw0 := calldataload(src)
            let raw1 := calldataload(add(src, 0x20))

            first := decodeAndValidate(raw0)
            second := decodeAndValidate(raw1)

            let dst := add(add(buffer, 0x20), oldLen)
            mstore(dst, raw0)
            mstore(add(dst, 0x20), raw1)
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeReadValidatedPackedExt5Le(
        State memory self,
        bytes calldata data,
        uint256 offset
    ) internal pure returns (uint256 packed) {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 20;
        _ensureCapacity(self, newLen + 12);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            let raw := calldataload(add(data.offset, offset))
            let modulus := 0x7f000001
            let x0 := bswap32(shr(224, raw))
            let x1 := bswap32(and(shr(192, raw), 0xffffffff))
            let x2 := bswap32(and(shr(160, raw), 0xffffffff))
            let x3 := bswap32(and(shr(128, raw), 0xffffffff))
            let x4 := bswap32(and(shr(96, raw), 0xffffffff))
            if or(
                or(or(iszero(lt(x0, modulus)), iszero(lt(x1, modulus))), iszero(lt(x2, modulus))),
                or(iszero(lt(x3, modulus)), iszero(lt(x4, modulus)))
            ) { revertPacked(raw) }

            packed := or(
                or(or(shl(224, x0), shl(192, x1)), or(shl(160, x2), shl(128, x3))),
                shl(96, x4)
            )

            mstore(add(add(buffer, 0x20), oldLen), and(raw, not(sub(shl(96, 1), 1))))
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeReadValidatedPackedExt5LePair(
        State memory self,
        bytes calldata data,
        uint256 offset
    ) internal pure returns (uint256 first, uint256 second) {
        first = observeReadValidatedPackedExt5Le(self, data, offset);
        second = observeReadValidatedPackedExt5Le(self, data, offset + 20);
    }

    /// Squeezes ONE byte, matching p3-challenger HashChallenger byte order.
    ///
    /// p3 pops from the END of a 32-byte output buffer, so the first byte a
    /// caller receives is digest[31], then digest[30], and so on. _sampleUint32
    /// already consumes the output block from its low end, and the low byte of a
    /// uint32 is the byte at the lowest address, so this reads the same stream in
    /// the same order without disturbing the field-level samplers.
    ///
    /// Added for transcript replay: the recorded WHIR verifier program is a
    /// byte-level absorb/squeeze sequence, and checking Solidity against it needs
    /// a byte-level squeeze. Field-level sampling stays the API the verifier uses.
    /// See lib/sol-whir-p3/PATCHES.md.
    function sampleByte(State memory self) internal pure returns (uint8) {
        if (self.outputIndex == 0) {
            _flush(self);
        }
        unchecked {
            // Same shift _sampleUint32 applies, narrowed to one byte: the byte at
            // offset (32 - outputIndex) from the start of the output block.
            uint256 shift = ((DIGEST_BYTES - self.outputIndex) & 0xff) << 3;
            self.outputIndex -= 1;
            return uint8(uint256(self.outputBlock >> shift) & 0xff);
        }
    }

    /// Squeezes n bytes in the same order as repeated sampleByte calls.
    function sampleBytes(State memory self, uint256 n) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i; i < n; ++i) {
            out[i] = bytes1(sampleByte(self));
        }
    }

    function sampleBase(State memory self) internal pure returns (uint256) {
        while (true) {
            uint256 value = uint256(_sampleUint32(self)) & KOALABEAR_SAMPLE_MASK;
            if (value < KOALABEAR_MODULUS) {
                return value;
            }
        }

        revert("UNREACHABLE");
    }

    function sampleBits(State memory self, uint256 bits) internal pure returns (uint256) {
        require(bits < 256, "BITS_WIDTH");
        if (bits == 0) {
            return 0;
        }

        require((uint256(1) << bits) <= KOALABEAR_MODULUS, "BITS_RANGE");
        return sampleBitsUnchecked(self, bits);
    }

    function sampleBitsUnchecked(State memory self, uint256 bits) internal pure returns (uint256) {
        if (bits == 0) {
            return 0;
        }
        unchecked {
            return uint256(_sampleUint32(self)) & ((uint256(1) << bits) - 1);
        }
    }

    function sampleExt4Coeffs(State memory self) internal pure returns (uint256[4] memory coeffs) {
        unchecked {
            for (uint256 i = 0; i < 4; ++i) {
                coeffs[i] = sampleBase(self);
            }
        }
    }

    function sampleExt8Coeffs(State memory self) internal pure returns (uint256[8] memory coeffs) {
        unchecked {
            for (uint256 i = 0; i < 8; ++i) {
                coeffs[i] = sampleBase(self);
            }
        }
    }

    function sampleExt5Coeffs(State memory self) internal pure returns (uint256[5] memory coeffs) {
        unchecked {
            for (uint256 i = 0; i < 5; ++i) {
                coeffs[i] = sampleBase(self);
            }
        }
    }
    /// Verifies a proof-of-work witness: squeeze one byte, absorb the witness, and
    /// require the next `bits` bits to be zero.
    ///
    /// The squeeze is load-bearing, not a no-op. p3 GrindingChallenger::check_witness
    /// calls a private squeeze that samples and discards one byte, and in the WHIR flow
    /// the output buffer is always empty here because the round just observed a
    /// commitment. So the squeeze FLUSHES, folding everything observed so far into a
    /// digest, and only then is the witness appended on top of that digest. Skipping it
    /// hashes the witness against the previous digest instead, and rejects a valid
    /// proof. Pinned by contracts/test/WhirSemanticProgram.t.sol, which replays 23
    /// recorded witness checks at difficulties 1, 3, 5, 7 and 8.
    ///
    /// A zero-bit check accepts without touching the transcript, matching p3.
    function checkWitness(State memory self, uint256 bits, uint256 witness)
        internal
        pure
        returns (bool)
    {
        if (bits == 0) {
            return true;
        }

        // Discard one byte, flushing if the buffer is empty. The value is unused; the
        // flush is the point.
        sampleByte(self);
        observeBase(self, witness);
        return sampleBits(self, bits) == 0;
    }

    function debugInputHash(State memory self) internal pure returns (bytes32 digest) {
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            digest := keccak256(add(buffer, 0x20), mload(add(self, 0x20)))
        }
    }

    function _flush(State memory self) private pure {
        bytes memory buffer = self.inputBuffer;
        bytes32 digest;
        assembly ("memory-safe") {
            digest := keccak256(add(buffer, 0x20), mload(add(self, 0x20)))
        }
        if (buffer.length < DIGEST_BYTES) {
            buffer = new bytes(INITIAL_CAPACITY);
            self.inputBuffer = buffer;
        }
        assembly ("memory-safe") {
            mstore(add(buffer, 0x20), digest)
        }
        self.inputLen = DIGEST_BYTES;
        self.outputBlock = digest;
        self.outputIndex = DIGEST_BYTES;
    }

    function _sampleUint32(State memory self) private pure returns (uint32 value) {
        if (self.outputIndex == 0) {
            _flush(self);
        }

        unchecked {
            uint256 oldIndex = self.outputIndex;
            self.outputIndex = oldIndex - 4;
            return uint32(uint256(self.outputBlock >> (((DIGEST_BYTES - oldIndex) & 0xff) << 3)));
        }
    }

    function _appendBytes(State memory self, bytes memory data) private pure {
        uint256 oldLen = self.inputLen;
        uint256 appendLen = data.length;
        uint256 newLen = oldLen + appendLen;
        _ensureCapacity(self, newLen);

        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            mcopy(add(add(buffer, 0x20), oldLen), add(data, 0x20), appendLen)
        }

        self.inputLen = newLen;
    }

    function _appendBytesCalldata(
        State memory self,
        bytes calldata data,
        uint256 offset,
        uint256 appendLen
    ) private pure {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + appendLen;
        _ensureCapacity(self, newLen);

        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            calldatacopy(add(add(buffer, 0x20), oldLen), add(data.offset, offset), appendLen)
        }

        self.inputLen = newLen;
    }

    function _appendBaseLE(State memory self, uint32 value) private pure {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 4;
        _ensureCapacity(self, newLen);

        bytes memory buffer = self.inputBuffer;
        uint256 bigEndian = _bswap32(value);
        assembly ("memory-safe") {
            mstore(add(add(buffer, 0x20), oldLen), shl(224, bigEndian))
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function _appendDigest32(State memory self, bytes32 digest) private pure {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + DIGEST_BYTES;
        _ensureCapacity(self, newLen);

        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            mstore(add(add(buffer, 0x20), oldLen), digest)
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function _appendDigestU64LE(State memory self, bytes32 digest) private pure {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + DIGEST_BYTES;
        _ensureCapacity(self, newLen);

        uint256 value = uint256(digest);
        uint256 reordered = (_bswap64(uint64(value >> 192)) << 192)
            | (_bswap64(uint64(value >> 128)) << 128) | (_bswap64(uint64(value >> 64)) << 64)
            | _bswap64(uint64(value));

        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            mstore(add(add(buffer, 0x20), oldLen), reordered)
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function _ensureCapacity(State memory self, uint256 minCapacity) private pure {
        uint256 capacity = self.inputBuffer.length;
        if (capacity >= minCapacity) {
            return;
        }

        uint256 newCapacity = capacity == 0 ? INITIAL_CAPACITY : capacity;
        while (newCapacity < minCapacity) {
            newCapacity <<= 1;
        }

        bytes memory newBuffer;
        bytes memory oldBuffer = self.inputBuffer;
        uint256 usedLen = self.inputLen;

        assembly ("memory-safe") {
            newBuffer := mload(0x40)
            mstore(newBuffer, newCapacity)
            mstore(0x40, add(newBuffer, and(add(add(newCapacity, 0x20), 0x1f), not(0x1f))))
            if usedLen {
                mcopy(add(newBuffer, 0x20), add(oldBuffer, 0x20), usedLen)
            }
        }

        self.inputBuffer = newBuffer;
    }

    function _bswap32(uint32 x) private pure returns (uint256) {
        return ((uint256(x) & 0x000000ff) << 24) | ((uint256(x) & 0x0000ff00) << 8)
            | ((uint256(x) & 0x00ff0000) >> 8) | ((uint256(x) & 0xff000000) >> 24);
    }

    function _bswap64(uint64 x) private pure returns (uint256 r) {
        assembly ("memory-safe") {
            // Swap adjacent bytes
            r := or(shr(8, and(x, 0xFF00FF00FF00FF00)), shl(8, and(x, 0x00FF00FF00FF00FF)))
            // Swap adjacent 16-bit pairs
            r := or(shr(16, and(r, 0xFFFF0000FFFF0000)), shl(16, and(r, 0x0000FFFF0000FFFF)))
            // Swap 32-bit halves
            r := or(shr(32, r), shl(32, and(r, 0xFFFFFFFF)))
        }
    }
}
