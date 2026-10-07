// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {KoalaBearExt4} from "../../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {WhirGadgets} from "./WhirGadgets.sol";
import {WhirFixedConfig} from "./WhirFixedConfig.sol";

/// @title TerminalWeight
/// @notice The terminal-weight satellite (D-086 step A).
///
/// The verifier's last phase - the batched constraint polynomial at the full
/// folding randomness, and the public polynomial at the closing randomness -
/// is the largest single block of verifier bytecode (evalConstraintsPoly,
/// constraintWeight, the eq/select evaluators) and it runs once per batch
/// round - a handful of times per verify, never in the per-query path. This
/// contract owns that computation so the pinned core fits under EIP-170 with
/// room to spare. The library functions are internal, so they inline HERE and
/// nowhere else: one source of truth, no duplication in WhirVerifier.
///
/// # Frame protocol (raw calldata, no ABI codec)
///
/// The caller staticcalls this contract with a contiguous word frame (no
/// selector; every call lands in fallback). All words are 32-byte
/// big-endian, canonical field elements exactly as the verifier holds them:
///
/// ```text
/// word 0        magic 0x5457_4947_4854 ("TWIGHT")
/// word 1        n, then n words of allR
/// next          m = constraint count; per constraint, 6 header words:
///                 k, gamma, initialPower, mode, nGroups, nSel
///   mode 1 (wire groups): nGroups eq-length words, then the flat eq words
///               (sum of lengths). The satellite's eqCdBase is the absolute
///               calldata byte offset of those words - the same
///               calldata-relative trick the core uses against the proof
///               bundle, so the big eq section is read, never decoded.
///   mode 0 (derived):     nGroups groups of exactly k words each.
///   mode 2 (statement):   stmLen, roundIdx, nVirtual, nVirtual virtual-point
///               words, then stmLen raw STATEMENT bytes (WBND v5). Groups are
///               derived from the public opening points + transcript draws.
///   then nSel selVars words.
/// next          nFinal, then finalPoly (nFinal words)
/// next          nRand, then randomness (nRand words)
/// ```
///
/// The frame must end exactly at calldatasize; anything else is malformed
/// and reverts. The reply is the raw 96-byte frame [magic, weight, value].
///
/// # Trust
///
/// This is a pure function of the frame: it touches no state and reverts on
/// any malformed input. The caller performs the terminal equality
/// folded == weight * value itself, so a faulty or malicious satellite can
/// only make verification FAIL - never pass. The verifier pins this
/// contract's codehash at construction and re-checks it before every call.
contract TerminalWeight {
    /// @notice Frame magic: ASCII "TWIGHT".
    uint256 public constant MAGIC = 0x5457_4947_4854;

    /// @notice Second frame magic: ASCII "MROOTS". v8 intermediate rounds
    /// hand the row decode, fold, and amortized pruned-Merkle walk here in
    /// one call per round, keeping the engine under its size margin.
    uint256 public constant MROOTS_MAGIC = 0x4D52_4F4F_5453;

    /// @notice The KoalaBear prime, for row-limb range checks.
    uint256 private constant P = 0x7F00_0001;
    /// @notice Montgomery radix for the wire limbs: 2^31 mod P.
    uint256 private constant MONT = 0x01FF_FFFE;

    /// @notice The frame did not start with the magic.
    error BadFrame();
    /// @notice The frame carries trailing or missing words.
    error BadFrameLength();
    /// @notice A mode-2 constraint's statement slice ran past the frame.
    error BadStatement();
    /// @notice A statement matrix claims more variables than the constraint.
    error BadArity(uint256 arity, uint256 numVariables);
    /// @notice The pruned digest stream ran dry, or carried extra digests:
    /// the walk's own boundary count (expected) and the wire's count (got)
    /// disagree. Either direction is fatal - the stream is not this proof's.
    error SiblingCountMismatch(uint256 expected, uint256 got);
    /// @notice The frontier walk did not collapse to a single root.
    error MrootsBadFrontier();

    /// Derive the mode-2 group descriptors for one opening round.
    ///
    /// Mirrors `StackedPlan::try_new` (vendor plan.rs) exactly: tables sorted
    /// by arity ASCENDING (stable), iterated REVERSE - so the largest arity
    /// lands first and equal arities place later-source-index-first. Per
    /// table, each of its `width` columns claims one contiguous slot:
    /// `raw_index = offset >> arity`, stored bit-reversed within the
    /// `nv = k - arity` selector bits, `offset += 2^arity` per COLUMN. The
    /// group order is statement-major: per point, then per column. Virtual
    /// tail groups (the initial round's OOD samples) come last: full stacked
    /// arity, no selector bits, zeta from the transcript draw.
    ///
    /// The statement section is 4-byte packed: per round `u32 n_mats`, per
    /// matrix `u32 log_size, u32 width, u32 n_points` (u32 LE), then per
    /// point a blob: `u32 byte_len (32)` + one packed ext word (limbs at
    /// bits 224/192/160/128, exactly the form the constraint walk consumes).
    /// So each point costs 36 bytes and its zeta is the word at +16.
    function deriveGroupDescs(
        uint256 stmCdBase,
        uint256 stmLen,
        uint256 roundIdx,
        uint256[] memory virtualPoints,
        uint256 k
    ) private pure returns (uint256[] memory descs) {
        if (stmCdBase + stmLen > msg.data.length) revert BadStatement();
        uint256 cursor = stmCdBase;
        uint256 numRounds = _leWordAt(cursor);
        cursor += 4;
        if (roundIdx >= numRounds) revert BadStatement();
        for (uint256 r; r < roundIdx; ++r) { cursor = _skipRound(cursor); }
        uint256 nMats = _leWordAt(cursor);
        cursor += 4;

        // Pass 1: one walk of the round; remember each matrix's byte offset
        // and the total group count (also validates the slice).
        uint256[] memory matOff = new uint256[](nMats);
        uint256 total = 0;
        for (uint256 i; i < nMats; ++i) {
            matOff[i] = cursor;
            uint256 arity = _arityAt(cursor);
            uint256 width = _leWordAt(cursor + 4);
            if (arity > k) revert BadArity(arity, k);
            total += _leWordAt(cursor + 8) * width;
            cursor = _skipMatrix(cursor);
        }
        total += virtualPoints.length;

        // Pass 2: stable insertion sort by arity ascending (nMats is small;
        // ties keep source order, which the reverse walk flips).
        uint256[] memory order = new uint256[](nMats);
        for (uint256 i; i < nMats; ++i) {
            uint256 a = _arityAt(matOff[i]);
            uint256 j = i;
            while (j > 0 && _arityAt(matOff[order[j - 1]]) > a) {
                order[j] = order[j - 1];
                --j;
            }
            order[j] = i;
        }

        // Pass 3: emit descriptors in placement order.
        descs = new uint256[](3 * total);
        uint256 w = 0;
        uint256 offset = 0;
        for (uint256 p = nMats; p > 0; --p) {
            uint256 mat = matOff[order[p - 1]];
            uint256 arity = _arityAt(mat);
            uint256 width = _leWordAt(mat + 4);
            uint256 nPoints = _leWordAt(mat + 8);
            uint256 nv = k - arity;
            uint256 slot = uint256(1) << arity;
            // Column slot indices, computed once per table (offset advances
            // per COLUMN, exactly like the reference stacking).
            uint256[] memory cols = new uint256[](width);
            for (uint256 c; c < width; ++c) {
                cols[c] = _reverseBits(offset >> arity, nv);
                offset += slot;
            }
            uint256 pts = mat + 16; // skip 12-byte header + first length word
            for (uint256 q; q < nPoints; ++q) {
                uint256 zeta = _cdWord(pts + 36 * q);
                for (uint256 c; c < width; ++c) {
                    descs[w++] = arity;
                    descs[w++] = zeta;
                    descs[w++] = cols[c];
                }
            }
        }
        // Virtual tail: full stacked arity, no selector bits.
        for (uint256 v; v < virtualPoints.length; ++v) {
            descs[w++] = k;
            descs[w++] = virtualPoints[v];
            descs[w++] = WhirGadgets.NO_SELECTOR;
        }
        if (w != 3 * total) revert BadStatement();
    }

    /// Cursor after round `cursor` (which starts at its `u32 n_mats`).
    function _skipRound(uint256 cursor) private pure returns (uint256) {
        uint256 nMats = _leWordAt(cursor);
        cursor += 4;
        for (uint256 i; i < nMats; ++i) { cursor = _skipMatrix(cursor); }
        return cursor;
    }

    /// Cursor after matrix `cursor`: 3 u32 LE header words (12 bytes) then,
    /// per point, a 4-byte blob length + 32-byte packed ext word (36 bytes).
    function _skipMatrix(uint256 cursor) private pure returns (uint256) {
        uint256 nPoints = _leWordAt(cursor + 8);
        return cursor + 12 + 36 * nPoints;
    }

    /// The raw 32-byte word at the frame byte offset.
    function _cdWord(uint256 at) private pure returns (uint256 v) {
        assembly ("memory-safe") { v := calldataload(at) }
    }

    /// The u32 LE field at the frame byte offset (four LE bytes of the BE load).
    function _leWordAt(uint256 at) private pure returns (uint256 v) {
        assembly ("memory-safe") {
            // shr(224) leaves the four bytes big-endian in the LOW 32 bits:
            // b0 at bits 31..24 (the LE LSB) down to b3 at bits 7..0. The LE
            // value is b3<<24 | b2<<16 | b1<<8 | b0.
            let w := shr(224, calldataload(at))
            v := or(
                or(and(shr(24, w), 0xff), and(shr(8, w), 0xff00)),
                or(and(shl(8, w), 0xff0000), and(shl(24, w), 0xff000000))
            )
        }
    }

    /// The stacking arity of the matrix whose header starts at `at`: the
    /// wire's raw log_size PADDED up to the folding factor, exactly like
    /// `padded_arity(log_size, FOLDING_FACTOR)` in composed_export.rs - the
    /// initial sumcheck folds `FINAL_FOLDING_FACTOR` variables per round, so
    /// every stacked table occupies at least that many variables. The wire
    /// stores the raw value; the satellite pads.
    function _arityAt(uint256 at) private pure returns (uint256) {
        uint256 raw = _leWordAt(at);
        return raw < WhirFixedConfig.FINAL_FOLDING_FACTOR ? WhirFixedConfig.FINAL_FOLDING_FACTOR : raw;
    }

    /// `x` with its low `n` bits reversed (p3_util::reverse_bits_len).
    function _reverseBits(uint256 x, uint256 n) private pure returns (uint256 r) {
        for (uint256 i; i < n; ++i) {
            r = (r << 1) | (x & 1);
            x >>= 1;
        }
    }

    // ---------------------------------------------------------------------
    // v8 MROOTS: amortized pruned Merkle root
    // ---------------------------------------------------------------------

    /// Read the 32-byte frame head (first calldata word) for dispatch.
    function _head() private pure returns (uint256 h) {
        assembly ("memory-safe") { h := calldataload(0) }
    }

    /// One pruned digest from the stream whose first digest sits at absolute
    /// calldata byte offset base, word k.
    function _streamDigest(uint256 base, uint256 k) private pure returns (bytes32 d) {
        assembly ("memory-safe") { d := calldataload(add(base, mul(k, 32))) }
    }

    /// v8 MROOTS frame:
    ///   [0] MROOTS_MAGIC
    ///   [1] depth      path length = log2 folded domain size
    ///   [2] nq         query count
    ///   [3] nDigests   pruned stream length for this intermediate
    ///   [4 .. 4+nq)                 query indices, query order
    ///   [4+nq .. 4+2nq)             leaf digests, query order
    ///   [4+2nq .. 4+2nq+nDigests)   pruned digest stream, walk order
    /// Reply: [MROOTS_MAGIC, root]. The walk mirrors p3-merkle-tree's
    /// walk_frontier at arity 2: sorted-unique leaves seed one frontier node
    /// each; per level, nodes sharing a parent hash together and consume
    /// nothing, lone children pull their sibling from the stream, groups in
    /// ascending parent order, level-major. The engine compares the returned
    /// root against its own prevCommitment, so a wrong stream can only make
    /// verification FAIL - never pass.
    function _mroots() private pure {
        assembly ("memory-safe") {
            let depth := calldataload(32)
            let nq := calldataload(64)
            let nD := calldataload(96)
            if iszero(eq(calldatasize(), mul(add(add(5, mul(2, nq)), nD), 32))) {
                mstore(0, shl(224, 0x09a205cc)) // BadFrameLength()
                revert(0, 4)
            }
            // The frame's final word is the root the engine expects. The
            // codehash pin means the engine trusts THIS code, so the
            // comparison lives here: a mismatch reverts and the shared call
            // path bubbles it up, costing the engine no second compare.
            let expectedRoot := calldataload(mul(add(add(4, mul(2, nq)), nD), 32))
            // Frontier arrays: current + next indices and digests, plus a
            // 64-byte hash scratch. All sized by nq (frontier never grows).
            let idxB := mload(0x40)
            let digB := add(idxB, mul(nq, 32))
            let nidxB := add(digB, mul(nq, 32))
            let ndigB := add(nidxB, mul(nq, 32))
            let scratch := add(ndigB, mul(nq, 32))
            mstore(0x40, add(scratch, 64))
            calldatacopy(idxB, 128, mul(nq, 32))
            calldatacopy(digB, add(128, mul(nq, 32)), mul(nq, 32))

            // Insertion sort by index, carrying digests. nq <= 74.
            for { let i := 1 } lt(i, nq) { i := add(i, 1) } {
                let ki := mload(add(idxB, mul(i, 32)))
                let kd := mload(add(digB, mul(i, 32)))
                let j := i
                for { } gt(j, 0) { } {
                    let pj := mload(add(idxB, mul(sub(j, 1), 32)))
                    if iszero(gt(pj, ki)) { break }
                    mstore(add(idxB, mul(j, 32)), pj)
                    mstore(add(digB, mul(j, 32)), mload(add(digB, mul(sub(j, 1), 32))))
                    j := sub(j, 1)
                }
                mstore(add(idxB, mul(j, 32)), ki)
                mstore(add(digB, mul(j, 32)), kd)
            }
            // Sorted-unique: duplicate query indices share one node.
            let u := 0
            for { let i := 0 } lt(i, nq) { i := add(i, 1) } {
                let ki := mload(add(idxB, mul(i, 32)))
                if or(iszero(i), iszero(eq(ki, mload(add(idxB, mul(sub(i, 1), 32)))))) {
                    mstore(add(idxB, mul(u, 32)), ki)
                    mstore(add(digB, mul(u, 32)), mload(add(digB, mul(i, 32))))
                    u := add(u, 1)
                }
            }
            if iszero(u) {
                mstore(0, shl(224, 0x81262fc8)) // MrootsBadFrontier()
                revert(0, 4)
            }
            let streamBase := mul(add(4, mul(2, nq)), 32)
            let w := 0
            for { let lvl := 0 } lt(lvl, depth) { lvl := add(lvl, 1) } {
                let m := 0
                let i := 0
                for { } lt(i, u) { } {
                    let ii := mload(add(idxB, mul(i, 32)))
                    let p := shr(1, ii)
                    let left := mload(add(digB, mul(i, 32)))
                    let right := 0
                    let paired := 0
                    if lt(add(i, 1), u) {
                        if eq(shr(1, mload(add(idxB, mul(add(i, 1), 32)))), p) { paired := 1 }
                    }
                    switch paired
                    case 1 {
                        right := mload(add(digB, mul(add(i, 1), 32)))
                        i := add(i, 2)
                    }
                    default {
                        // Boundary child: sibling from the stream. The odd
                        // child keeps its own digest as the RIGHT input and
                        // takes the stream digest as LEFT.
                        switch and(ii, 1)
                        case 0 { right := calldataload(add(streamBase, mul(w, 32))) }
                        default {
                            right := left
                            left := calldataload(add(streamBase, mul(w, 32)))
                        }
                        w := add(w, 1)
                        i := add(i, 1)
                    }
                    mstore(scratch, left)
                    mstore(add(scratch, 32), right)
                    mstore(add(nidxB, mul(m, 32)), p)
                    mstore(add(ndigB, mul(m, 32)), keccak256(scratch, 64))
                    m := add(m, 1)
                }
                // Swap frontiers: current always lives at idxB/digB.
                let t := idxB
                idxB := nidxB
                nidxB := t
                t := digB
                digB := ndigB
                ndigB := t
                u := m
            }
            if iszero(eq(w, nD)) {
                mstore(0, shl(224, 0xc6de65b0)) // SiblingCountMismatch(uint256,uint256)
                mstore(4, w)
                mstore(36, nD)
                revert(0, 68)
            }
            if iszero(eq(u, 1)) {
                mstore(0, shl(224, 0x81262fc8)) // MrootsBadFrontier()
                revert(0, 4)
            }
            if iszero(eq(mload(digB), expectedRoot)) {
                mstore(0, shl(224, 0xaee6dc69)) // PrunedRootMismatch()
                revert(0, 4)
            }
            // Reply [magic, root, 0]: the same 96-byte shape as TWIGHT, so
            // the engine's single satellite-call path reads both.
            mstore(0, 0x4D524F4F5453) // MROOTS_MAGIC
            mstore(32, mload(digB))
            mstore(64, 0)
            return(0, 96)
        }
    }

    /// @notice Parse the frame, evaluate the terminal weight and value, and
    /// reply [magic, weight, value]. No mutability modifier: a fallback may
    /// not be declared pure/view, but this body reads no state and the caller
    /// staticcalls it, so ETH can never enter and nothing is written.
    fallback() external {
        if (_head() == MROOTS_MAGIC) {
            // _mroots answers via the return opcode; control never returns.
            _mroots();
        }
        uint256[] memory allR;
        WhirGadgets.ConstraintWeight[] memory constraints;
        uint256[] memory finalPoly;
        uint256[] memory randomness;
        assembly ("memory-safe") {
            // Raw staticcall: the frame IS the calldata, starting at byte 0.
            let c := 0
            if iszero(eq(calldataload(0), MAGIC)) {
                mstore(0, 0xe9459814) // BadFrame()
                revert(0, 4)
            }
            c := 32

            // --- allR ---
            let n := calldataload(c)
            c := add(c, 32)
            allR := mload(0x40)
            mstore(allR, n)
            calldatacopy(add(allR, 32), c, mul(n, 32))
            c := add(c, mul(n, 32))
            mstore(0x40, add(add(allR, 32), mul(n, 32)))

            // --- constraints ---
            let m := calldataload(c)
            c := add(c, 32)
            constraints := mload(0x40)
            mstore(constraints, m)
            let cb := add(constraints, 32)
            // ConstraintWeight has dynamic members, so Solidity lays its
            // memory array out as POINTS: m words here, each the address of
            // a 384-byte block (12 words) allocated after them. Inline
            // structs would be read back as garbage pointers.
            mstore(0x40, add(cb, mul(m, 32)))
            for { let i := 0 } lt(i, m) { i := add(i, 1) } {
                let base := mload(0x40)
                mstore(0x40, add(base, 384))
                mstore(add(cb, mul(i, 32)), base)
                let k := calldataload(c)
                let gamma := calldataload(add(c, 32))
                let ipow := calldataload(add(c, 64))
                let mode := calldataload(add(c, 96))
                let nGroups := calldataload(add(c, 128))
                let nSel := calldataload(add(c, 160))
                c := add(c, 192)
                // Field order: [0]numVariables [1]gamma [2]initialPower
                // [3]eqPoints(+96) [4]eqCdBase(+128) [5]eqLens(+160)
                // [6]selVars(+192) [7]stmCdBase(+224) [8]stmLen(+256)
                // [9]stmRound(+288) [10]virtualPoints(+320)
                // [11]groupDescs(+352) - filled after the parse loop.
                mstore(base, k)
                mstore(add(base, 32), gamma)
                mstore(add(base, 64), ipow)

                if eq(mode, 1) {
                    // Wire groups stay in OUR calldata: eqLens to memory,
                    // eqCdBase = absolute offset of the flat words here.
                    let lens := mload(0x40)
                    mstore(lens, nGroups)
                    calldatacopy(add(lens, 32), c, mul(nGroups, 32))
                    c := add(c, mul(nGroups, 32))
                    mstore(0x40, add(add(lens, 32), mul(nGroups, 32)))
                    mstore(add(base, 160), lens)
                    mstore(add(base, 128), c) // eqCdBase
                    let total := 0
                    for { let j := 0 } lt(j, nGroups) { j := add(j, 1) } {
                        total := add(total, mload(add(add(lens, 32), mul(j, 32))))
                    }
                    c := add(c, mul(total, 32))
                }
                if eq(mode, 2) {
                    // Derived-from-statement groups (WBND v5, D-086 step C):
                    // [stmLen, round, nVirtual, virtualPoints..., raw statement
                    // bytes]. The statement slice is the bundle's STATEMENT
                    // section copied verbatim; the group descriptors are
                    // derived from it after the parse loop
                    // (deriveGroupDescs), never materialised as coordinates.
                    let stmLen := calldataload(c)
                    let roundIdx := calldataload(add(c, 32))
                    let nV := calldataload(add(c, 64))
                    c := add(c, 96)
                    let vp := mload(0x40)
                    mstore(vp, nV)
                    calldatacopy(add(vp, 32), c, mul(nV, 32))
                    c := add(c, mul(nV, 32))
                    mstore(0x40, add(add(vp, 32), mul(nV, 32)))
                    if gt(add(c, stmLen), calldatasize()) { mstore(0, 0xa1f115fd) revert(0, 4) }
                    mstore(add(base, 224), c) // stmCdBase (absolute, our calldata)
                    mstore(add(base, 256), stmLen)
                    mstore(add(base, 288), roundIdx)
                    mstore(add(base, 320), vp)
                    c := add(c, stmLen)
                }
                if eq(mode, 0) {
                    // Derived groups: ragged memory array, k words each.
                    let pts := mload(0x40)
                    mstore(pts, nGroups)
                    let pd := add(pts, 32)
                    mstore(0x40, add(pd, mul(nGroups, 32)))
                    for { let j := 0 } lt(j, nGroups) { j := add(j, 1) } {
                        let grp := mload(0x40)
                        mstore(grp, k)
                        calldatacopy(add(grp, 32), c, mul(k, 32))
                        c := add(c, mul(k, 32))
                        mstore(0x40, add(add(grp, 32), mul(k, 32)))
                        mstore(add(pd, mul(j, 32)), grp)
                    }
                    mstore(add(base, 96), pts) // eqPoints; eqCdBase stays 0
                }

                // selVars (absent when nSel == 0, matching the verifier).
                if nSel {
                    let sv := mload(0x40)
                    mstore(sv, nSel)
                    calldatacopy(add(sv, 32), c, mul(nSel, 32))
                    c := add(c, mul(nSel, 32))
                    mstore(0x40, add(add(sv, 32), mul(nSel, 32)))
                    mstore(add(base, 192), sv)
                }
            }

            // --- finalPoly ---
            let nFinal := calldataload(c)
            c := add(c, 32)
            finalPoly := mload(0x40)
            mstore(finalPoly, nFinal)
            calldatacopy(add(finalPoly, 32), c, mul(nFinal, 32))
            c := add(c, mul(nFinal, 32))
            mstore(0x40, add(add(finalPoly, 32), mul(nFinal, 32)))

            // --- randomness ---
            let nRand := calldataload(c)
            c := add(c, 32)
            randomness := mload(0x40)
            mstore(randomness, nRand)
            calldatacopy(add(randomness, 32), c, mul(nRand, 32))
            c := add(c, mul(nRand, 32))
            mstore(0x40, add(add(randomness, 32), mul(nRand, 32)))

            if iszero(eq(c, calldatasize())) {
                mstore(0, 0x09a205cc) // BadFrameLength()
                revert(0, 4)
            }
        }

        // Mode-2 constraints: turn each statement slice into flat group
        // descriptors [arity, zeta, selIndex] ONCE per frame, so the
        // per-query walk in constraintWeight is a pure read. Fresh satellite
        // memory is zeroed, so every field the parse did not write is 0.
        for (uint256 i; i < constraints.length; ++i) {
            WhirGadgets.ConstraintWeight memory c = constraints[i];
            if (c.stmCdBase != 0) {
                c.groupDescs = deriveGroupDescs(
                    c.stmCdBase, c.stmLen, c.stmRound, c.virtualPoints, c.numVariables
                );
            }
        }

        uint256 weight = WhirGadgets.evalConstraintsPoly(allR, constraints, false);
        uint256 value = KoalaBearExt4.evaluate_hypercube(finalPoly, randomness);
        assembly ("memory-safe") {
            mstore(0, MAGIC)
            mstore(32, weight)
            mstore(64, value)
            return(0, 96)
        }
    }
}
