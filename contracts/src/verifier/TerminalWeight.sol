// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {KoalaBearExt4} from "../../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {WhirGadgets} from "./WhirGadgets.sol";
import {WhirFixedConfig} from "./WhirFixedConfig.sol";
import {ConstraintIdentity} from "./ConstraintIdentity.sol";

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

    /// @notice Third frame magic: ASCII "CIDNTY". The constraint identity
    /// (D-076) - claim walk, DAG fold, quotient recompose - runs here so the
    /// engine never inlines the ConstraintIdentity interpreter (batch 48).
    uint256 public constant CIDNTY_MAGIC = 0x4349_444E_5459;

    /// @notice Fourth frame magic: ASCII "QFOLD". v9: the whole per-query loop
    /// (row decode, leaf hash, fold) plus the amortized pruned-Merkle walk runs
    /// here in ONE call per round. The engine keeps only the transcript, the
    /// fold dot-product, and the sumcheck. This is the codegen lever: the same
    /// kernels cost 7-15x less when compiled in this small contract than when
    /// inlined into the monolithic engine (via-IR spills the engine's hot loops
    /// to memory; here they stay in registers).
    uint256 public constant QFOLD_MAGIC = 0x5146_4F4C_4400;

    /// @notice The identity did not hold for this instance. Same selector as
    /// the engine's own error, so the bubbled revert is indistinguishable.
    error ConstraintIdentityMismatch(uint256 instance);
    /// @notice The CIDNTY frame was malformed, or its CONFIG section did not
    /// parse exactly to its declared length.
    error BadIdentityFrame(uint256 site, uint256 a, uint256 b);

    using KoalaBearExt4 for uint256;

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

    // ---------------------------------------------------------------------
    // QFOLD: the whole per-query loop (v9), offloaded from the engine
    // ---------------------------------------------------------------------
    //
    // Frame (raw BE 32-byte words):
    //
    //   word 0        magic "QFOLD"
    //   word 1        depth (log folded-domain size)
    //   word 2        nq (query count)
    //   word 3        nD  (pruned digest count)
    //   word 4        rowLimbs (16 base or 64 extension limbs per row)
    //   word 5        rowsAreBase (0/1)
    //   word 6        foldDims (must be 4)
    //   word 7        expectedRoot
    //   words 8..11   prevRandomness (4 packed ext elements)
    //   word 12       gamma (the round batching challenge, drawn by the
    //                 engine BEFORE the frame: the query loop touches no
    //                 transcript state, so drawing it early is identical)
    //   word 13       carriedClaim (packed ext)
    //   word 14       nOod
    //   words 15..    oodAnswers (nOod packed ext words)
    //   then          indices (nq words, sampled by the engine transcript)
    //   then          rows: nq*rowLimbs wire limbs, 4 bytes each, copied
    //                 verbatim from the proof calldata (the satellite's own
    //                 calldata is the frame - the outer tx calldata is not
    //                 visible here, so the rows ride inside the frame)
    //   then          nD digest words (the pruned stream)
    //
    // The satellite decodes each row (wire LE u32 limbs -> Mont byte words
    // for the leaf, packed lanes for the fold), hashes the leaf, folds the
    // row against the randomness with the same 15-fold tree as
    // KoalaBearExt4.evaluate_hypercube (dims-4 unrolled), forms this round's
    // combined claim (carried + gamma-powers over the OOD answers and the
    // folds - the whole phase-7 dot product), then runs the amortized
    // pruned-Merkle walk over the (index, leaf) pairs and checks the root.
    // Reply [magic, root, claimedEval] - the same 96-byte shape as TWIGHT
    // and MROOTS, so the engine's single satellite-call path reads it.
    //
    // Why here and not in the engine: identical kernels cost 7-15x less
    // compiled in this small contract than inlined into the monolithic
    // engine (via-IR stack pressure spills the engine's hot loops). The
    // fold dot-product and everything transcript-bound stays in the engine.
    function _qfold() private pure {
        assembly ("memory-safe") {
            let depth := calldataload(32)
            let nq := calldataload(64)
            let nD := calldataload(96)
            let rowLimbs := calldataload(128)
            let rowsAreBase := calldataload(160)
            if iszero(eq(calldataload(192), 4)) {
                mstore(0, shl(224, 0x09a205cc)) // BadFrameLength()
                revert(0, 4)
            }
            let expectedRoot := calldataload(224)
            let r0 := calldataload(256)
            let r1 := calldataload(288)
            let r2 := calldataload(320)
            let r3 := calldataload(352)
            let gamma := calldataload(384)
            let carried := calldataload(416)
            let nOod := calldataload(448)
            let oodBase := 480 // word 15: the round's OOD answers
            let idxBase := add(oodBase, mul(nOod, 32))
            let rowsAbs := add(idxBase, mul(nq, 32))
            let streamAbs := add(rowsAbs, mul(mul(nq, rowLimbs), 4))
            if iszero(eq(calldatasize(), add(streamAbs, mul(nD, 32)))) {
                mstore(0, shl(224, 0x09a205cc)) // BadFrameLength()
                revert(0, 4)
            }
            let p := 0x7f000001
            let rr := 0x01fffffe
            let q00 := shr(224, r0)
            let q01 := and(shr(192, r0), 0xffffffff)
            let q02 := and(shr(160, r0), 0xffffffff)
            let q03 := and(shr(128, r0), 0xffffffff)
            let q10 := shr(224, r1)
            let q11 := and(shr(192, r1), 0xffffffff)
            let q12 := and(shr(160, r1), 0xffffffff)
            let q13 := and(shr(128, r1), 0xffffffff)
            let q20 := shr(224, r2)
            let q21 := and(shr(192, r2), 0xffffffff)
            let q22 := and(shr(160, r2), 0xffffffff)
            let q23 := and(shr(128, r2), 0xffffffff)
            let q30 := shr(224, r3)
            let q31 := and(shr(192, r3), 0xffffffff)
            let q32 := and(shr(160, r3), 0xffffffff)
            let q33 := and(shr(128, r3), 0xffffffff)
            function swap32(x) -> y {
                y := or(
                    or(and(shl(24, x), 0xff000000), and(shl(8, x), 0xff0000)),
                    or(and(shr(8, x), 0xff00), shr(24, x))
                )
            }
            // One fused extension fold: a0 + r*(a1-a0), the exact lane
            // discipline of KoalaBearExt4._fold_once (deferred reductions).
            function foldL(a0, a1, c0, c1, c2, c3) -> o {
                let pm := 0x7f000001
                let M := 0xffffffff
                let W := 3
                let x0 := shr(224, a0)
                let x1 := and(shr(192, a0), M)
                let x2 := and(shr(160, a0), M)
                let x3 := and(shr(128, a0), M)
                let d0 := add(sub(shr(224, a1), x0), pm)
                let d1 := add(sub(and(shr(192, a1), M), x1), pm)
                let d2 := add(sub(and(shr(160, a1), M), x2), pm)
                let d3 := add(sub(and(shr(128, a1), M), x3), pm)
                let t0 := add(mul(c0, d0), mul(W, add(add(mul(c1, d3), mul(c2, d2)), mul(c3, d1))))
                let t1 := add(add(mul(c0, d1), mul(c1, d0)), mul(W, add(mul(c2, d3), mul(c3, d2))))
                let t2 := add(add(add(mul(c0, d2), mul(c1, d1)), mul(c2, d0)), mul(W, mul(c3, d3)))
                let t3 := add(add(add(mul(c0, d3), mul(c1, d2)), mul(c2, d1)), mul(c3, d0))
                o := or(
                    or(shl(224, mod(add(x0, t0), pm)), shl(192, mod(add(x1, t1), pm))),
                    or(shl(160, mod(add(x2, t2), pm)), shl(128, mod(add(x3, t3), pm)))
                )
            }
            // Extension add/mul with the same lane discipline as
            // KoalaBearExt4.add / _mul_packed (the fold dot product).
            function eadd(a, b) -> o {
                let pm := 0x7f000001
                let M := 0xffffffff
                let sum := add(a, b)
                o := or(
                    or(shl(224, mod(shr(224, sum), pm)), shl(192, mod(and(shr(192, sum), M), pm))),
                    or(shl(160, mod(and(shr(160, sum), M), pm)), shl(128, mod(and(shr(128, sum), M), pm)))
                )
            }
            function emul(a, b) -> o {
                let pm := 0x7f000001
                let M := 0xffffffff
                let W := 3
                let x0 := shr(224, a)
                let x1 := and(shr(192, a), M)
                let x2 := and(shr(160, a), M)
                let x3 := and(shr(128, a), M)
                let y0 := shr(224, b)
                let y1 := and(shr(192, b), M)
                let y2 := and(shr(160, b), M)
                let y3 := and(shr(128, b), M)
                let t0 := add(mul(x0, y0), mul(W, add(add(mul(x1, y3), mul(x2, y2)), mul(x3, y1))))
                let t1 := add(add(mul(x0, y1), mul(x1, y0)), mul(W, add(mul(x2, y3), mul(x3, y2))))
                let t2 := add(add(add(mul(x0, y2), mul(x1, y1)), mul(x2, y0)), mul(W, mul(x3, y3)))
                let t3 := add(add(add(mul(x0, y3), mul(x1, y2)), mul(x2, y1)), mul(x3, y0))
                o := or(
                    or(shl(224, mod(t0, pm)), shl(192, mod(t1, pm))),
                    or(shl(160, mod(t2, pm)), shl(128, mod(t3, pm)))
                )
            }
            // Work arrays: fold inputs (16 words), leaf scratch (64 B),
            // Merkle frontiers (nq-sized), fold outputs (nq words).
            let eB := mload(0x40)
            let scratch := add(eB, 512)
            // Leaf scratch: one 4-byte Mont word per wire limb, up to 64
            // limbs (256 B) for extension rows; 64 B suffices for base rows.
            let idxB := add(scratch, 256)
            let digB := add(idxB, mul(nq, 32))
            let nidxB := add(digB, mul(nq, 32))
            let ndigB := add(nidxB, mul(nq, 32))
            let foldB := add(ndigB, mul(nq, 32))
            let mscratch := add(foldB, mul(nq, 32))
            mstore(0x40, add(mscratch, 64))
            for { let q := 0 } lt(q, nq) { q := add(q, 1) } {
                let idx := calldataload(add(idxBase, mul(q, 32)))
                let leaf := 0
                switch rowsAreBase
                case 1 {
                    // 16 base limbs: wire LE u32 -> Mont byte word + lane 0.
                    let hs := add(rowsAbs, mul(mul(q, rowLimbs), 4))
                    for { let j := 0 } lt(j, rowLimbs) { j := add(j, 1) } {
                        let v := swap32(shr(224, calldataload(add(hs, shl(2, j)))))
                        if iszero(lt(v, p)) {
                            mstore(0, shl(224, 0x97a1e05e)) // LimbOutOfRange()
                            mstore(4, v)
                            revert(0, 36)
                        }
                        mstore(add(scratch, shl(2, j)), shl(224, swap32(mod(mul(v, rr), p))))
                        mstore(add(eB, shl(5, j)), shl(224, v))
                    }
                    leaf := keccak256(scratch, 64)
                }
                default {
                    // 64 wire limbs = 16 packed ext elements, 4 limbs per
                    // element, top lane first. One 4-byte load per limb.
                    let hs := add(rowsAbs, mul(mul(q, rowLimbs), 4))
                    for { let e := 0 } lt(e, shr(2, rowLimbs)) { e := add(e, 1) } {
                        let eo := shl(4, e)
                        let c0 := swap32(shr(224, calldataload(add(hs, eo))))
                        let c1 := swap32(shr(224, calldataload(add(hs, add(eo, 4)))))
                        let c2 := swap32(shr(224, calldataload(add(hs, add(eo, 8)))))
                        let c3 := swap32(shr(224, calldataload(add(hs, add(eo, 12)))))
                        if iszero(gt(and(and(sub(c0, p), sub(c1, p)), and(sub(c2, p), sub(c3, p))), 0xffffffff)) {
                            mstore(0, shl(224, 0x97a1e05e)) // LimbOutOfRange()
                            mstore(4, c0)
                            revert(0, 36)
                        }
                        let dp := add(scratch, eo)
                        mstore(dp, shl(224, swap32(mod(mul(c0, rr), p))))
                        mstore(add(dp, 4), shl(224, swap32(mod(mul(c1, rr), p))))
                        mstore(add(dp, 8), shl(224, swap32(mod(mul(c2, rr), p))))
                        mstore(add(dp, 12), shl(224, swap32(mod(mul(c3, rr), p))))
                        mstore(add(eB, shl(5, e)),
                            or(or(shl(224, c0), shl(192, c1)), or(shl(160, c2), shl(128, c3))))
                    }
                    leaf := keccak256(scratch, 256)
                }
                // dims-4 fold tree: 16 elements at eB -> 1 value.
                let l0 := foldL(mload(add(eB, 0)),   mload(add(eB, 256)), q00, q01, q02, q03)
                let l1 := foldL(mload(add(eB, 32)),  mload(add(eB, 288)), q00, q01, q02, q03)
                let l2 := foldL(mload(add(eB, 64)),  mload(add(eB, 320)), q00, q01, q02, q03)
                let l3 := foldL(mload(add(eB, 96)),  mload(add(eB, 352)), q00, q01, q02, q03)
                let l4 := foldL(mload(add(eB, 128)), mload(add(eB, 384)), q00, q01, q02, q03)
                let l5 := foldL(mload(add(eB, 160)), mload(add(eB, 416)), q00, q01, q02, q03)
                let l6 := foldL(mload(add(eB, 192)), mload(add(eB, 448)), q00, q01, q02, q03)
                let l7 := foldL(mload(add(eB, 224)), mload(add(eB, 480)), q00, q01, q02, q03)
                let m0 := foldL(l0, l4, q10, q11, q12, q13)
                let m1 := foldL(l1, l5, q10, q11, q12, q13)
                let m2 := foldL(l2, l6, q10, q11, q12, q13)
                let m3 := foldL(l3, l7, q10, q11, q12, q13)
                let n0 := foldL(m0, m2, q20, q21, q22, q23)
                let n1 := foldL(m1, m3, q20, q21, q22, q23)
                let fv := foldL(n0, n1, q30, q31, q32, q33)
                mstore(add(idxB, mul(q, 32)), idx)
                mstore(add(digB, mul(q, 32)), leaf)
                mstore(add(foldB, mul(q, 32)), fv)
            }
            // --- phase-7 dot product: carried + gamma-powers over OOD, folds ---
            let claimed := carried
            let power := gamma // gamma^1: the carried claim owns gamma^0
            for { let i := 0 } lt(i, nOod) { i := add(i, 1) } {
                claimed := eadd(claimed, emul(calldataload(add(oodBase, mul(i, 32))), power))
                power := emul(power, gamma)
            }
            for { let q := 0 } lt(q, nq) { q := add(q, 1) } {
                claimed := eadd(claimed, emul(mload(add(foldB, mul(q, 32))), power))
                power := emul(power, gamma)
            }
            // --- amortized pruned Merkle walk (identical to _mroots) ---
            // Insertion sort by index, carrying leaves.
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
            let w := 0
            for { let lvl := 0 } lt(lvl, depth) { lvl := add(lvl, 1) } {
                let m := 0
                let i := 0
                for { } lt(i, u) { } {
                    let ii := mload(add(idxB, mul(i, 32)))
                    let par := shr(1, ii)
                    let left := mload(add(digB, mul(i, 32)))
                    let right := 0
                    let paired := 0
                    if lt(add(i, 1), u) {
                        if eq(shr(1, mload(add(idxB, mul(add(i, 1), 32)))), par) { paired := 1 }
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
                        case 0 { right := calldataload(add(streamAbs, mul(w, 32))) }
                        default {
                            right := left
                            left := calldataload(add(streamAbs, mul(w, 32)))
                        }
                        w := add(w, 1)
                        i := add(i, 1)
                    }
                    mstore(mscratch, left)
                    mstore(add(mscratch, 32), right)
                    mstore(add(nidxB, mul(m, 32)), par)
                    mstore(add(ndigB, mul(m, 32)), keccak256(mscratch, 64))
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
            // Reply [magic, root, claimedEval]: the same 96-byte shape as
            // TWIGHT and MROOTS, so the engine's single satellite path reads
            // it. The root rode back only for debug - the compare above
            // already pinned it against the frame's expectedRoot.
            mstore(0, 0x51464F4C4400) // QFOLD_MAGIC
            mstore(32, mload(digB))
            mstore(64, claimed)
            return(0, 96)
        }
    }

    // ---------------------------------------------------------------------
    // CIDNTY: the constraint identity (D-076), offloaded from the engine
    // ---------------------------------------------------------------------
    //
    // Frame (raw BE 32-byte words; the CONFIG section is the wire's raw
    // little-endian u32 stream, copied verbatim):
    //
    //   [0] CIDNTY_MAGIC
    //   [1] zeta  [2] constraintAlpha  [3] lookupAlpha  [4] beta
    //   [5] nTerm, then nTerm packed-ext terminal words
    //   [6] nStm, then nStm canonical-u32 statement words
    //   [7] cfgWords, then cfgWords*4 raw CONFIG CONSTRAINTS bytes
    //   then for rounds 1..4: boundLen, then boundLen packed-ext words
    //
    // The satellite parses CONSTRAINTS itself (node programs stay in the
    // frame's calldata, read in place), rebuilds every opened value from the
    // bound evaluations the engine's walk just verified, and checks
    // fold(alpha, C(zeta)) * inv_vanishing == Q(zeta) per instance. A
    // mismatch reverts with the engine's own error selector; the codehash
    // pin means the engine trusts this code, exactly as for MROOTS.

    /// The subset of the CONSTRAINTS config the claim layout walks.
    struct IdentityCfg {
        uint256 n;
        uint256[] width;
        uint256[] preWidth;
        uint256[] auxWidth;
        bool[] hasMainNext;
        bool[] hasPreNext;
        uint256[] numChunks;
        uint256[][] roundArities;
    }

    /// The claims of one opening round: widths, owning matrix, arity, point
    /// index (0 = zeta, 1 = zeta_next of the matrix). Ported verbatim from
    /// the engine (batch 48) - including the round-2 arity quirk (ar[j]).
    struct ClaimLayout {
        uint256 count;
        uint256[] widths;
        uint256[] matrix;
        uint256[] arities;
        uint256[] point;
    }

    function _claimLayoutS(IdentityCfg memory c, uint256 round)
        private
        pure
        returns (ClaimLayout memory L)
    {
        uint256 n = c.n;
        uint256[] memory ar = c.roundArities[round];
        if (round == 1 || round == 3) {
            uint256 cnt = 0;
            for (uint256 i; i < n; ++i) {
                cnt += (round == 1 ? c.hasMainNext[i] : c.hasPreNext[i]) ? 2 : 1;
            }
            L.count = cnt;
            L.widths = new uint256[](cnt);
            L.matrix = new uint256[](cnt);
            L.arities = new uint256[](cnt);
            L.point = new uint256[](cnt);
            uint256 j = 0;
            for (uint256 i; i < n; ++i) {
                uint256 w = round == 1 ? c.width[i] : c.preWidth[i];
                uint256 reps = (round == 1 ? c.hasMainNext[i] : c.hasPreNext[i]) ? 2 : 1;
                for (uint256 q; q < reps; ++q) {
                    L.widths[j] = w;
                    L.matrix[j] = i;
                    L.arities[j] = ar[i];
                    L.point[j] = q;
                    j++;
                }
            }
        } else if (round == 2) {
            uint256 cnt = 0;
            for (uint256 i; i < n; ++i) {
                cnt += c.numChunks[i];
            }
            L.count = cnt;
            L.widths = new uint256[](cnt);
            L.matrix = new uint256[](cnt);
            L.arities = new uint256[](cnt);
            L.point = new uint256[](cnt);
            uint256 j = 0;
            for (uint256 i; i < n; ++i) {
                for (uint256 q; q < c.numChunks[i]; ++q) {
                    L.widths[j] = 4;
                    L.matrix[j] = i;
                    L.arities[j] = ar[j];
                    L.point[j] = 0;
                    j++;
                }
            }
        } else {
            uint256 cnt = 2 * n;
            L.count = cnt;
            L.widths = new uint256[](cnt);
            L.matrix = new uint256[](cnt);
            L.arities = new uint256[](cnt);
            L.point = new uint256[](cnt);
            uint256 j = 0;
            for (uint256 i; i < n; ++i) {
                for (uint256 q; q < 2; ++q) {
                    L.widths[j] = 4 * c.auxWidth[i];
                    L.matrix[j] = i;
                    L.arities[j] = ar[i];
                    L.point[j] = q;
                    j++;
                }
            }
        }
    }

    /// claimed = bound * scale, element-wise, w values from off.
    function _claimed(uint256[] memory bound, uint256 off, uint256 w, uint256 sc)
        private
        pure
        returns (uint256[] memory out)
    {
        out = new uint256[](w);
        for (uint256 j; j < w; ++j) {
            out[j] = bound[off + j].mul(sc);
        }
    }

    /// fromExt4 over each 4-value group of the w claimed values.
    function _fromExt4Group(uint256[] memory bound, uint256 off, uint256 w, uint256 sc)
        private
        pure
        returns (uint256[] memory out)
    {
        out = new uint256[](w / 4);
        for (uint256 j; j < w / 4; ++j) {
            uint256[] memory vals = new uint256[](4);
            for (uint256 q; q < 4; ++q) {
                vals[q] = bound[off + 4 * j + q].mul(sc);
            }
            out[j] = _fromExt4(vals, 0);
        }
    }

    /// Horner evaluation of a quartic at x (the EF4 class of the
    /// indeterminate) from four consecutive claimed extension values.
    function _fromExt4(uint256[] memory vals, uint256 off) private pure returns (uint256) {
        uint256 x = uint256(1) << 192;
        uint256 acc = vals[off + 3];
        acc = acc.mul(x).add(vals[off + 2]);
        acc = acc.mul(x).add(vals[off + 1]);
        return acc.mul(x).add(vals[off]);
    }

    /// prod_{i<k}(1 + z^{2^i}): the univariate-eq scale of a claim group.
    function _claimScale(uint256 z, uint256 k) private pure returns (uint256) {
        uint256 sc = KoalaBearExt4.ONE;
        uint256 y = z;
        for (uint256 i; i < k; ++i) {
            sc = sc.mul(KoalaBearExt4.ONE.add(y));
            y = y.square();
        }
        return sc;
    }

    /// A wire LE u32 array at byte offset `at`: count then count LE words.
    function _leArr(uint256 at) private pure returns (uint256[] memory out, uint256 next) {
        uint256 n = _leWordAt(at);
        out = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            out[i] = _leWordAt(at + 4 + 4 * i);
        }
        next = at + 4 + 4 * n;
    }

    /// Pack flat u32 extension limbs (4 per value) into packed quartics.
    function _packQuartics(uint256[] memory flat)
        private
        pure
        returns (uint256[] memory out)
    {
        out = new uint256[](flat.length / 4);
        for (uint256 j; j < out.length; ++j) {
            out[j] = (flat[4 * j] << 224) | (flat[4 * j + 1] << 192) | (flat[4 * j + 2] << 160)
                | (flat[4 * j + 3] << 128);
        }
    }

    /// Two-adic generators (p3-koala-bear TWO_ADIC_GENERATORS), duplicated
    /// from the engine so the satellite stands alone.
    uint256 private constant G0 = 0x1;
    uint256 private constant G1 = 0x7f00_0000;
    uint256 private constant G2 = 0x7e01_0002;
    uint256 private constant G3 = 0x6832_fe4a;
    uint256 private constant G4 = 0x08db_d69c;
    uint256 private constant G5 = 0x0a28_f031;
    uint256 private constant G6 = 0x5c4a_5b99;
    uint256 private constant G7 = 0x29b7_5a80;
    uint256 private constant G8 = 0x1766_8b8a;
    uint256 private constant G9 = 0x27ad_539b;
    uint256 private constant G10 = 0x334d_48c7;
    uint256 private constant G11 = 0x7744_959c;
    uint256 private constant G12 = 0x768f_c6fa;
    uint256 private constant G13 = 0x3039_64b2;
    uint256 private constant G14 = 0x3e68_7d4d;
    uint256 private constant G15 = 0x45a6_0e61;
    uint256 private constant G16 = 0x6e2f_4d7a;
    uint256 private constant G17 = 0x163b_d499;
    uint256 private constant G18 = 0x6c4a_8a45;
    uint256 private constant G19 = 0x143e_f899;
    uint256 private constant G20 = 0x514d_dcad;
    uint256 private constant G21 = 0x484e_f19b;
    uint256 private constant G22 = 0x205d_63c3;
    uint256 private constant G23 = 0x68e7_dd49;
    uint256 private constant G24 = 0x6ac4_9f88;

    function _twoAdic(uint256 k) private pure returns (uint256) {
        if (k == 0) return G0;
        if (k == 1) return G1;
        if (k == 2) return G2;
        if (k == 3) return G3;
        if (k == 4) return G4;
        if (k == 5) return G5;
        if (k == 6) return G6;
        if (k == 7) return G7;
        if (k == 8) return G8;
        if (k == 9) return G9;
        if (k == 10) return G10;
        if (k == 11) return G11;
        if (k == 12) return G12;
        if (k == 13) return G13;
        if (k == 14) return G14;
        if (k == 15) return G15;
        if (k == 16) return G16;
        if (k == 17) return G17;
        if (k == 18) return G18;
        if (k == 19) return G19;
        if (k == 20) return G20;
        if (k == 21) return G21;
        if (k == 22) return G22;
        if (k == 23) return G23;
        if (k == 24) return G24;
        revert BadIdentityFrame(4, k, 0);
    }

    /// The whole constraint identity for every instance, from the frame.
    function _cidnty() private pure {
        uint256 c = 32;
        uint256 zeta = _cdWord(c); c += 32;
        uint256 alpha = _cdWord(c); c += 32;
        uint256 lookupAlpha = _cdWord(c); c += 32;
        uint256 beta = _cdWord(c); c += 32;

        uint256 nTerm = _cdWord(c); c += 32;
        uint256[] memory terminals = new uint256[](nTerm);
        assembly ("memory-safe") { calldatacopy(add(terminals, 32), c, mul(nTerm, 32)) }
        c += nTerm * 32;

        uint256 nStm = _cdWord(c); c += 32;
        uint256[] memory statement = new uint256[](nStm);
        assembly ("memory-safe") { calldatacopy(add(statement, 32), c, mul(nStm, 32)) }
        c += nStm * 32;

        uint256 cfgWords = _cdWord(c); c += 32;
        uint256 cfg = c;
        c += cfgWords * 4;

        uint256[][] memory boundEvalsOf = new uint256[][](5);
        for (uint256 r = 1; r <= 4; ++r) {
            uint256 bl = _cdWord(c); c += 32;
            uint256[] memory b = new uint256[](bl);
            assembly ("memory-safe") { calldatacopy(add(b, 32), c, mul(bl, 32)) }
            c += bl * 32;
            boundEvalsOf[r] = b;
        }
        if (c != msg.data.length) revert BadIdentityFrame(1, c, msg.data.length);

        uint256 p = cfg;
        uint256 n = _leWordAt(p); p += 4;
        uint256 stmInst = _leWordAt(p); p += 4;
        ConstraintIdentity.Program[] memory programs =
            new ConstraintIdentity.Program[](n);
        uint256[] memory width = new uint256[](n);
        uint256[] memory preWidth = new uint256[](n);
        uint256[] memory auxWidth = new uint256[](n);
        bool[] memory hasMainNext = new bool[](n);
        bool[] memory hasPreNext = new bool[](n);
        uint256[] memory traceLogSize = new uint256[](n);
        uint256[] memory traceInvShift = new uint256[](n);
        uint256[] memory traceHInv = new uint256[](n);
        uint256[] memory numChunks = new uint256[](n);
        ConstraintIdentity.ChunkDomain[][] memory chunkDomains =
            new ConstraintIdentity.ChunkDomain[][](n);
        uint256[][] memory invD = new uint256[][](n);
        for (uint256 i; i < n; ++i) {
            width[i] = _leWordAt(p); p += 4;
            preWidth[i] = _leWordAt(p); p += 4;
            auxWidth[i] = _leWordAt(p); p += 4;
            hasMainNext[i] = _leWordAt(p) != 0; p += 4;
            hasPreNext[i] = _leWordAt(p) != 0; p += 4;
            p += 4; // numConstraints: roots.length is authoritative
            uint256 nNodes = _leWordAt(p); p += 4;
            programs[i].nodesCdBase = p;
            programs[i].nodesLen = nNodes;
            p += nNodes * 4;
            (programs[i].baseConsts, p) = _leArr(p);
            uint256[] memory extFlat;
            (extFlat, p) = _leArr(p);
            programs[i].extConsts = _packQuartics(extFlat);
            (programs[i].roots, p) = _leArr(p);
            traceLogSize[i] = _leWordAt(p); p += 4;
            p += 4; // trace shift: selectors work in u = zeta * invShift
            traceInvShift[i] = _leWordAt(p); p += 4;
            traceHInv[i] = _leWordAt(p); p += 4;
            uint256 k = _leWordAt(p); p += 4;
            numChunks[i] = k;
            ConstraintIdentity.ChunkDomain[] memory cds =
                new ConstraintIdentity.ChunkDomain[](k);
            for (uint256 j; j < k; ++j) {
                cds[j].logSize = _leWordAt(p); p += 4;
                p += 4; // shift unused
                cds[j].invShift = _leWordAt(p); p += 4;
            }
            chunkDomains[i] = cds;
            uint256[] memory invDFlat;
            (invDFlat, p) = _leArr(p);
            invD[i] = _packQuartics(invDFlat);
        }
        uint256 maxMsgW = _leWordAt(p); p += 4;
        uint256[][] memory busIds = new uint256[][](n);
        for (uint256 i; i < n; ++i) {
            (busIds[i], p) = _leArr(p);
        }
        bool[] memory hasTerminal = new bool[](n);
        for (uint256 i; i < n; ++i) {
            hasTerminal[i] = _leWordAt(p) != 0; p += 4;
        }
        uint256 nr = _leWordAt(p); p += 4;
        if (nr != 5) revert BadIdentityFrame(2, nr, p);
        uint256[][] memory roundArities = new uint256[][](nr);
        for (uint256 r; r < nr; ++r) {
            (roundArities[r], p) = _leArr(p);
        }
        if (p != cfg + cfgWords * 4) revert BadIdentityFrame(3, p, cfg + cfgWords * 4);

        // --- opened values, exactly as the engine built them (D-076) ---
        uint256[] memory zetaNext = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            zetaNext[i] = zeta.mulBase(_twoAdic(traceLogSize[i]));
        }
        ConstraintIdentity.Opened[] memory opened =
            new ConstraintIdentity.Opened[](n);
        for (uint256 i; i < n; ++i) {
            opened[i].permValues = new uint256[](0);
            opened[i].periodicValues = new uint256[](0);
        }
        uint256[][] memory quotBuf = new uint256[][](n);
        for (uint256 i; i < n; ++i) {
            quotBuf[i] = new uint256[](numChunks[i]);
        }
        uint256 tIdx = 0;
        for (uint256 i; i < n; ++i) {
            if (hasTerminal[i]) {
                opened[i].permValues = new uint256[](1);
                opened[i].permValues[0] = terminals[tIdx];
                tIdx++;
            }
        }
        uint256 betaW = beta;
        for (uint256 w = 1; w < maxMsgW; ++w) {
            betaW = betaW.mul(beta);
        }
        for (uint256 i; i < n; ++i) {
            uint256 nb = busIds[i].length;
            opened[i].permChallenges = new uint256[](2 * nb);
            for (uint256 k = 0; k < nb; ++k) {
                uint256 prefix = lookupAlpha.add(betaW.mulBase(busIds[i][k] + 1));
                opened[i].permChallenges[2 * k] = prefix;
                opened[i].permChallenges[2 * k + 1] = beta;
            }
        }
        if (stmInst < n) {
            opened[stmInst].publicValues = statement;
        }

        for (uint256 round = 1; round <= 4; ++round) {
            IdentityCfg memory icfg = IdentityCfg(
                n, width, preWidth, auxWidth, hasMainNext, hasPreNext, numChunks, roundArities);
            ClaimLayout memory L = _claimLayoutS(icfg, round);
            uint256[] memory bound = boundEvalsOf[round];
            uint256 boff = 0;
            uint256[] memory qIdx = new uint256[](n);
            for (uint256 j; j < L.count; ++j) {
                uint256 mi = L.matrix[j];
                uint256 z = L.point[j] == 0 ? zeta : zetaNext[mi];
                uint256 sc = _claimScale(z, L.arities[j]);
                uint256 w = L.widths[j];
                if (round == 1) {
                    if (L.point[j] == 0) {
                        opened[mi].mainLocal = _claimed(bound, boff, w, sc);
                    } else {
                        opened[mi].mainNext = _claimed(bound, boff, w, sc);
                    }
                } else if (round == 3) {
                    if (L.point[j] == 0) {
                        opened[mi].preLocal = _claimed(bound, boff, w, sc);
                    } else {
                        opened[mi].preNext = _claimed(bound, boff, w, sc);
                    }
                } else if (round == 2) {
                    quotBuf[mi][qIdx[mi]] = _fromExt4Group(bound, boff, w, sc)[0];
                    qIdx[mi]++;
                } else {
                    if (L.point[j] == 0) {
                        opened[mi].permLocal = _fromExt4Group(bound, boff, w, sc);
                    } else {
                        opened[mi].permNext = _fromExt4Group(bound, boff, w, sc);
                    }
                }
                boff += w;
            }
        }

        for (uint256 i; i < n; ++i) {
            ConstraintIdentity.Selectors memory sels = ConstraintIdentity.selectors(
                zeta, traceInvShift[i], traceLogSize[i], traceHInv[i]);
            uint256 fold = ConstraintIdentity.foldConstraints(
                programs[i], opened[i], sels, alpha);
            uint256 quotient = ConstraintIdentity.recomposeQuotient(
                quotBuf[i], chunkDomains[i], invD[i], zeta);
            if (fold.mul(sels.invVanishing) != quotient) {
                revert ConstraintIdentityMismatch(i);
            }
        }
        assembly ("memory-safe") {
            mstore(0, CIDNTY_MAGIC)
            mstore(32, 0)
            mstore(64, 0)
            return(0, 96)
        }
    }

    /// @notice Parse the frame, evaluate the terminal weight and value, and
    /// reply [magic, weight, value]. No mutability modifier: a fallback may
    /// not be declared pure/view, but this body reads no state and the caller
    /// staticcalls it, so ETH can never enter and nothing is written.
    fallback() external {
        if (_head() == QFOLD_MAGIC) {
            // _qfold answers via the return opcode; control never returns.
            _qfold();
        }
        if (_head() == MROOTS_MAGIC) {
            // _mroots answers via the return opcode; control never returns.
            _mroots();
        }
        if (_head() == CIDNTY_MAGIC) {
            // _cidnty answers via the return opcode; control never returns.
            _cidnty();
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
