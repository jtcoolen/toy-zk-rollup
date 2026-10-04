// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {KoalaBear} from "../../lib/sol-whir-p3/field/KoalaBear.sol";
import {KoalaBearExt4} from "../../lib/sol-whir-p3/field/KoalaBearExt4.sol";
import {KeccakChallenger} from "../../lib/sol-whir-p3/transcript/KeccakChallenger.sol";
import {ChunkVerifier} from "../../src/verifier/ChunkVerifier.sol";
import {ConstraintIdentity} from "../../src/verifier/ConstraintIdentity.sol";
import {WhirVerifierCore} from "../../src/verifier/WhirVerifierCore.sol";
import {SumcheckCore} from "../../src/verifier/SumcheckCore.sol";
import {StarkMerkle} from "../../src/verifier/StarkMerkle.sol";
import {StirOpenings} from "../../src/verifier/StirOpenings.sol";
import {ProofCodec} from "../../src/verifier/ProofCodec.sol";

/// EIP-170 size probe: references every verifier layer's entry points so the
/// linker pulls all their code into one deployment artifact. Its runtime size is
/// what a monolithic settlement verifier costs against the 24,576-byte limit.
/// Never deployed; measured with `forge build --sizes`.
contract VerifierSizeProbe {
    function field(uint256 a, uint256 b) external pure returns (uint256) {
        uint256 s = KoalaBearExt4.add(a, b);
        s = KoalaBearExt4.sub(s, KoalaBearExt4.mul(a, b));
        s = KoalaBearExt4.square(s);
        s = KoalaBearExt4.inv(s);
        s = KoalaBearExt4.mulBase(s, KoalaBear.add(a, b));
        s = KoalaBearExt4.mul_by_w(s);
        return s;
    }

    function batch(bytes memory seed, bytes memory degrees) external pure returns (bytes memory) {
        return ChunkVerifier.begin(seed, degrees);
    }

    function chunk(bytes memory carry) external pure returns (bytes memory) {
        return ChunkVerifier.stepOod(carry, 0, 0);
    }

    function constraints(
        ConstraintIdentity.Program memory prog,
        ConstraintIdentity.Opened memory opened,
        ConstraintIdentity.Selectors memory sels,
        uint256 alpha
    ) external pure returns (uint256) {
        return ConstraintIdentity.foldConstraints(prog, opened, sels, alpha);
    }

    function selectors(uint256 zeta, uint256 invShift, uint256 logSize, uint256 hInv)
        external
        pure
        returns (ConstraintIdentity.Selectors memory)
    {
        return ConstraintIdentity.selectors(zeta, invShift, logSize, hInv);
    }

    function sumcheck(uint256 packed) external pure returns (uint256) {
        KeccakChallenger.State memory s;
        SumcheckCore.observeExt4Canonical(s, packed);
        return SumcheckCore.sampleExt4(s);
    }

    function core(uint256 packed, bytes32 digest) external pure returns (uint256) {
        WhirVerifierCore.Transcript memory t;
        WhirVerifierCore.observeExt(t, packed);
        WhirVerifierCore.observeDigest(t, digest);
        return WhirVerifierCore.drawExt(t);
    }

    function merkle(uint256[] memory limbs) external pure returns (bytes32) {
        return StarkMerkle.leafFromLimbs(limbs);
    }

    function stir(uint256[] memory row, uint256[] memory randomness)
        external
        pure
        returns (uint256)
    {
        return StirOpenings.foldRow(row, randomness);
    }

    /// The heavy phase entry points. Empty schedules/inputs are fine: the linker
    /// pulls the code regardless, and this contract is never executed.
    function phases(WhirVerifierCore.Transcript memory t) external pure {
        WhirVerifierCore.InitialSchedule memory isch;
        WhirVerifierCore.InitialInput memory iin;
        WhirVerifierCore.verifyInitial(t, isch, iin);
        WhirVerifierCore.RoundSchedule memory rsch;
        WhirVerifierCore.RoundInput memory rin;
        WhirVerifierCore.verifyRound(t, rsch, rin, 0);
        WhirVerifierCore.FinalSchedule memory fsch;
        WhirVerifierCore.FinalInput memory fin;
        WhirVerifierCore.verifyFinal(t, fsch, fin, 0);
    }

    function stirOpen(
        bytes32 root,
        uint256 index,
        uint256 depth,
        uint256[] memory limbs,
        uint256[] memory row,
        bytes32[] memory siblings,
        uint256[] memory randomness
    ) external pure returns (uint256) {
        return StirOpenings.openAndFold(root, index, depth, limbs, row, siblings, randomness);
    }

    function merkleVerify(
        bytes32 root,
        uint256 index,
        bytes32 leafDigest,
        bytes32[] memory siblings
    ) external pure returns (bool) {
        return StarkMerkle.verify(root, index, leafDigest, siblings, siblings.length);
    }

    function recompose(
        uint256[] memory chunks,
        ConstraintIdentity.ChunkDomain[] memory domains,
        uint256[] memory invD,
        uint256 zeta
    ) external pure returns (uint256) {
        return ConstraintIdentity.recomposeQuotient(chunks, domains, invD, zeta);
    }

    function codec(bytes calldata proof) external pure returns (bytes32) {
        ProofCodec.Cursor memory c = ProofCodec.start();
        (bytes32 digest,) = ProofCodec.readDigest(proof, c);
        return digest;
    }
}
