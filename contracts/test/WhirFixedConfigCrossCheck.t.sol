// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {WhirFixedConfig} from "../src/verifier/WhirFixedConfig.sol";
import {KoalaBear} from "../lib/sol-whir-p3/field/KoalaBear.sol";

/// Cross-check the generated `WhirFixedConfig` against the JSON the prover
/// emitted from the same `FixedSchedule`.
///
/// This is not redundant with the generator. The JSON is produced by serde
/// from the Rust struct's field names; the Solidity library is produced by a
/// hand-written `format!` template. If the template maps a value to the
/// wrong constant — say `final_pow` into `POW_BITS` — the JSON still carries
/// the correct `final_round.pow_bits`, and this test catches the mismatch.
/// The generator's own round-trip test cannot see that class of bug because
/// both sides come from the same template.
///
/// Regenerate both with:
///     cargo test -p prover fixed_config -- --ignored --nocapture
/// External wrapper so an out-of-range revert lands at a deeper call depth
/// than the `expectRevert` cheatcode. The library's functions are `internal
/// pure` and get inlined, and an inlined revert is at the same depth as the
/// cheatcode call, which `expectRevert` does not count.
contract FixedConfigProbe {
    function round(uint256 i) external pure returns (WhirFixedConfig.RoundConfig memory) {
        return WhirFixedConfig.roundConfig(i);
    }

    function fold(uint256 i) external pure returns (uint256) {
        return WhirFixedConfig.foldingSchedule(i);
    }
}

contract WhirFixedConfigCrossCheckTest is Test {
    FixedConfigProbe internal probe = new FixedConfigProbe();
    string internal constant VECTOR = "test/vectors/whir_fixed_config.json";

    function test_scalar_constants_match_json() public view {
        string memory json = vm.readFile(VECTOR);

        assertEq(
            WhirFixedConfig.NUM_VARIABLES,
            vm.parseJsonUint(json, ".num_variables"),
            "NUM_VARIABLES"
        );
        assertEq(
            WhirFixedConfig.MAX_LOG_DOMAIN_SIZE,
            vm.parseJsonUint(json, ".max_log_domain_size"),
            "MAX_LOG_DOMAIN_SIZE"
        );
        assertEq(
            WhirFixedConfig.COMMITMENT_OOD_SAMPLES,
            vm.parseJsonUint(json, ".commitment_ood_samples"),
            "COMMITMENT_OOD_SAMPLES"
        );
        assertEq(
            WhirFixedConfig.STARTING_FOLDING_POW_BITS,
            vm.parseJsonUint(json, ".starting_folding_pow_bits"),
            "STARTING_FOLDING_POW_BITS"
        );
        assertEq(
            WhirFixedConfig.TERMINAL_NUM_QUERIES,
            vm.parseJsonUint(json, ".terminal_num_queries"),
            "TERMINAL_NUM_QUERIES"
        );
        assertEq(
            WhirFixedConfig.TERMINAL_POW_BITS,
            vm.parseJsonUint(json, ".terminal_pow_bits"),
            "TERMINAL_POW_BITS"
        );
        assertEq(
            WhirFixedConfig.FINAL_SUMCHECK_ROUNDS,
            vm.parseJsonUint(json, ".final_sumcheck_rounds"),
            "FINAL_SUMCHECK_ROUNDS"
        );
        assertEq(
            WhirFixedConfig.FINAL_FOLDING_POW_BITS,
            vm.parseJsonUint(json, ".final_folding_pow_bits"),
            "FINAL_FOLDING_POW_BITS"
        );
        assertEq(
            WhirFixedConfig.STARTING_LOG_INV_RATE,
            vm.parseJsonUint(json, ".starting_log_inv_rate"),
            "STARTING_LOG_INV_RATE"
        );
        assertEq(
            WhirFixedConfig.SECURITY_LEVEL,
            vm.parseJsonUint(json, ".security_level"),
            "SECURITY_LEVEL"
        );
        assertEq(WhirFixedConfig.POW_BITS, vm.parseJsonUint(json, ".pow_bits"), "POW_BITS");
        assertEq(WhirFixedConfig.N_ROUNDS, vm.parseJsonUint(json, ".n_rounds"), "N_ROUNDS");

        // `total_queries` is a derived method on the Rust side, so it is not
        // a JSON field. Recompute it from the rounds and the terminal count
        // and check the library's constant against that.
        uint256 total = vm.parseJsonUint(json, ".terminal_num_queries");
        uint256 nRounds = vm.parseJsonUint(json, ".n_rounds");
        for (uint256 i; i < nRounds; ++i) {
            total +=
                vm.parseJsonUint(json, string.concat(".rounds[", vm.toString(i), "].num_queries"));
        }
        assertEq(WhirFixedConfig.TOTAL_QUERIES, total, "TOTAL_QUERIES");
    }

    function test_final_round_matches_json() public view {
        string memory json = vm.readFile(VECTOR);
        WhirFixedConfig.RoundConfig memory f = WhirFixedConfig.finalRoundConfig();

        assertEq(f.powBits, vm.parseJsonUint(json, ".final_round.pow_bits"), "final powBits");
        assertEq(
            f.foldingPowBits,
            vm.parseJsonUint(json, ".final_round.folding_pow_bits"),
            "final foldingPowBits"
        );
        assertEq(
            f.numQueries,
            vm.parseJsonUint(json, ".final_round.num_queries"),
            "final numQueries"
        );
        assertEq(
            f.numVariables,
            vm.parseJsonUint(json, ".final_round.num_variables"),
            "final numVariables"
        );
        assertEq(
            f.foldingFactor,
            vm.parseJsonUint(json, ".final_round.folding_factor"),
            "final foldingFactor"
        );
        assertEq(f.logInvRate, vm.parseJsonUint(json, ".final_round.log_inv_rate"), "final logInvRate");
        assertEq(
            f.domainSize,
            vm.parseJsonUint(json, ".final_round.domain_size"),
            "final domainSize"
        );
        assertEq(
            f.logFoldedDomainSize,
            vm.parseJsonUint(json, ".final_round.log_folded_domain_size"),
            "final logFoldedDomainSize"
        );
        assertEq(
            f.foldedDomainGen,
            vm.parseJsonUint(json, ".final_round.folded_domain_gen"),
            "final foldedDomainGen"
        );
    }

    function test_every_round_matches_json() public view {
        string memory json = vm.readFile(VECTOR);
        uint256 nRounds = vm.parseJsonUint(json, ".n_rounds");
        assertEq(nRounds, WhirFixedConfig.N_ROUNDS, "round count");

        for (uint256 i; i < nRounds; ++i) {
            WhirFixedConfig.RoundConfig memory r = WhirFixedConfig.roundConfig(i);
            string memory base = string.concat(".rounds[", vm.toString(i), "]");
            assertEq(r.powBits, vm.parseJsonUint(json, string.concat(base, ".pow_bits")), "powBits");
            assertEq(
                r.foldingPowBits,
                vm.parseJsonUint(json, string.concat(base, ".folding_pow_bits")),
                "foldingPowBits"
            );
            assertEq(
                r.numQueries,
                vm.parseJsonUint(json, string.concat(base, ".num_queries")),
                "numQueries"
            );
            assertEq(
                r.oodSamples,
                vm.parseJsonUint(json, string.concat(base, ".ood_samples")),
                "oodSamples"
            );
            assertEq(
                r.numVariables,
                vm.parseJsonUint(json, string.concat(base, ".num_variables")),
                "numVariables"
            );
            assertEq(
                r.foldingFactor,
                vm.parseJsonUint(json, string.concat(base, ".folding_factor")),
                "foldingFactor"
            );
            assertEq(
                r.logInvRate,
                vm.parseJsonUint(json, string.concat(base, ".log_inv_rate")),
                "logInvRate"
            );
            assertEq(
                r.domainSize,
                vm.parseJsonUint(json, string.concat(base, ".domain_size")),
                "domainSize"
            );
            assertEq(
                r.logFoldedDomainSize,
                vm.parseJsonUint(json, string.concat(base, ".log_folded_domain_size")),
                "logFoldedDomainSize"
            );
            assertEq(
                r.foldedDomainGen,
                vm.parseJsonUint(json, string.concat(base, ".folded_domain_gen")),
                "foldedDomainGen"
            );
        }
    }

    /// Each round's folded-domain generator must really generate a domain of
    /// the size the schedule claims: order exactly 2^logFoldedDomainSize.
    ///
    /// Why this is a security property and not a sanity check: the STIR query
    /// phase maps a sampled index to `gen^index`, and the verifier recomputes
    /// that point to bind the opened leaf. A generator of the wrong order
    /// would make the verifier evaluate the domain constraint at a point that
    /// is not in the committed domain, so the STIR proximity test would be
    /// performed against the wrong set of points.
    ///
    /// Order is exactly 2^k when `g^(2^k) == 1` and `g^(2^(k-1)) != 1`.
    function test_folded_domain_generators_have_the_claimed_order() public pure {
        uint256 nRounds = WhirFixedConfig.N_ROUNDS;
        for (uint256 i; i < nRounds; ++i) {
            _checkGeneratorOrder(WhirFixedConfig.roundConfig(i), i);
        }
        _checkGeneratorOrder(WhirFixedConfig.finalRoundConfig(), nRounds);
    }

    function _checkGeneratorOrder(WhirFixedConfig.RoundConfig memory r, uint256 phase)
        private
        pure
    {
        uint256 g = r.foldedDomainGen;
        uint256 k = r.logFoldedDomainSize;
        // g^(2^k) == 1: k repeated squarings from g.
        uint256 acc = g;
        uint256 half = 1;
        for (uint256 j; j < k; ++j) {
            if (j == k - 1) {
                half = acc;
            }
            acc = KoalaBear.mul(acc, acc);
        }
        assertEq(acc, 1, "generator order does not divide domain size");
        assertTrue(half != 1, "generator order is smaller than the domain");
        assertEq(
            KoalaBear.pow(r.foldedDomainGen, r.domainSize >> r.foldingFactor),
            1,
            "generator^folded_domain_size must be one"
        );
        assertTrue(phase < 100, "phase index sanity");
    }

    function test_folding_schedule_matches_json() public view {
        string memory json = vm.readFile(VECTOR);
        uint256[] memory sched = vm.parseJsonUintArray(json, ".folding_schedule");
        uint256 len = sched.length;
        for (uint256 i; i < len; ++i) {
            assertEq(
                WhirFixedConfig.foldingSchedule(i),
                sched[i],
                "folding schedule entry"
            );
        }
    }

    /// The out-of-range accessors must revert, not return a default. A
    /// silent zero would fold nothing while looking like it folded.
    function test_out_of_range_reverts() public {
        vm.expectRevert(bytes("ROUND_INDEX"));
        probe.round(WhirFixedConfig.N_ROUNDS);

        vm.expectRevert(bytes("FOLD_INDEX"));
        probe.fold(999);
    }
}