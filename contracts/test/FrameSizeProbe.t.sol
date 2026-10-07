// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {WhirVerifierP} from "./WhirVerifierP.sol";
import {TerminalWeightP} from "./TerminalWeightP.sol";

/// Forwards to the instrumented satellite and records frame sizes.
contract FrameLogger {
    address public immutable REAL;
    uint256[] public sizes;

    constructor(address real_) {
        REAL = real_;
    }

    function count() external view returns (uint256) {
        return sizes.length;
    }

    fallback() external {
        sizes.push(msg.data.length);
        (bool ok, bytes memory ret) = REAL.call(msg.data);
        require(ok, "satellite failed");
        assembly {
            return(add(ret, 32), mload(ret))
        }
    }
}

contract FrameSizeProbeTest is Test {
    function test_frame_sizes() public {
        TerminalWeightP sat = new TerminalWeightP();
        FrameLogger logger = new FrameLogger(address(sat));
        WhirVerifierP p = new WhirVerifierP(address(logger));
        string memory j = vm.readFile("test/vectors/recursion_chain_sidecar.json");
        uint256[] memory statement = vm.parseJsonUintArray(j, ".statement");
        bytes memory bundle = vm.readFileBinary("test/vectors/recursion_chain_bundle.bin");
        (bool ok,) = p.verifyProfiled(statement, bundle);
        assertTrue(ok);
        emit log_named_uint("parse gas", sat.gParse());
        emit log_named_uint("derive gas", sat.gDerive());
        emit log_named_uint("hyper gas", sat.gHyper());
        uint256 evalTotal;
        for (uint256 i; i < sat.perConstraintGas_length(); ++i) {
            evalTotal += sat.perConstraintGas(i);
        }
        emit log_named_uint("constraint eval gas", evalTotal);
        uint256 idx;
        for (uint256 r; r < sat.perCallCount_length(); ++r) {
            uint256 n = sat.perCallCount(r);
            uint256 roundTotal;
            for (uint256 i; i < n; ++i) {
                uint256 g = sat.perConstraintGas(idx);
                roundTotal += g;
                if (g > 300_000) {
                    emit log_named_uint("  round", r);
                    emit log_named_uint("    constraint idx", idx);
                    emit log_named_uint("      gas", g);
                    emit log_named_uint("      k", sat.perConstraintK(idx));
                    emit log_named_uint("      mode", sat.perConstraintMode(idx));
                    emit log_named_uint("      groups", sat.perConstraintGroups(idx));
                    emit log_named_uint("      selVars", sat.perConstraintSel(idx));
                }
                ++idx;
            }
            emit log_named_uint("round total", roundTotal);
        }
    }
}
