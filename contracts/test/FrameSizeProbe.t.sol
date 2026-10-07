// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {WhirVerifierP} from "./WhirVerifierP.sol";
import {TerminalWeight} from "../src/verifier/TerminalWeight.sol";

/// Records every TWIGHT frame size, then forwards to the real satellite.
/// WhirVerifierP uses a plain call (fork-only change) so this contract can
/// write storage; the real TerminalWeight still does all the math.
contract FrameLogger {
    address public immutable REAL;
    uint256[] public sizes;
    uint256[] public satGas;

    constructor(address real_) {
        REAL = real_;
    }

    function count() external view returns (uint256) {
        return sizes.length;
    }

    function gasAt(uint256 i) external view returns (uint256) {
        return satGas[i];
    }

    fallback() external {
        sizes.push(msg.data.length);
        uint256 g = gasleft();
        (bool ok, bytes memory ret) = REAL.staticcall(msg.data);
        satGas.push(g - gasleft());
        require(ok, "satellite failed");
        assembly {
            return(add(ret, 32), mload(ret))
        }
    }
}

contract FrameSizeProbeTest is Test {
    function test_frame_sizes() public {
        FrameLogger logger = new FrameLogger(address(new TerminalWeight()));
        WhirVerifierP p = new WhirVerifierP(address(logger));
        string memory j = vm.readFile("test/vectors/recursion_chain_sidecar.json");
        uint256[] memory statement = vm.parseJsonUintArray(j, ".statement");
        bytes memory bundle = vm.readFileBinary("test/vectors/recursion_chain_bundle.bin");
        (bool ok,) = p.verifyProfiled(statement, bundle);
        assertTrue(ok);
        uint256 total;
        for (uint256 i; i < logger.count(); ++i) {
            uint256 sz = logger.sizes(i);
            total += sz;
            emit log_named_uint("frame bytes (round)", sz);
        }
        emit log_named_uint("total frame bytes", total);
        uint256 satTotal;
        for (uint256 i; i < logger.count(); ++i) {
            uint256 g = logger.gasAt(i);
            satTotal += g;
            emit log_named_uint("satellite gas (round)", g);
        }
        emit log_named_uint("total satellite gas", satTotal);
    }
}
