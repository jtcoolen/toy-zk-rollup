// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import {Test, console} from "forge-std/Test.sol";
import {WhirGadgets} from "../src/verifier/WhirGadgets.sol";
import {KoalaBearExt4} from "../lib/sol-whir-p3/field/KoalaBearExt4.sol";
contract EqSelDiffTest is Test {
    function mk(uint256 t, uint256 i) internal pure returns (uint256) {
        uint256 P = 0x7f000001;
        uint256[4] memory cs;
        cs[0] = uint256(keccak256(abi.encode(t, i, 0))) % P;
        cs[1] = uint256(keccak256(abi.encode(t, i, 1))) % P;
        cs[2] = uint256(keccak256(abi.encode(t, i, 2))) % P;
        cs[3] = uint256(keccak256(abi.encode(t, i, 3))) % P;
        return KoalaBearExt4.pack(cs);
    }
    function oldSel(uint256[] memory localR, uint256 arity, uint256 selIndex)
        internal
        pure
        returns (uint256)
    {
        uint256 nv = localR.length - arity;
        uint256 s = KoalaBearExt4.ONE;
        for (uint256 j; j < nv; ++j) {
            uint256 r = localR[arity + j];
            bool one = ((selIndex >> (nv - 1 - j)) & 1) == 1;
            s = one ? KoalaBearExt4.mul(s, r) : KoalaBearExt4.mul(s, KoalaBearExt4.sub(KoalaBearExt4.ONE, r));
        }
        return s;
    }
    function check(uint256 k, uint256 arity, uint256 sel) internal pure {
        uint256[] memory localR = new uint256[](k);
        for (uint256 i; i < k; ++i) { localR[i] = mk(7, i); }
        uint256 a = oldSel(localR, arity, sel);
        uint256 b = WhirGadgets.eqSelectorValue(localR, arity, sel);
        require(a == b, "MISMATCH");
    }
    function test_diff() public pure {
        for (uint256 k = 1; k <= 24; ++k) {
            for (uint256 arity = 0; arity < k; ++arity) {
                uint256 nv = k - arity;
                uint256 lim = nv >= 20 ? 20 : nv;
                for (uint256 s = 0; s < lim; ++s) {
                    uint256 sel = uint256(keccak256(abi.encode(k, arity, s))) % (uint256(1) << nv);
                    check(k, arity, sel);
                }
            }
        }
    }
}
