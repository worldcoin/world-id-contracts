// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

library TypeConverter {
    function toString(address x) public pure returns (string memory) {
        bytes memory s = new bytes(42);
        s[0] = "0";
        s[1] = "x";
        for (uint256 i = 0; i < 20; i++) {
            bytes1 b = bytes1(uint8(uint256(uint160(x)) / (2 ** (8 * (19 - i)))));
            bytes1 hi = bytes1(uint8(b) / 16);
            bytes1 lo = bytes1(uint8(b) - 16 * uint8(hi));
            s[2 * i + 2] = char(hi);
            s[2 * i + 3] = char(lo);
        }
        return string(s);
    }

    function char(bytes1 b) public pure returns (bytes1 c) {
        if (uint8(b) < 10) return bytes1(uint8(b) + 0x30);
        else return bytes1(uint8(b) + 0x57);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                             ARRAY UTILITIES                             ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 1-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint8[1] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 1-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint16[1] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 1-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint32[1] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 1-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint256[1] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 1-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint8[2] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 2-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint16[2] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 2-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint32[2] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 2-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint256[2] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 3-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint8[3] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 3-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint16[3] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 3-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint32[3] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 3-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint256[3] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 1-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint8[4] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 4-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint16[4] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 4-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint32[4] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 4-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint256[4] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 5-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint8[5] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 5-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint16[5] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 5-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint32[5] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 5-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint256[5] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 6-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint8[6] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 6-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint16[6] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 6-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint32[6] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 6-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint256[6] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 7-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint8[7] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 7-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint16[7] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 7-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint32[7] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 7-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint256[7] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 8-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint8[8] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 8-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint16[8] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 8-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint32[8] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 8-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint256[8] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 1-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint8[9] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 9-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint16[9] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 9-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint32[9] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 9-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint256[9] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 1-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint8[10] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 10-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint16[10] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 10-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint32[10] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }

    /// @notice Converts from a fixed-length array to a dynamically sized array.
    /// @dev Overloads only exist for fixed-size arrays from 10-10.
    ///
    /// @param input The fixed size array to convert.
    ///
    /// @return array The dynamically sized array. Its size will match that of `input`.
    function makeDynArray(uint256[10] memory input) public pure returns (uint256[] memory array) {
        array = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            array[i] = input[i];
        }
    }
}
