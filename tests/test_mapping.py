import pytest
from rainbow.generics import rainbow_arm, rainbow_x86

all_mappings = [
    [
        (0x1000, 0x2000),
        # Test: same map
        (0x1000, 0x2000),
    ],
    [
        (0x1000, 0x2000),
        # Test: included map
        (0x1400, 0x1800),
    ],
    [
        (0x1000, 0x2000),
        # Test: distinct map
        (0x5000, 0x6000),
    ],
    [
        (0x1000, 0x2000),
        # Test: contiguous map above
        (0x2000, 0x3000),
    ],
    [
        (0x1000, 0x2000),
        # Test: contiguous map below
        (0x800, 0x1000),
    ],
    [
        (0x1000, 0x2000),
        # Test: overlapping below
        (0x1800, 0x3000),
    ],
    [
        (0x1000, 0x2000),
        # Test: exact overlapping below
        (0x1800, 0x2000),
    ],
    [
        (0x1000, 0x2000),
        # Test: overlapping above
        (0x800, 0x1800),
    ],
    [
        (0x1000, 0x2000),
        # Test: exact overlapping above
        (0x1000, 0x1800),
    ],
    [
        (0x1000, 0x2000),
        (0x3000, 0x4000),
        # Test: contiguous map below and above
        (0x2000, 0x3000),
    ],
    [
        (0x1000, 0x2000),
        # Test: inclusion of previous map
        (0x800, 0x2800),
    ],
    [
        (0x1000, 0x2000),
        (0x3000, 0x4000),
        # Test: multiple inclusions of previous maps
        (0x800, 0x5000),
    ],
    [
        (0x1000, 0x2000),
        (0x3000, 0x4000),
        # Test: inclusion and overlap
        (0x800, 0x3800),
    ],
]


@pytest.mark.parametrize("rainbow_class", [rainbow_arm, rainbow_x86])
@pytest.mark.parametrize("mapping", all_mappings)
def test_map_space(rainbow_class, mapping):
    emu = rainbow_class()
    for region in mapping:
        emu.map_space(*region)


def test_map_space_invalid():
    emu = rainbow_arm()
    with pytest.raises(ValueError):
        emu.map_space(0x2000, 0x1000)
