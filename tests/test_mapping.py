import pytest
from rainbow.generics import rainbow_arm, rainbow_x86
import unicorn as uc

tests = [
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
          # [
          #   (0x1000, 0x2000), 
          #   (0x3000, 0x4000), 

          #   # Test: contiguous map below and above
          #   # Crashes
          #   (0x2000, 0x3000), 
          # ],
          # [
          #   (0x1000, 0x2000), 

          #   # Test: inclusion of previous map
          #   (0x800, 0x2800), 
          # ],
          # [
          #   (0x1000, 0x2000), 
          #   (0x3000, 0x4000), 

          #   # Test: multiple inclusions of previous maps
          #   (0x800, 0x5000), 
          # ],
          # [
          #   (0x1000, 0x2000), 
          #   (0x3000, 0x4000), 

          #   # Test: inclusion and overlap
          #   (0x800, 0x3800), 
          # ],
        ] 

def test_all_arm():
  for test in tests:
    emu = rainbow_arm()

    for t in test:
      emu.map_space(*t)

def test_all_x86():
  for test in tests:
    emu = rainbow_x86()

    for t in test:
      emu.map_space(*t)
    