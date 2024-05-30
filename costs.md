# BLOCK PRE-EXECUTION

CmpCount: 1280 <!-- range check for hints -->
AssertCmpCount: 1024 <!-- range check for hints -->

FloorDivCount: 256 <!-- integer division -->
IsNegativeCount: 256

AbsCount: 0
ToBinaryCount: 0
FromBinaryCount: 0
NativeMimcCount: 0
GkrMimcCount: 0
ShaBytesCount: 0
PoseidonCount: 0

# TRANSACTION LOOP (BLOCK SIZE = 1)

GkrMimcCount: 5582
PoseidonCount: 66

FromBinaryCount: 236
ToBinaryCount: 65

CmpCount: 49
AssertCmpCount: 19
FloorDivCount: 13
IsNegativeCount: 6
NativeMimcCount: 4
AbsCount: 4 <!-- unaccounted -->
ShaBytesCount: 0

# CHECK STATE ROOT + EVALUATE COMMITMENT

FromBinaryCount: 484
ShaBytesCount: 484
ToBinaryCount: 84

CmpCount: 3 <!-- range check for hints -->
AssertCmpCount: 1 <!-- range check for hints -->

FloorDivCount: 1 <!-- integer division -->

AbsCount: 0
IsNegativeCount: 0
NativeMimcCount: 0
GkrMimcCount: 1
PoseidonCount: 0
