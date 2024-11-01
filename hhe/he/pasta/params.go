package pasta

import "math"

type Parameter struct {
	logN      int
	plainMod  uint64
	modDegree uint64
	UseBsGs   bool
	bSgSN1    int
	bSgSN2    int
}

var (
	Pasta3Param1614 = Parameter{
		UseBsGs:   true,
		bSgSN1:    16,
		bSgSN2:    8,
		logN:      14,
		plainMod:  65537,
		modDegree: uint64(math.Pow(2, 14)),
	}
	Pasta3Param3215 = Parameter{
		UseBsGs:   true,
		bSgSN1:    16,
		bSgSN2:    8,
		logN:      15,
		plainMod:  8088322049,
		modDegree: uint64(math.Pow(2, 15)),
	}

	Pasta3Param6015 = Parameter{
		UseBsGs:   true,
		logN:      15,
		bSgSN1:    16,
		bSgSN2:    8,
		plainMod:  1096486890805657601,
		modDegree: uint64(math.Pow(2, 15)),
	}

	Pasta4Param1614 = Parameter{
		UseBsGs:   true,
		bSgSN1:    8,
		bSgSN2:    4,
		logN:      14,
		plainMod:  65537,
		modDegree: uint64(math.Pow(2, 14)),
	}

	Pasta4Param3215 = Parameter{
		UseBsGs:   true,
		bSgSN1:    8,
		bSgSN2:    4,
		logN:      15,
		plainMod:  8088322049,
		modDegree: uint64(math.Pow(2, 15)),
	}

	Pasta4Param6015 = Parameter{
		UseBsGs:   true,
		bSgSN1:    8,
		bSgSN2:    4,
		logN:      16,
		plainMod:  1096486890805657601,
		modDegree: uint64(math.Pow(2, 16)),
	}
)
