package hhe

import (
	he "sherdal/hhe/he/pasta"
	sym "sherdal/hhe/sym/pasta"
)

type HHEParams struct {
	SymParams sym.Parameter
	HomParams he.Parameter
}

var (
	HHEPasta3P1614 = HHEParams{
		SymParams: sym.Pasta3Param1614,
		HomParams: he.Pasta3Param1614,
	}

	HHEPasta3P3215 = HHEParams{
		SymParams: sym.Pasta3Param3215,
		HomParams: he.Pasta3Param3215,
	}

	HHEPasta3P6015 = HHEParams{
		SymParams: sym.Pasta3Param6015,
		HomParams: he.Pasta3Param6015,
	}

	HHEPasta4P1614 = HHEParams{
		SymParams: sym.Pasta4Param1614,
		HomParams: he.Pasta4Param1614,
	}

	HHEPasta4P3215 = HHEParams{
		SymParams: sym.Pasta4Param3215,
		HomParams: he.Pasta4Param3215,
	}

	HHEPasta4P6015 = HHEParams{
		SymParams: sym.Pasta4Param6015,
		HomParams: he.Pasta4Param6015,
	}
)
