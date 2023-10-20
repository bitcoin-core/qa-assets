contract C {
	bytes8[] x;
	bytesWIDTH[] y;
	event E(bytesWIDTH[], bytes8[]);
	function store() public {
		x.push("abc");
		x.push("def");
		for (uint i = 0; i < SIZE; i ++)
			y.push(bytesWIDTH(uintUINTWIDTH(i + 1)));
	}
	function f() public returns (bytesWIDTH[] memory, bytes8[] memory) {
		emit E(y, x);
		return (y, x); // this copies to memory first
	}
}
