
cmakebuild:
	cmake -H. -Bbuild -DEXPORT_COMPILE_COMMANDS=1
	cmake --build build

runtest:
	./build/test_io
	./build/test_padding
	./build/test_crypto


test: cmakebuild runtest
