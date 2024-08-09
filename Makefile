
cmakebuild:
	cmake -H. -Bbuild -DEXPORT_COMPILE_COMMANDS=1
	cmake --build build

runtest:
	./build/test_io -d yes
	./build/test_crypto -d yes
	./build/test_ciphermode -d yes


test: cmakebuild runtest
