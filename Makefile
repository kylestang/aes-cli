test: cmakebuild runtest

cmakebuild:
	cmake -H. -Bbuild
	cmake --build build

runtest:
	./build/test_io -d yes
	./build/test_crypto -d yes
	./build/test_ciphermode -d yes
