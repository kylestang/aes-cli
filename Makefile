test:
	cmake -H. -Bbuild -DTEST=ON -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON -DENABLE_UBSAN=ON
	cmake --build build 
	./build/test_io -d yes
	./build/test_crypto -d yes
	./build/test_ciphermode -d yes

debug:
	cmake -H. -Bbuild -DTEST=OFF -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON -DENABLE_UBSAN=ON
	cmake --build build

release:
	cmake -H. -Bbuild -DTEST=OFF -DCMAKE_BUILD_TYPE=Release -DENABLE_ASAN=OFF -DENABLE_UBSAN=OFF
	cmake --build build
