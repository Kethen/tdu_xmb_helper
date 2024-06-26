set -xe

for arch in x86_64 i686
do
	OUT_DIR=dist/windows_${arch}
	rm -rf $OUT_DIR
	mkdir -p $OUT_DIR

	CPPC=${arch}-w64-mingw32-g++
	$CPPC -g -fPIC -c main.cpp -Ijson_hpp -std=c++20 -o $OUT_DIR/main.o
	$CPPC -g -static -o $OUT_DIR/xmb_helper $OUT_DIR/main.o -lntdll -Wl,-Bstatic -static-libgcc -static-libstdc++ -liconv

	rm $OUT_DIR/*.o
done

OUT_DIR=dist/linux_x86_64
rm -rf $OUT_DIR
mkdir -p $OUT_DIR
g++ -g -fPIC -c main.cpp -Ijson_hpp -std=c++20 -o $OUT_DIR/main.o
g++ -g -o $OUT_DIR/xmb_helper $OUT_DIR/main.o
