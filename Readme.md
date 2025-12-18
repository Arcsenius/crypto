sudo apt update
sudo apt install build-essential cmake libtbb-dev
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j
./bin/lab1 ECB DES PKCS7 mykey file.in file.out enc
chmod +x scripts/*.sh

sudo apt update
sudo apt install libboost-all-dev