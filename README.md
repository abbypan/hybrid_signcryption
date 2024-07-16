# hybrid_signcryption

## install

    sudo apt-get install make build-essential libncurses-dev bison flex libelf-dev
    sudo apt install tshark libcbor openssl libssl-dev

    make

##  test

    ./hybrid_sc plain.txt single.csv

    ./hybrid_sc_print plain.txt single.csv

    ./hybrid_sc_multi plain.txt multi.csv 3
