# hybrid_signcryption

## install

    sudo apt install make build-essential libncurses-dev bison flex libelf-dev
    sudo apt install tshark libcbor openssl libssl-dev
    sudo apt install r-base r-cran-dplyr

    make

##  formal verification

install proverif: https://bblanche.gitlabpages.inria.fr/proverif/

see also: https://github.com/ernestyyy0306/ProVerif-MQV-Based

    cd proverif
    proverif -graph trace hybrid_sc.pv

##  test

    ./hybrid_sc plain.txt single.csv

    ./hybrid_sc_print plain.txt single.csv

    ./hybrid_sc_multi plain.txt multi.csv 3

##  experiment
    
    ./main_single.pl
    ./main_multi.pl result/multi.csv

   cd result 
   ./main_stat.pl

