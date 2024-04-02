# hybrid_signcryption

    sudo apt-get install make build-essential libncurses-dev bison flex libelf-dev
    sudo apt install tshark libcbor openssl libssl-dev

    make
    
    ./hybrid_signcryption resources/plain.1KB.txt >> resources/hybrid_signcryption.1KB.csv

    ./sigma resources/plain.1KB.txt >> resources/sigma.1KB.csv

    sudo tshark -w dtls.1KB.cap -i lo 'udp port 23232'
    ./dtls_udp_echo -L 127.0.0.1
    ./dtls_udp_echo -f resources/plain.1KB.txt -n 1 127.0.0.1 >> resources/dtls_udp_echo.1KB.csv

# note

cert.sh is from https://github.com/nplab/DTLS-Examples/

dtls_udp_echo.c is from https://github.com/nplab/DTLS-Examples/
