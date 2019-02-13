# MPC Crypto Python Script

**MPC Crypto** is a Python script that can be used to accurately measure the speed of the **blockchain-crypto-mpc** library. It runs **blockchain-crypto-mpc** with a specified algorithm for a number of iterations and then returns that average runtime. The utility strives to measure the raw speed of the **blockchain-crypto-mpc** library, without any delays due to networking.

## Command Line

Before running the command line, set the following environment variable, pointing to wherever you compiled the **blockchain-crypto-mpc** library:

`LD_LIBRARY_PATH=/home/centos/Unbound/blockchain-crypto-mpc`

Run the utility with the following command:

```
python mpc_demo.py \
    --type <algorithm> \
    --command <sign|generate> \
    --in_file <key filename>.bin \
    --data_file <data filename>.dat \
    --repeat <iterations>
```

where *algorithm* can be one of the following:

- ECDSA - for ECDSA  
- EDDSA - for EdDSA  

The value of *iterations* designates how many times to loop.

## Example

To run 10 iterations of ECDSA key signing:

```
python mpc_demo.py --type ECDSA --command sign --in_file key_share2.bin --data_file data.dat --repeat 5
ECDSA signing...
ok
ECDSA signing...
ok
ECDSA signing...
ok
ECDSA signing...
ok
ECDSA signing...
ok
Took 15.4986 ms on average
```
