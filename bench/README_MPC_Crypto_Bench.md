# MPC Crypto Bench

**MPC Crypto Bench** is a utility that can be used to accurately measure the speed of the **blockchain-crypto-mpc** library. It runs **blockchain-crypto-mpc** with a specified algorithm for a number of iterations and then returns that average runtime. 

## Build Instructions

The utility can be compiled by running `make`. The resulting executable is called **mpc_crypto_bench**.

## Command Line

Run the utility with the following command:

`./mpc_crypto_bench [algorithm] <iterations>`

where *algorithm* can be one of the following:

- ecdsa-gen
- ecdsa-sign
- eddsa-gen
- eddsa-sign
- bip-initial
- bip-hardened
- bip-normal

The value of *iterations* designates how many times to loop.

## Example

To run 10 iterations of ECDSA key generation:

```
./mpc_crypto_bench ecdsa-gen 10
Initialization...
Runing ecdsa-gen for 10 times
..........
0.786100 seconds per operation
```
