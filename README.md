## pseudo_encrypt-rs

This is a native Rust generic implementation of the `pseudo_encrypt` function [from Psql](https://wiki.postgresql.org/wiki/Pseudo_encrypt)

> pseudo_encrypt(int) can be used as a pseudo-random generator of unique values. It produces an integer output that is 
> uniquely associated to its integer input (by a mathematical permutation), but looks random at the same time, with
> zero collision. This is useful to communicate numbers generated sequentially without revealing their ordinal position 
> in the sequence (for ticket numbers, URLs shorteners, promo codes...

There is out of the box support for integer primitives that are 32bit and up:

- i32
- u32
- i64
- u64
- i128
- u128
