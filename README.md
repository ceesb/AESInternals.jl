# AESInternals

Exposes internals of the AES cipher.

## Examples

AES 256/192/128 encrypt:
```julia
aes_encrypt(rand(UInt8, 16), rand(UInt8, 32))
aes_encrypt(rand(UInt8, 16), rand(UInt8, 24))
aes_encrypt(rand(UInt8, 16), rand(UInt8, 16))
```

The cipher state is kept as a UInt128. 

S-box:
```julia
sbox(rand(UInt128))
```

Shift-rows:
```julia
shiftrows(rand(UInt128))
```

Mix-columns:
```julia
mixcolumns(rand(UInt128))
```

Inverse operations are prepended with `i`.

Inverse S-box:
```julia
isbox(rand(UInt128))
```

Inverse shift-rows:
```julia
ishiftrows(rand(UInt128))
```

Inverse mix-columns:
```julia
imixcolumns(rand(UInt128))
```

One day when I need it, I'll add decrypt.

## Biases

To generate key and inputs pairs for AES 256 encrypt that cause an internal bias, use `aes256_hammer`. For example, the following generates key and input pairs for which rounds 8 and 9 start are full-zero.

```julia
input, key = aes256_hammer(;
    state1 = zero(UInt128),
    state2 = zero(UInt128),
    round1 = 8, 
    round2 = 9, 
    operation1 = :start,
    operation2 = :start)
```

You can see this bias in action:

```
julia> AESInternals.dump_aes_encrypt(input,key)
round  0  input:   8a4a499becff674750e7a6115ff7db11
round  1  start:   e7bf136c69ebf08da640c2505fdfe246
round  1  s_box:   94087d50f9e98c5d24092553cf9e985a
round  1  s_row:   94e9255af9099850249e7d5dcf088c53
round  1  m_col:   6c68d9df3a082b21d1d9a73542033168
round  2  start:   a62b2d5fada47e5991744d8649c874fe
round  2  s_box:   24f1d8cf9549f3cb8192e3443be892bb
round  2  s_row:   2449e3bb959292cf81e8d8cb3bf1f344
round  2  m_col:   cb3366abc1c8722129f28425c988fbc7
round  3  start:   b8a8ac7737472f3729dabd72c988fbc7
round  3  s_box:   6cc291f59aa0159aa5577a40ddc40fc6
round  3  s_row:   6ca07ac69a570ff5a5c4919addc21540
round  3  m_col:   9f7f69f92cd0d71c0d04ed8ea93df52b
round  4  start:   365ffe1a125c15877325c5a6dcd79895
round  4  s_box:   05cfbba2c94a59178f3fa624860e462a
round  4  s_row:   054aa62ac93f46a28f0ebb1786cf5924
round  4  m_col:   584a66b72cdf8766bb52d51120cc974f
round  5  start:   aeed02f62cf7be31bb52d51120cc974f
round  5  s_box:   e45577427168aec7ea000382b74b8884
round  5  s_row:   e468038471008842ea4b77c7b755ae82
round  5  m_col:   ecb51d4f28b0bc9fa2221d8ca6763826
round  6  start:   26f6e9cfdc7f8a8428cc03bf59724bab
round  6  s_box:   f7421e8a86d27e5f344b7b08cb40b362
round  6  s_row:   f7d27b62864bb38a34401e5fcb427e08
round  6  m_col:   81a7756ff3543566e9c9a9bc3dc56d6a
round  7  start:   818f4c38f3543566e9c9a9bc3dc56d6a
round  7  s_box:   0c7329070d2096331eddd36527a63c02
round  7  s_row:   0c20d3020ddd3c071ea6293327739665
round  7  m_col:   a92097e35defa1f8d701bfcb2805cc46
round  8  start:   00000000000000000000000000000000
round  8  s_box:   63636363636363636363636363636363
round  8  s_row:   63636363636363636363636363636363
round  8  m_col:   63636363636363636363636363636363
round  9  start:   00000000000000000000000000000000
round  9  s_box:   63636363636363636363636363636363
round  9  s_row:   63636363636363636363636363636363
round  9  m_col:   63636363636363636363636363636363
round 10  start:   31b80f7b6c57ae83bb5611489353dd0e
round 10  s_box:   c76c7621505be4eceab18252dcedc1ab
round 10  s_row:   c75b82ab50b1c121eaed76ecdc6ce452
round 10  m_col:   514765c688501bc2795dc47da1619553
round 11  start:   268a3a299cfe274e0e909b92b5cfa9df
round 11  s_box:   f77e80a5debbcc2fab60144fd58ad39e
round 11  s_row:   f7bb149ede60d3a5ab8a802fd57ecc4f
round 11  m_col:   a938dd8a71d5f79b67104bb2b029f948
round 12  start:   01075af6d6debd07182e73053f277f92
round 12  s_box:   7cc5be42f61d7ac5ad318f6b75ccd24f
round 12  s_row:   7c1d8f4ff631d242adccbec575c57a6b
round 12  m_col:   1f83b58834bbbe667532520faf01f9f6
round 13  start:   e30abd14dc9c8a76ead839f02445ae85
round 13  s_box:   11677afa86de7e388761128c366ee497
round 13  s_row:   11de12978661e4fa876e7a3836677e8c
round 13  m_col:   de1749caaa8921fbe5ed55f637f62240
round 14  start:   4b33953998a6b794a8fcfb2ef5e90a42
round 14  s_box:   b3c32a124624a922c2b00f31e61e672c
round 14  s_row:   b3240f2c46b06712c21e2a22e6c3a931
round 14 output:   cf997095d22a2cbbc96e0a7466f7de14

```