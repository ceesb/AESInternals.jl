const aes_poly = 0x1b
const aes_affine = 0b11110001_11100011_11000111_10001111_00011111_00111110_01111100_11111000
const aes_constant = 0x63

"""Multiply two bytes in GF(2^8) with the AES primitive polynomial."""
function gf_mult(a::UInt8, b::UInt8; primitive_polynomial = aes_poly)::UInt8
    result = UInt8(0)
    for _ in 1:8
        if (b & 0x01) != 0
            result ⊻= a
        end
        carry = a & 0x80
        a <<= 1
        if carry != 0
            a ⊻= primitive_polynomial
        end
        b >>= 1
    end
    return result
end

"""Build the GF(2^8) antilog table used by the AES field arithmetic."""
function gen_gf8_antilog_table(;primitive_element = 0x3, primitive_polynomial = aes_poly)
    t = zeros(UInt8, 256)
    t[1] = 1
    t[2] = primitive_element

    for i in 3 : length(t) - 1
        t[i] = gf_mult(t[i - 1], primitive_element; primitive_polynomial = primitive_polynomial)
    end

    t[256] = 1

    return t
end

"""Build the GF(2^8) log table from an antilog table."""
function gen_gf8_log_table(alogtab)
    t = zeros(UInt8, 256)

    t[1] = 0
    
    for i in 2 : length(alogtab)
        t[alogtab[i] + 1] = i - 1
    end
    
    return t
end


"""Multiply two field elements using precomputed log and antilog tables."""
function logtable_mul(a::UInt8, b::UInt8, logtab::Vector{UInt8}, alogtab::Vector{UInt8})::UInt8
    if a == 0x00 || b == 0x00
        return 0x00
    end

    @inbounds begin
        log_a = logtab[a + 1]
        log_b = logtab[b + 1]
    end

    sum = Int(log_a) + Int(log_b)

    sum %= 255

    @inbounds begin
        r = alogtab[sum + 1]
    end

    return r
end

const alogtab = gen_gf8_antilog_table()
const logtab = gen_gf8_log_table(alogtab)

"""Multiply two AES field elements with the cached tables."""
@inline gf8_mul(x, y) = logtable_mul(x, y, logtab, alogtab)

"""Return the AES multiplicative inverse of a field element."""
@inline gf8_inv(x) = iszero(x) ? zero(x) : alogtab[((logtab[x + 1] * 254) % 255) + 1]

"""Multiply an 8x8 binary matrix by an 8-bit vector over GF(2)."""
function gf2_matvec8(m::UInt64, v::UInt8)::UInt8
    result = 0x00
    for i in 0:7
        row = UInt8((m >> (8 * i)) & 0xff)
        dot = count_ones(row & v) & 1
        result |= dot << (7 - i) 
    end
    return result
end

"""Compute one AES S-box byte from a raw input byte."""
function sbox(x::UInt8)
    gf2_matvec8(aes_affine, gf8_inv(x)) ⊻ aes_constant
end

const sbox_table = map(sbox, 0x00:0xff)

"""Invert a lookup table."""
function itable(table)
    invtable = similar(table)

    for (i,v) in enumerate(table)
        invtable[v + 1] = i - 1
    end

    return invtable
end

const isbox_table = itable(sbox_table)

"""Apply the AES MixColumns transform to one 32-bit column."""
@inline function mixcolumn(col::UInt32)::UInt32
    a3 = UInt8((col >> 24) & 0xff)
    a2 = UInt8((col >> 16) & 0xff)
    a1 = UInt8((col >> 8) & 0xff)
    a0 = UInt8((col) & 0xff)

    b0 = gf8_mul(0x2, a0) ⊻ gf8_mul(0x3, a1) ⊻ a2 ⊻ a3
    b1 = a0 ⊻ gf8_mul(0x2, a1) ⊻ gf8_mul(0x3, a2) ⊻ a3
    b2 = a0 ⊻ a1 ⊻ gf8_mul(0x2, a2) ⊻ gf8_mul(0x3, a3)
    b3 = gf8_mul(0x3, a0) ⊻ a1 ⊻ a2 ⊻ gf8_mul(0x2, a3)

    return (UInt32(b3) << 24) | (UInt32(b2) << 16) | (UInt32(b1) << 8) | UInt32(b0)
end

"""Apply the AES inverse MixColumns transform to one 32-bit column."""
@inline function imixcolumn(col::UInt32)::UInt32
    a3 = UInt8((col >> 24) & 0xff)
    a2 = UInt8((col >> 16) & 0xff)
    a1 = UInt8((col >> 8) & 0xff)
    a0 = UInt8(col & 0xff)

    b0 = gf8_mul(0x0e, a0) ⊻ gf8_mul(0x0b, a1) ⊻ gf8_mul(0x0d, a2) ⊻ gf8_mul(0x09, a3)
    b1 = gf8_mul(0x09, a0) ⊻ gf8_mul(0x0e, a1) ⊻ gf8_mul(0x0b, a2) ⊻ gf8_mul(0x0d, a3)
    b2 = gf8_mul(0x0d, a0) ⊻ gf8_mul(0x09, a1) ⊻ gf8_mul(0x0e, a2) ⊻ gf8_mul(0x0b, a3)
    b3 = gf8_mul(0x0b, a0) ⊻ gf8_mul(0x0d, a1) ⊻ gf8_mul(0x09, a2) ⊻ gf8_mul(0x0e, a3)

    return (UInt32(b3) << 24) | (UInt32(b2) << 16) | (UInt32(b1) << 8) | UInt32(b0)
end

export makeT
"""
    makeT(idx)

Build the four 256-byte lookup tables for a single AES input byte position.
Each returned vector encodes one byte position of the MixColumns output for
that input position.
"""
function makeT(idx)
    ret1 = zeros(UInt8, 256)
    ret2 = zeros(UInt8, 256)
    ret3 = zeros(UInt8, 256)
    ret4 = zeros(UInt8, 256)

    for b in collect(UInt8, 0:255)
        out = mixcolumn(UInt32(b) << ((idx - 1) * 8))
        ret1[b + 1] = out & 0xff
        ret2[b + 1] = (out >> 8) & 0xff
        ret3[b + 1] = (out >> 16) & 0xff
        ret4[b + 1] = (out >> 24) & 0xff
    end

    return ret1, ret2, ret3, ret4
end

export makeT
"""
    makeT()

Build the full 4x4 table matrix used by AES lookup-table predictors.
Each entry `T[r, c]` is a 256-byte lookup table that represents the
contribution of row `r` of an AES input column to row `c` of the AES output
column.
"""
function makeT()
    gT11, gT21, gT31, gT41 = makeT(1)
    gT12, gT22, gT32, gT42 = makeT(2)
    gT13, gT23, gT33, gT43 = makeT(3)
    gT14, gT24, gT34, gT44 = makeT(4)

    # column i are the mc inputs for output i
    T = [[gT11] [gT21] [gT31] [gT41];
         [gT12] [gT22] [gT32] [gT42];
         [gT13] [gT23] [gT33] [gT43];
         [gT14] [gT24] [gT34] [gT44]]
end

export shiftrows
"""Apply the AES ShiftRows transform to a 128-bit state."""
function shiftrows(u::UInt128)::UInt128
    result = zero(UInt128)

    for i in 0 : 3
        result |= ((u >> (8 * (( 0 + i * 5) & 0xf))) & 0xff) << (8 * ( 0 + i))
        result |= ((u >> (8 * (( 4 + i * 5) & 0xf))) & 0xff) << (8 * ( 4 + i))
        result |= ((u >> (8 * (( 8 + i * 5) & 0xf))) & 0xff) << (8 * ( 8 + i))
        result |= ((u >> (8 * ((12 + i * 5) & 0xf))) & 0xff) << (8 * (12 + i))
    end

    return result
end

export ishiftrows
"""Apply the AES inverse ShiftRows transform to a 128-bit state."""
function ishiftrows(u::UInt128)::UInt128
    result = zero(UInt128)

    for i in 0:3
        result |= ((u >> (8 * (( 0 + i * 13) & 0xf))) & 0xff) << (8 * ( 0 + i))
        result |= ((u >> (8 * (( 4 + i * 13) & 0xf))) & 0xff) << (8 * ( 4 + i))
        result |= ((u >> (8 * (( 8 + i * 13) & 0xf))) & 0xff) << (8 * ( 8 + i))
        result |= ((u >> (8 * ((12 + i * 13) & 0xf))) & 0xff) << (8 * (12 + i))
    end

    return result
end

export mixcolumns
"""Apply MixColumns to each AES state column."""
function mixcolumns(state::UInt128)::UInt128
    result = zero(UInt128)
    for i in 0:3
        # Extract 4 bytes making up column i (in column-major order)
        shift = 8 * (12 - 4i)
        col = UInt32((state >> shift) & 0xffffffff)
        mixed = mixcolumn(col)
        result |= UInt128(mixed) << shift
    end
    return result
end

export imixcolumns
"""Apply inverse MixColumns to each AES state column."""
function imixcolumns(state::UInt128)::UInt128
    result = zero(UInt128)
    for i in 0:3
        # Extract 4 bytes making up column i (in column-major order)
        shift = 8 * (12 - 4i)
        col = UInt32((state >> shift) & 0xffffffff)
        mixed = imixcolumn(col)
        result |= UInt128(mixed) << shift
    end
    return result
end

"""Apply the AES S-box to each byte of a 32-bit word."""
function sbox(state::UInt32)::UInt32
    result = zero(UInt32)
    for i in 0 : 3
        shift = 8i
        byte = (state >> shift) & 0xff
        sboxout = sbox_table[byte + 1]
        result |= UInt32(sboxout) << shift
    end
    return result
end

export sbox
"""Apply the AES S-box to each byte of a 128-bit state."""
function sbox(state::UInt128)::UInt128
    result = zero(UInt128)
    for i in 0 : 15
        shift = 8i
        byte = (state >> shift) & 0xff
        sboxout = sbox_table[byte + 1]
        result |= UInt128(sboxout) << shift
    end
    return result
end

export isbox
"""Apply the AES inverse S-box to each byte of a 128-bit state."""
function isbox(state::UInt128)::UInt128
    result = zero(UInt128)
    for i in 0 : 15
        shift = 8i
        byte = (state >> shift) & 0xff
        sboxout = isbox_table[byte + 1]
        result |= UInt128(sboxout) << shift
    end
    return result
end

"""Rotate a 32-bit AES word by one byte."""
@inline rotword(x) = (x >> 8) | (x << 24)

"""Return the AES round constant for key expansion step `i`."""
@inline rcon(i) = alogtab[(logtab[0x02 + 1] * (i - 1)) % 255 + 1]

const rcon_table = map(rcon, 1 : 16)
const Nb = 4

export expandkey!
"""Expand an AES key into a preallocated buffer of round keys."""
function expandkey!(expandedkey::AbstractVector, key::AbstractVector{UInt8}, offset = 0)
    if length(key) == 16
        Nr = 10
        Nk = 4
    elseif length(key) == 24
        Nr = 12
        Nk = 6
    elseif length(key) == 32
        Nr = 14
        Nk = 8
    else
        error("unsupported key length $(length(key))")
    end

    if offset == -1
        offset = Nb*(Nr+1)-Nk
    end

    0 <= offset <= Nb*(Nr+1)-Nk || 
        error("offset does not satisfy 0 <= $(offset) <= $(Nb*(Nr+1)-Nk) (Nb*(Nr+1)-Nk)")

    length(expandedkey) == Nr + 1 || 
        error("need $(Nr + 1) UInt128 array, got $(length(expandedkey))")

    w = reinterpret(UInt32, expandedkey)

    key_ = reinterpret(UInt32, key)
    for i in eachindex(key_)
        w[offset + i] = key_[i]
    end

    i = offset+Nk-1
    while (i >= Nk)
        temp = w[i-1+1]
        if i % Nk == 0
            temp = sbox(rotword(temp)) ⊻ rcon_table[div(i,Nk)]
        elseif Nk > 6 && i % Nk == 4
            temp = sbox(temp)
        end

        w[i-Nk+1] = w[i+1] ⊻ temp
        i = i - 1
    end

    i = offset + Nk
    while (i < Nb * (Nr+1))
        temp = w[i-1+1]
        if i % Nk == 0
            temp = sbox(rotword(temp)) ⊻ rcon_table[div(i,Nk)]
        elseif Nk > 6 && i % Nk == 4
            temp = sbox(temp)
        end

        w[i+1] = w[i-Nk+1] ⊻ temp
        i = i + 1
    end

    return expandedkey
end

export expandkey
"""Expand an AES key into a fresh vector of round keys."""
function expandkey(key::AbstractVector{UInt8}, offset = 0)
    n = length(key)
    Nr = div(n, 4) + 6
    expandedkey = zeros(UInt128, Nr + 1)
    expandkey!(expandedkey, key, offset)
end

export set_leakage!
"""Print a leakage state in a compact debug format."""
function set_leakage!(leakages, round, symbol, state)
    println("round $(lpad(round, 2)) $(lpad(symbol, 6)):   $(string(state |> hton, base = 16, pad = 32))")
end

"""Record a leakage state in a dictionary keyed by round and stage."""
function AESInternals.set_leakage!(leakages::Dict, round::Int, stage::Symbol, state::UInt128)
    leakages[(round, stage)] = state
end

"""Return the default leakage points for AES encryption at a given key length."""
function all_encrypt_leakages(keylength)
    if keylength == 16
        Nr = 10
        Nk = 4
    elseif keylength == 24
        Nr = 12
        Nk = 6
    elseif keylength == 32
        Nr = 14
        Nk = 8
    else
        error("unsupported key length $(keylength)")
    end

    l = Set{Tuple{Int, Symbol}}()

    for r in 0 : Nr
        if r == 0
            push!(l, (r, :input))
        elseif r == Nr
            push!(l, (r, :start))
            push!(l, (r, :s_box))
            push!(l, (r, :s_row))
            push!(l, (r, :output))
        else
            push!(l, (r, :start))
            push!(l, (r, :s_box))
            push!(l, (r, :s_row))
            push!(l, (r, :m_col))
        end
    end

    return l
end

"""Return the default leakage points for AES decryption at a given key length."""
function all_decrypt_leakages(keylength)
    if keylength == 16
        Nr = 10
        Nk = 4
    elseif keylength == 24
        Nr = 12
        Nk = 6
    elseif keylength == 32
        Nr = 14
        Nk = 8
    else
        error("unsupported key length $(keylength)")
    end

    l = Set{Tuple{Int, Symbol}}()

    for r in 0:Nr
        if r == 0
            push!(l, (r, :input))
        elseif r == Nr
            push!(l, (r, :start))
            push!(l, (r, :s_row))
            push!(l, (r, :s_box))
            push!(l, (r, :output))
        else
            push!(l, (r, :start))
            push!(l, (r, :s_row))
            push!(l, (r, :s_box))
            push!(l, (r, :m_col))
        end
    end

    return l
end

"""Generate an AES encryption implementation for a fixed key length and leakage set."""
@generated function aes_encrypt(
        ::Val{keylength}, 
        input::UInt128, 
        expandedkey::Vector{UInt128}, 
        leakages, ::Val{LEAKS}) where {keylength, LEAKS}
    if keylength == 16
        Nr = 10
        Nk = 4
    elseif keylength == 24
        Nr = 12
        Nk = 6
    elseif keylength == 32
        Nr = 14
        Nk = 8
    else
        error("unsupported key length $(keylength)")
    end

    stages = Expr[:(state = input ⊻ expandedkey[1])]

    if (0, :input) in LEAKS
        push!(stages, :(set_leakage!(leakages, $0, :input, input)))
    end

    for round = 1:Nr
        if (round, :start) in LEAKS
            push!(stages, :(set_leakage!(leakages, $round, :start, state)))
        end

        # SBOX
        push!(stages, :(state = sbox(state)))
        if (round, :s_box) in LEAKS
            push!(stages, :(set_leakage!(leakages, $round, :s_box, state)))
        end

        # SHIFTROWS
        push!(stages, :(state = shiftrows(state)))
        if (round, :s_row) in LEAKS
            push!(stages, :(set_leakage!(leakages, $round, :s_row, state)))
        end

        # MIXCOLUMNS (skip for round 14)
        if round < Nr
            push!(stages, :(state = mixcolumns(state)))
            if (round, :m_col) in LEAKS
                push!(stages, :(set_leakage!(leakages, $round, :m_col, state)))
            end
        end

        # ADDROUNDKEY
        push!(stages, :(state ⊻= expandedkey[$(round + 1)]))
    end

    if (Nr, :output) in LEAKS
        push!(stages, :(set_leakage!(leakages, $Nr, :output, state)))
    end

    push!(stages, :(return state))
    return Expr(:block, stages...)
end

"""Generate an AES decryption implementation for a fixed key length and leakage set."""
@generated function aes_decrypt(
        ::Val{keylength},
        input::UInt128,
        expandedkey::Vector{UInt128},
        leakages, ::Val{LEAKS}) where {keylength, LEAKS}
    if keylength == 16
        Nr = 10
        Nk = 4
    elseif keylength == 24
        Nr = 12
        Nk = 6
    elseif keylength == 32
        Nr = 14
        Nk = 8
    else
        error("unsupported key length $(keylength)")
    end

    stages = Expr[:(state = input ⊻ expandedkey[$(Nr + 1)])]

    if (0, :input) in LEAKS
        push!(stages, :(set_leakage!(leakages, $0, :input, input)))
    end

    for round = 1:Nr
        if (round, :start) in LEAKS
            push!(stages, :(set_leakage!(leakages, $round, :start, state)))
        end

        push!(stages, :(state = ishiftrows(state)))
        if (round, :s_row) in LEAKS
            push!(stages, :(set_leakage!(leakages, $round, :s_row, state)))
        end

        push!(stages, :(state = isbox(state)))
        if (round, :s_box) in LEAKS
            push!(stages, :(set_leakage!(leakages, $round, :s_box, state)))
        end

        if round < Nr
            push!(stages, :(state ⊻= expandedkey[$(Nr + 1 - round)]))
            push!(stages, :(state = imixcolumns(state)))
            if (round, :m_col) in LEAKS
                push!(stages, :(set_leakage!(leakages, $round, :m_col, state)))
            end
        else
            push!(stages, :(state ⊻= expandedkey[1]))
        end
    end

    if (Nr, :output) in LEAKS
        push!(stages, :(set_leakage!(leakages, $Nr, :output, state)))
    end

    push!(stages, :(return state))
    return Expr(:block, stages...)
end

"""Encrypt a byte-vector input using a key-length tag and expanded key."""
@inline function aes_encrypt(keylength, input::AbstractVector{UInt8}, expandedkey::Vector{UInt128}, leakages, leakdefs)
    o = aes_encrypt(keylength, reinterpret(UInt128, input)[1], expandedkey, leakages, leakdefs)
    return reinterpret(UInt8, [o])
end

"""Decrypt a byte-vector input using a key-length tag and expanded key."""
@inline function aes_decrypt(keylength, input::AbstractVector{UInt8}, expandedkey::Vector{UInt128}, leakages, leakdefs)
    o = aes_decrypt(keylength, reinterpret(UInt128, input)[1], expandedkey, leakages, leakdefs)
    return reinterpret(UInt8, [o])
end

export aes_encrypt
"""Encrypt an AES state using an expanded key and optional leakage targets."""
@inline function aes_encrypt(input, expandedkey, leakages = nothing, leakdefs = Val(0))
    if length(expandedkey) == 15
        keylength = 32
    elseif length(expandedkey) == 13
        keylength = 24
    elseif length(expandedkey) == 11
        keylength = 16
    else
        error("unsupported key length $(length(expandedkey))")
    end
   aes_encrypt(Val(keylength), input, expandedkey, leakages, leakdefs)
end

export aes_decrypt
"""Decrypt an AES state using an expanded key and optional leakage targets."""
@inline function aes_decrypt(input, expandedkey, leakages = nothing, leakdefs = Val(0))
    if length(expandedkey) == 15
        keylength = 32
    elseif length(expandedkey) == 13
        keylength = 24
    elseif length(expandedkey) == 11
        keylength = 16
    else
        error("unsupported key length $(length(expandedkey))")
    end
   aes_decrypt(Val(keylength), input, expandedkey, leakages, leakdefs)
end

"""Encrypt a byte-vector input using a raw AES key."""
function aes_encrypt(input::AbstractVector{UInt8}, key::AbstractVector{UInt8})
    ex = expandkey(key)
    aes_encrypt(input, ex)
end

"""Decrypt a byte-vector input using a raw AES key."""
function aes_decrypt(input::AbstractVector{UInt8}, key::AbstractVector{UInt8})
    ex = expandkey(key)
    aes_decrypt(input, ex)
end

"""Run AES encryption while capturing the default encryption leakages."""
function dump_aes_encrypt(input::AbstractVector{UInt8}, key::AbstractVector{UInt8})
    ex = expandkey(key)
    aes_encrypt(input, ex, nothing, Val(
        tuple(
            all_encrypt_leakages(length(key))...)))
end

"""Run AES decryption while capturing the default decryption leakages."""
function dump_aes_decrypt(input::AbstractVector{UInt8}, key::AbstractVector{UInt8})
    ex = expandkey(key)
    aes_decrypt(input, ex, nothing, Val(
        tuple(
            all_decrypt_leakages(length(key))...)))
end
