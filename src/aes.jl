const aes_poly = 0x1b
const aes_affine = 0b11110001_11100011_11000111_10001111_00011111_00111110_01111100_11111000
const aes_constant = 0x63

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

function gen_gf8_log_table(alogtab)
    t = zeros(UInt8, 256)

    t[1] = 0
    
    for i in 2 : length(alogtab)
        t[alogtab[i] + 1] = i - 1
    end
    
    return t
end


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

@inline gf8_mul(x, y) = logtable_mul(x, y, logtab, alogtab)
@inline gf8_inv(x) = iszero(x) ? zero(x) : alogtab[((logtab[x + 1] * 254) % 255) + 1]

function gf2_matvec8(m::UInt64, v::UInt8)::UInt8
    result = 0x00
    for i in 0:7
        row = UInt8((m >> (8 * i)) & 0xff)
        dot = count_ones(row & v) & 1
        result |= dot << (7 - i) 
    end
    return result
end

function sbox(x::UInt8)
    gf2_matvec8(aes_affine, gf8_inv(x)) ⊻ aes_constant
end

const sbox_table = map(sbox, 0x00:0xff)

function itable(table)
    invtable = similar(table)

    for (i,v) in enumerate(table)
        invtable[v + 1] = i - 1
    end

    return invtable
end

const isbox_table = itable(sbox_table)

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

export shiftrows
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

@inline rotword(x) = (x >> 8) | (x << 24)
@inline rcon(i) = alogtab[(logtab[0x02 + 1] * (i - 1)) % 255 + 1]

const rcon_table = map(rcon, 1 : 16)
const Nb = 4

export expandkey!
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
function expandkey(key::AbstractVector{UInt8}, offset = 0)
    n = length(key)
    Nr = div(n, 4) + 6
    expandedkey = zeros(UInt128, Nr + 1)
    expandkey!(expandedkey, key, offset)
end

export set_leakage!
function set_leakage!(leakages, round, symbol, state)
    println("round $(lpad(round, 2)) $(lpad(symbol, 6)):   $(string(state |> hton, base = 16, pad = 32))")
end

function AESInternals.set_leakage!(leakages::Dict, round::Int, stage::Symbol, state::UInt128)
    leakages[(round, stage)] = state
end

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

@inline function aes_encrypt(keylength, input::AbstractVector{UInt8}, expandedkey::Vector{UInt128}, leakages, leakdefs)
    o = aes_encrypt(keylength, reinterpret(UInt128, input)[1], expandedkey, leakages, leakdefs)
    return reinterpret(UInt8, [o])
end

export aes_encrypt
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

function dump_aes_encrypt(input::AbstractVector{UInt8}, key::AbstractVector{UInt8})
    ex = expandkey(key)
    aes_encrypt(input, ex, nothing, Val(
        tuple(
            all_encrypt_leakages(length(key))...)))
end

# export aes128_encrypt
# @inline aes128_encrypt(input, expandedkey, leakages = nothing, leakdefs = Val(0)) =
#     aes_encrypt(Val(16), input, expandedkey, leakages, leakdefs)

# export aes192_encrypt
# @inline aes192_encrypt(input, expandedkey, leakages = nothing, leakdefs = Val(0)) =
#     aes_encrypt(Val(24), input, expandedkey, leakages, leakdefs)

# export aes256_encrypt
# @inline aes256_encrypt(input, expandedkey, leakages = nothing, leakdefs = Val(0)) =
#     aes_encrypt(Val(32), input, expandedkey, leakages, leakdefs)