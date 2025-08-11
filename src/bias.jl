const fullround = [:s_box, :s_row, :m_col, :addroundkey]
const lastround = [:s_box, :s_row, :addroundkey]

function aes256_hammer(
    state1::UInt128, 
    state2::UInt128, 
    round::Int, 
    operation::Symbol)

    key = zeros(UInt8, 32)
    input = zeros(UInt8, 16)
    aes256_hammer!(
        input,
        key,
        state1,
        state2,
        round,
        operation
    )

    return input, key
end

function aes256_hammer!(
    input::Vector{UInt8},
    key::Vector{UInt8},
    state1::UInt128, 
    state2::UInt128, 
    round::Int, 
    operation::Symbol)

    operation == :start || error("fixme")

    input128 = reinterpret(UInt128, input)
    key128 = reinterpret(UInt128, key)

    rx_start = state1
    rx_s_box = sbox(rx_start)
    rx_s_row = shiftrows(rx_s_box)
    rx_m_col = mixcolumns(rx_s_row)
    key128[1] = rx_m_col ⊻ state2
    key128[2] = rand(UInt128)

    expandedkey = expandkey(
        key,
        round * 4)

    state = state1
    for r in round - 1 : - 1 : 1
        state ⊻= expandedkey[r + 1]
        state = imixcolumns(state)
        state = ishiftrows(state)
        state = isbox(state)
    end

    state ⊻= expandedkey[1]

    input128[1] = state
    key128[1] = expandedkey[1]
    key128[2] = expandedkey[2]

    return nothing
end