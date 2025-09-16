const fullround = [:s_box, :s_row, :m_col, :addroundkey]
const lastround = [:s_box, :s_row, :addroundkey]

export aes256_hammer
function aes256_hammer(;
    state1 = zero(UInt128),
    state2 = zero(UInt128),
    round1 = 4, 
    round2 = 5, 
    operation1 = :start,
    operation2 = :start,
    )

    key = zeros(UInt8, 32)
    input = zeros(UInt8, 16)
    aes256_hammer!(
        input,
        key;
        state1 = state1,
        state2 = state2,
        round1 = round1,
        round2 = round2,
        operation1 = operation1,
        operation2 = operation2,
    )

    return input, key
end

export aes256_hammer!
function aes256_hammer!(
    input::Vector{UInt8},
    key::Vector{UInt8};
    state1 = zero(UInt128),
    state2 = zero(UInt128),
    round1 = 4, 
    round2 = 5, 
    operation1 = :start,
    operation2 = :start)

    round2 == round1 + 1 || error("fixme")

    input128 = reinterpret(UInt128, input)
    key128 = reinterpret(UInt128, key)

    if operation1 == :start
        rx_start = state1
    elseif operation1 == :s_box
        rx_start = isbox(state1)
    elseif operation1 == :m_col
        rx_start = isbox(ishiftrows(imixcolumns(state1)))
    else
        error("unknown operation $operation, can be either :start, :s_box, or :m_col")
    end

    rx_s_box = sbox(rx_start)
    rx_s_row = shiftrows(rx_s_box)
    rx_m_col = mixcolumns(rx_s_row)

    if operation2 == :start
        key128[1] = rx_m_col ⊻ state2
    elseif operation2 == :s_box
        key128[1] = rx_m_col ⊻ isbox(state2)
    elseif operation2 == :m_col
        key128[1] = rx_m_col ⊻ isbox(ishiftrows(imixcolumns(state2)))
    end

    key128[2] = rand(UInt128)

    expandedkey = expandkey(
        key,
        round1 * 4)

    state = rx_start
    for r in round1 - 1 : - 1 : 1
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