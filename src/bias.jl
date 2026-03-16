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
    input::AbstractArray{UInt8},
    key::AbstractArray{UInt8};
    state1 = zero(UInt128),
    state2 = zero(UInt128),
    round1 = 4, 
    round2 = 5, 
    operation1 = :start,
    operation2 = :start)

    round2 == round1 + 1 || error("fixme")
    length(input) == 16 || error("input is not 16 bytes")
    length(key) == 32 || error("key is not 32 bytes")

    input128 = reinterpret(UInt128, input)
    key128 = reinterpret(UInt128, key)

    if operation1 == :start
        rx_start = state1
    elseif operation1 == :s_box
        rx_start = isbox(state1)
    elseif operation1 == :s_row
        rx_start = isbox(ishiftrows(state1))
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

export aes_smallhammer
function aes_smallhammer(key::AbstractArray{UInt8};
    state = zero(UInt128),
    round = 4, 
    operation = :start,
    )

    input = zeros(UInt8, 16)
    aes_smallhammer!(
        input,
        key;
        state = state,
        round = round,
        operation = operation,
    )

    return input
end


export aes_smallhammer!
function aes_smallhammer!(
    input::AbstractArray{UInt8},
    key::AbstractArray{UInt8};
    state = zero(UInt128),
    round = 4, 
    operation = :start)

    length(input) == 16 ||
        error("input is not 16 bytes")
    length(key) == 32 || length(key) == 24 || length(key) == 16 || 
        error("length key is $(length(key)) but needs to be 32/24/16")

    input128 = reinterpret(UInt128, input)
    kl = length(key)
    if kl == 16
        lr = 10
    elseif kl == 24
        lr = 12
    else
        lr = 14
    end

    if operation == :start && 1 <= round <= lr
        rx_start = state
    elseif operation == :s_box  && 1 <= round <= lr
        rx_start = isbox(state)
    elseif operation == :s_row && 1 <= round <= lr
        rx_start = isbox(ishiftrows(state))
    elseif operation == :m_col && 1 <= round <= (lr-1)
        rx_start = isbox(ishiftrows(imixcolumns(state)))
    else
        error("unknown operation $operation, can be either :start, :s_box, or :m_col")
    end

    expandedkey = expandkey(key)

    state = rx_start

    for r in round - 1 : - 1 : 1
        state ⊻= expandedkey[r + 1]
        state = imixcolumns(state)
        state = ishiftrows(state)
        state = isbox(state)
    end

    state ⊻= expandedkey[1]

    input128[1] = state

    return nothing
end
