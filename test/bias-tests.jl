using AESInternals
using Test


function AESInternals.set_leakage!(leakages, round, symbol, state)
    println("round $(lpad(round, 2)) $(lpad(symbol, 6)):   $(string(state |> hton, base = 16, pad = 32))")
end

function test_aes256()
    for round in 1:12
        for operation1 in (:start,:s_box, :m_col)
            for operation2 in (:start, :s_box, :m_col)

                leakages = Dict()
                @show leakdefs = ((round, operation1), ((round + 1), operation2))

                # state1 = rand(UInt128)
                # state2 = rand(UInt128)
                state1 = zero(UInt128) | 0xdead
                state2 = zero(UInt128) | 0xc335

                input, key = AESInternals.aes256_hammer(
                    state1 = state1, 
                    state2 = state2, 
                    round1 = round,
                    round2 = round + 1,
                    operation1 = operation1,
                    operation2 = operation2)

                    aes_encrypt(input, expandkey(key), leakages, Val(leakdefs))
                    # AESInternals.dump_aes_encrypt(input, key)

                @test leakages[leakdefs[1]] == state1
                @test leakages[leakdefs[2]] == state2
            end
        end
    end
end
