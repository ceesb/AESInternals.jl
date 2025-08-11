using BenchmarkTools
using AESInternals

function dobench(expandedkey)
    expandkey!(expandedkey, rand(UInt8, 32))
    aes_encrypt(rand(UInt8, 16), expandedkey, nothing, Val(0))
end

b1 = @benchmarkable dobench(expandedkey) setup=(expandedkey = zeros(UInt128, 14 + 1))

