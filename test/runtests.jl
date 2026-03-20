include("aes-tests.jl")

@testset "aes tests" begin
    testshiftrows()
    testmixcolumns()
    testsbox()
    testkeyexpansion128()
    testkeyexpansion128backward()
    testkeyexpansion192()
    testkeyexpansion192backward()
    testkeyexpansion256()
    testkeyexpansion256backward()

    testaes256()
    testaes256decrypt()
    testaes256decryptwithkey()
    testaes256roundtrip()
    testaes256leakages()
    testaes256decryptleakages()
end

include("bias-tests.jl")

@testset "aes bias tests" begin
    test_aes_smallhammer()
    test_aes256_hammer()
end
