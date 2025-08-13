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
    testaes256leakages()
end

include("bias-tests.jl")

@testset "aes bias tests" begin
    test_aes256()
end