
using Test
using AESInternals

function testshiftrows()
    ib = "50d80483b3c6c51470f17c4694756104" |> hex2bytes
    kob = "50c67c04b3f161837075041494d8c546" |> hex2bytes

    i = reinterpret(UInt128, ib)[1]
    ko = reinterpret(UInt128, kob)[1]

    @test shiftrows(i) == ko
    @test ishiftrows(ko) == i
end

function testmixcolumns()
    ib = "50d80483b3c6c51470f17c4694756104" |> hex2bytes
    kob = "54741e31fd64d8e5d24bb391c9d92fbb" |> hex2bytes

    i = reinterpret(UInt128, ib)[1]
    ko = reinterpret(UInt128, kob)[1]

    @test mixcolumns(i) == ko
    @test imixcolumns(ko) == i
end


function testsbox()
    ib = "50d80483b3c6c51470f17c4694756104" |> hex2bytes
    kob = "5361f2ec6db4a6fa51a1105a229deff2" |> hex2bytes

    i = reinterpret(UInt128, ib)[1]
    ko = reinterpret(UInt128, kob)[1]

    @test sbox(i) == ko
    @test isbox(ko) == i
end

function testkeyexpansion128()
    ib = "50d80483b3c6c51470f17c4694756104" |> hex2bytes
    kob = "50d80483b3c6c51470f17c4694756104cc37f6a17ff133b50f004ff39b752ef753069eb52cf7ad0023f7e2f3b882cc04444d6cd968bac1d94b4d232af3cfef2ec6925dd4ae289c0de565bf2716aa50097ac15c93d4e9c09e318c7fb927262fb0add4bb5f793d7bc148b104786f972bc8652553f71c18283654a92c4e3b3e078657e017154bf83f231f51136d246f14ebe41afe23afe2c100b0b3d26d94dcc68654aeba01fb4c7b014bffa96cdf236fea" |> hex2bytes

    ko = reinterpret(UInt128, kob)

    @test expandkey(ib) == ko
end

function testkeyexpansion128backward()
    ib = "50d80483b3c6c51470f17c4694756104" |> hex2bytes
    kob = "fce98c964243d0bb428dd832a1d4ab63b58b77a4f7c8a71fb5457f2d1491d44e36c3585ec10bff41744e806c60df5422ace3cb8e6de834cf19a6b4a37979e0811202c7387feaf3f7664c47541f35a7d5945ec4f8ebb4370f8df8705b92cdd78e0950ddb7e2e4eab86f1c9ae3fdd14d6d77b3e1e395570b5bfa4b91b8079adcd54f35e226da62e97d202978c527b3a410397c28eae31ec197c337b952e4841d4250d80483b3c6c51470f17c4694756104" |> hex2bytes

    ko = reinterpret(UInt128, kob)

    @test expandkey(ib, -1) == ko
end

function testkeyexpansion192()
    ib = "50d80483b3c6c51470f17c46947561041122334455667788" |> hex2bytes
    kob = "50d80483b3c6c51470f17c46947561041122334455667788622dc07fd1eb056ba11a792d356f1829244d2b6d712b5ce5916719dc408c1cb7e196659ad4f97db3f0b456de819f0a3b4e00fbd00e8ce767ef1a82fd3be3ff4ecb57a9904ac8a3abae0a9906a0867e614f9cfc9c747f03d2bf28aa42f5e009e95f0b87e0ff8df981b011051dc46e06cf7b46ac8d8ea6a5645b0dc4f9a4803d7814913865d0ff3eaaabb99227251f3743db97dec67f17e3be6b86dbdbbb79e57110c0775635df4015c59e8750ba8964eed10fbf356a765a44" |> hex2bytes

    ko = reinterpret(UInt128, kob)

    @test expandkey(ib) == ko
end

function testkeyexpansion192backward()
    ib = "50d80483b3c6c51470f17c46947561041122334455667788" |> hex2bytes
    kob = "5ad055b5464476a78a234b7945a13cbef762cf8cb1d22d1aee08f77da84c81da226fcaa367cef61d90ac3991217e148b1ff2ca80b7be4b5a95d181f9f21f77e462b34e7543cd5afea64c719a11f23ac08423bb39763cccdd148f82a85742d856822dc0c193dffa0117fc413861c08de5754f0f4d220dd71b45236f52d6fc9553c100d46ba0c0598ed58f56c3f78281d8762f0e3aa0d39b6961d34f02c113168c149c404fe31ec1974457862be4841d4285575240444444cc50d80483b3c6c51470f17c46947561041122334455667788" |> hex2bytes

    ko = reinterpret(UInt128, kob)

    @test expandkey(ib, -1) == ko
end

function testkeyexpansion256()
    ib = "50d80483b3c6c51470f17c4694756104112233445566778899aabbccddeeff00" |> hex2bytes
    kob = "50d80483b3c6c51470f17c4694756104112233445566778899aabbccddeeff0079ce6742ca08a256baf9de102e8cbf1420463bbe75204c36ec8af7fa316408fa38fe4a85f2f6e8d3480f36c3668389d713aa9cb0668ad0868a00277cbb642f867feb0e6f8d1de6bcc512d07fa39159a8192b57727fa187f4f5a1a0884ec58f0ed198a5405c8543fc999793833a06ca2b99442383e6e5a477134404ff5d818bf1cda5040c912047f008b7d47332b11e58ba8c51e95c69f59e4f2df16112ac7a907c7f64c5ed5f2335e5e8f746d759e91eb4474f9be82eba05a7034b64b5af31f445b8db10a8e7f8254d0f0f639a56e67d" |> hex2bytes

    ko = reinterpret(UInt128, kob)

    @test expandkey(ib) == ko
end

function testkeyexpansion256backward()
    ib = "50d80483b3c6c51470f17c4694756104112233445566778899aabbccddeeff00" |> hex2bytes
    kob = "9f8f6bd980532fd72b5d8a94b08603c58b8106e1295ff83a2036cc3544d0c773ee49e4c26e1acb1545474181f5c142446df92afa44a6d2c064901ef52040d986e57ca0758b666b60ce212ae13be068a58f186ffccbbebd3caf2ea3c98f6e7a4f7ea62406f5c04f663be1658700010d22ec64b86f27da055388f4a69a079adcd5ce2027c33be068a500010d22000000008f07db0ca8ddde5f202978c527b3a410b369ed0f888985aa88888888888888884bc31fc8e31ec197c337b952e4841d42cccdc166444444cccccccc44444444cc50d80483b3c6c51470f17c4694756104112233445566778899aabbccddeeff00" |> hex2bytes

    ko = reinterpret(UInt128, kob)

    @test expandkey(ib, -1) == ko
end

function testaes256()
    input = "00112233445566778899aabbccddeeff" |> hex2bytes
    key = "50d80483b3c6c51470f17c4694756104112233445566778899aabbccddeeff00" |> hex2bytes
    expectedoutput = "c48bce6977a67ee4570dd8e279ea2cbe" |> hex2bytes
    
    output = aes_encrypt(input, expandkey(key), nothing, Val(0))

    @test reinterpret(UInt128, expectedoutput)[1] == output
end

function AESInternals.set_leakage!(leakages::Dict, round::Int, stage::Symbol, state::UInt128)
    leakages[(round, stage)] = state
end

function testaes256leakages()
    input = "00112233445566778899aabbccddeeff" |> hex2bytes
    key = "50d80483b3c6c51470f17c4694756104112233445566778899aabbccddeeff00" |> hex2bytes
    expectedoutput = "c48bce6977a67ee4570dd8e279ea2cbe" |> hex2bytes

    leakages = Dict(
        (1, :s_box) => UInt128(0),
        (3, :m_col) => UInt128(0),
        (14, :output) => UInt128(0),
    )

    leakkeys = keys(leakages) |> collect
    leaktuples = ntuple(i -> leakkeys[i], length(leakkeys))

    aes_encrypt(input, expandkey(key), leakages, Val{leaktuples}())

    for (k,v) in leakages
        @test !iszero(v)
    end

    @test leakages[(14, :output)] == reinterpret(UInt128, expectedoutput)[1]
end
