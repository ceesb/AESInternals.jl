# docs/make.jl
using Documenter, AESInternals

makedocs(
    sitename = "AESInternals.jl",
    modules = [AESInternals],
    format = Documenter.HTML(),
    pages = [
        "Home" => "index.md",
        "API"  => "api.md",
    ]
)
