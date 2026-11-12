"GENERATED"

load("@rules_dotnet//dotnet:defs.bzl", "nuget_repo")

def main():
    "main"
    nuget_repo(
        name = "paket.main",
        packages = [
            {"name": "SP.Other", "id": "SP.Other", "version": "1.0.0", "sha512": "sha512-UYYndM/8aEsn2NPPHecSroWYSo3HDOkkfkQNjT/ZOD6Bjq/KiIwiAztAkfWyVdctVooIskr8ELkRXrcKGMWyJQ==", "sources": ["https://api.nuget.org/v3/index.json"], "dependencies": {"net6.0": [], "net8.0": [], "net9.0": [], "netstandard2.0": [], "netstandard2.1": []}, "targeting_pack_overrides": [], "framework_list": [], "tools": {}},
            {"name": "SP.Victim", "id": "SP.Victim", "version": "1.0.0", "sha512": "sha512-fIYTuz3T8aSwai2/N4teNgwbFh7YYi50ptRulds1qeLLcwYgoIxuE+QgjpW8w9BHAD6/mKkGH1qAXgEzOV25KA==", "sources": ["https://api.nuget.org/v3/index.json"], "dependencies": {"net6.0": [], "net8.0": [], "net9.0": [], "netstandard2.0": [], "netstandard2.1": []}, "targeting_pack_overrides": [], "framework_list": [], "tools": {}},
        ],
    )
