set shell := ["bash", "-c"]
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

default:
    just --list

run *args:
    @cargo build --package hook {{args}}
    @cargo run --package launcher {{args}}

check:
    @cargo clippy --all-features --all-targets -- -D warnings
    @cargo machete
    @cargo nextest run
