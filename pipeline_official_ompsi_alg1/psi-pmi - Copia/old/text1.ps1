foreach ($n in 2, 3, 4, 8, 16) {
    cargo run --release --example bench_e2e -- `
        --n $n --u 4 --n-bits 128 --hash-k 3 `
        --degree 8192 --runs 3 --set-size 10 `
        --out f1_correctness.csv --append
}
