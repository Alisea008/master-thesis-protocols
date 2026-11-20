import subprocess

executable = "../target/release/attack"        # <-- era bloom-goes-boom
trials = 1000000
# universe_size = 32
universe_size = 26

options_priority = [
    (5, 8, 2),
    (5, 8, 3),
    (5, 8, 4),
    (10, 8, 2),
    (10, 8, 3),
    (10, 8, 4),
    (10, 12, 2),
    (10, 16, 2),
    (20, 8, 2),
    (20, 8, 3),
    (20, 8, 4),
    (20, 12, 2),
    (20, 16, 2),
    (30, 8, 2),
    (30, 8, 3),
    (30, 8, 4),
    (30, 12, 2),
    (30, 16, 2),
]

def run_bloom(false_positive, max_set_size, universe_client_factor):
    flags = [
        f"--universe-size={universe_size}",
        f"--universe-client-factor={universe_client_factor}",
        f"--client-set-size={max_set_size}",
        f"--max-set-size={max_set_size}",
        f"--false-positives={false_positive}",
        f"--trials={trials}",
        "-v",
    ]
    cmd = [executable] + flags
    print(f"% {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    print(f"{false_positive} & {max_set_size} & {universe_client_factor} &  % fp k U2_fact")
    for line in proc.stdout: print(line, end="")
    for line in proc.stderr: print(line, end="")
    proc.wait()

for fp, k, f in options_priority:
    run_bloom(fp, k, f)
