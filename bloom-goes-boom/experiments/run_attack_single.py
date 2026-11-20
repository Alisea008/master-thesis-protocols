import subprocess

executable = "../target/release/attack_single"
trials = 1000000
# universe_size = 32
universe_size = 26

options_priority = [
    (10, 8, 2),
    (20, 8, 2),
    (10, 12, 2),
    (20, 12, 2),
    (10, 16, 2),
    (20, 16, 2),
]

def run(fp, k, f):
    flags = [
        f"--universe-size={universe_size}",
        f"--universe-client-factor={f}",
        f"--client-set-size={k}",
        f"--max-set-size={k}",
        f"--false-positives={fp}",
        f"--trials={trials}",
        "-v",
    ]
    cmd = [executable] + flags
    print(f"% {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    print(f"{fp} & {k} & {f} &  % fp k U2_fact")
    for line in proc.stdout: print(line, end="")
    for line in proc.stderr: print(line, end="")
    proc.wait()

for fp, k, f in options_priority:
    run(fp, k, f)
