import subprocess
import os
import glob

process_count = int(input("Instance Count >> "))

## Create dist-combos folder, or clear previous files
if not os.path.exists("dist-combos"):
    os.mkdir("dist-combos")
else:
    for f in glob.glob("dist-combos/*"):
        os.remove(f)

## Load original combo file
with open("combos.txt", encoding="UTF-8", errors="ignore") as f:
    total_combos = f.read().splitlines()[::-1]

## Calculate amount of combos per process/file
per_chunk = int(len(total_combos)/process_count)

## Split combo file into parts and write them into different files
pn = 0
while 1:
    pn += 1
    combos = [total_combos.pop() for _ in range(per_chunk) if total_combos]
    if not combos: break
    with open(f"dist-combos/{pn}", "w", encoding="UTF-8", errors="ignore") as f:
        f.write("\n".join(combos))

## Start cracker processes and feed combo parts into them
processes = []
for pn in range(1, process_count+1):
    path = f"dist-combos/{pn}"
    p = subprocess.Popen(["python", "cracker.py", path],
        creationflags=subprocess.CREATE_NEW_CONSOLE)
    processes.append(p)