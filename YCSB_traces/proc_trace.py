
M_FINAL_SCRIPT = '''
#ifndef PARANOID_SGX_BENCHMARK_H
#define PARANOID_SGX_BENCHMARK_H

#define M_BENCHMARK_HERE void benchmark(){ \\
'''

def proc_put(line):
    global M_FINAL_SCRIPT
    M_FINAL_SCRIPT += ("\tput(\"{}\", \"{}\");\\\n".format(line[1], "default_value"))

def proc_get(line):
    global M_FINAL_SCRIPT
    M_FINAL_SCRIPT += ("\tget(\"{}\");\\\n".format(line[1]))

# M_FINAL_SCRIPT += "\t LOGD << \"Load started\"; \\\n"

# counter = 0
# num_times = 5
# with open("./tracea_load_a.txt") as f:
#     text = f.read() * num_times
#     for line in text.split("\n"):
#         if not line:
#             continue 
#         line = line.split(" ")
#         proc_put(line)
#         counter += 1

# M_FINAL_SCRIPT += "\t LOGD << \"client put end\"; \\\n"

# M_FINAL_SCRIPT += "\t LOGD << \"Loaded {} entries\"; \\\n".format(counter)

counter_put = 0
counter_get = 0
with open("./tracea_run_a.txt") as f:
    text = f.read()
    for line in text.split("\n"):
        if not line:
            continue
        line = line.split(" ")
        if line[0] == "GET":
            proc_get(line)
            counter_put += 1
        else:
            proc_put(line)
            counter_get += 1

# M_FINAL_SCRIPT += "\t LOGD << \"put {} and get {} end\"; \\\n".format(counter_put, counter_get)

M_FINAL_SCRIPT+= '''}

#endif //PARANOID_SGX_BENCHMARK_H
'''

print(M_FINAL_SCRIPT)

with open("../src/benchmark.h", "w") as f:
    f.write(M_FINAL_SCRIPT)
