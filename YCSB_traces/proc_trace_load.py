
M_FINAL_SCRIPT = '''
#ifndef PARANOID_SGX_BENCHMARK_LOAD
#define PARANOID_SGX_BENCHMARK_LOAD

#define M_BENCHMARK_HERE_LOAD void benchmark_load(){ \\
'''

def proc_put(line):
    global M_FINAL_SCRIPT
    M_FINAL_SCRIPT += ("\tput(\"{}\", R\"({})\");\\\n".format(line[1], line[2].replace('"',"'").replace(",",".")))

def proc_get(line):
    global M_FINAL_SCRIPT
    M_FINAL_SCRIPT += ("\tget(\"{}\");\\\n".format(line[1]))

M_FINAL_SCRIPT += "\t LOGD << \"Pre-test kv load started\"; \\\n"

counter_put = 0
counter_get = 0
with open("./tracea_load_a.txt") as f:
    text = f.read()
    for line in text.split("\n"):
        if counter_get+counter_put > 5000:
            break
        if not line:
            continue
        line = line.split(" ")
        if line[0] == "GET":
            proc_get(line)
            counter_put += 1
        else:
            proc_put(line)
            counter_get += 1

M_FINAL_SCRIPT += "\t LOGD << \"Pre-test kv load done\"; \\\n"

M_FINAL_SCRIPT+= '''}

#endif //PARANOID_SGX_BENCHMARK_LOAD
'''

print(M_FINAL_SCRIPT)

with open("../src/benchmark_load.h", "w") as f:
    f.write(M_FINAL_SCRIPT)
