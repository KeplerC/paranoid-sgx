
M_FINAL_SCRIPT = '''
#ifndef PARANOID_SGX_BENCHMARK2_H
#define PARANOID_SGX_BENCHMARK2_H

#define M_BENCHMARK_HERE2 void benchmark2(){ \\
'''

def proc_put(line):
    global M_FINAL_SCRIPT
    M_FINAL_SCRIPT += ("\tput(\"{}\", R\"({})\");\\\n".format(line[1], line[2].replace('"',"'").replace(",",".")))

def proc_get(line):
    global M_FINAL_SCRIPT
    M_FINAL_SCRIPT += ("\tget(\"{}\");\\\n".format(line[1]))

M_FINAL_SCRIPT += "\t LOGD << \"Run iteration started\"; \\\n"

counter_put = 0
counter_get = 0
counter_skip = 0
with open("./tracea_run_a.txt") as f:
    text = f.read()
    for line in text.split("\n"):
        if counter_skip <= 5000:
            counter_skip += 1
            continue
        if not line:
            continue
        line = line.split(" ")
        if line[0] == "GET":
            proc_get(line)
            counter_put += 1
        else:
            proc_put(line)
            counter_get += 1

M_FINAL_SCRIPT += "\t LOGD << \"Run iteration ended\"; \\\n"

M_FINAL_SCRIPT+= '''}

#endif //PARANOID_SGX_BENCHMARK2_H
'''

print(M_FINAL_SCRIPT)

with open("../src/benchmark2.h", "w") as f:
    f.write(M_FINAL_SCRIPT)
