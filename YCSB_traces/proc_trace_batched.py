
M_FINAL_SCRIPT = '''
#ifndef PARANOID_SGX_BENCHMARK_H
#define PARANOID_SGX_BENCHMARK_H

#define M_BENCHMARK_HERE void benchmark(){ \\
'''

def proc_get(line):
    global M_FINAL_SCRIPT
    M_FINAL_SCRIPT += ("\tget(\"{}\");\\\n".format(line[1]))

batch_size = 200
number_of_get = 300

counter = 0
def proc_put(load_keys, load_values):
    global M_FINAL_SCRIPT
    global counter
    while(load_keys):
        counter += 1
        keys = load_keys[:batch_size]
        load_keys = load_keys[batch_size:]
        values = load_values[:batch_size]
        load_values = load_values[batch_size:]
        M_FINAL_SCRIPT += ("std::vector<std::string> k"+str(counter)+"{{\"{}\"}};".format("\",\"".join(keys)))
        M_FINAL_SCRIPT += ("std::vector<std::string> v"+str(counter)+"{{\"{}\"}};".format("\",\"".join(values)))
        M_FINAL_SCRIPT += ("put_multi({}, {});\\\n".format("k"+str(counter), "v"+str(counter)))

M_FINAL_SCRIPT += "\t LOGD << \"Load started\"; \\\n"
put_load_keys = []
put_load_values = []
with open("./tracea_load_a.txt") as f:
    text = f.read()
    for line in text.split("\n"):
        if not line:
            continue 
        line_kv = line.split(" ")
        put_load_keys += [line_kv[1]]
        put_load_values += [line_kv[2].replace('"',"").replace(",","").replace("?","").replace("\\", "")]
proc_put(put_load_keys,put_load_values)


M_FINAL_SCRIPT += "\t LOGD << \"client put end\"; \\\n"
        

put_runtime_keys = []       
put_runtime_values = []
get_counter = 0
with open("./tracea_run_a.txt") as f:
    text = f.read()
    for line in text.split("\n"):
        if not line:
            continue 
        line_kv = line.split(" ")
        if line_kv[0] == "GET":
            get_counter += 1
            if(get_counter < number_of_get):
                proc_get(line_kv)
            pass
        if line_kv[0] == "SET":
            put_runtime_keys += [line_kv[1]]
            put_runtime_values += [line_kv[2].replace('"',"").replace(",","").replace("?","").replace("\\", "")]
proc_put(put_runtime_keys,put_runtime_values)

M_FINAL_SCRIPT += "\t LOGD << \"put and get end\"; \\\n"

M_FINAL_SCRIPT+= '''}

#endif //PARANOID_SGX_BENCHMARK_H
'''

print(M_FINAL_SCRIPT)

with open("../src/benchmark.h", "w") as f:
    f.write(M_FINAL_SCRIPT)
