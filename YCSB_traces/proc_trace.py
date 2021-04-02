
M_FINAL_SCRIPT = '''
#ifndef PARANOID_SGX_BENCHMARK_H
#define PARANOID_SGX_BENCHMARK_H

#define M_BENCHMARK_HERE void benchmark(){ \\
'''

def proc_put(line):
    global M_FINAL_SCRIPT
    M_FINAL_SCRIPT += ("\tput(\"{}\", \"{}\");\\ \n".format(line[1], line[2].replace("\"", "").replace("\\", "")))

def proc_get(line):
    global M_FINAL_SCRIPT
    return
    M_FINAL_SCRIPT += ("\tget(\"{}\");\\ \n".format(line[1]))
	
with open("./tracea_load_a.txt") as f:
    text = f.read()
    for line in text.split("\n"):
        if not line:
            continue 
        line = line.split(" ")
        proc_put(line)

with open("./tracea_run_a.txt") as f:
    text = f.read()
    counter = 0
    for line in text.split("\n"):
        if not line:
            continue
        line = line.split(" ")
        if line[0] == "GET":
            proc_get(line)
        else:
            proc_put(line)
        if counter%100 == 1:
        	print("LOG(INFO) << {}; ".format( str(counter)))
        counter += 1
        
M_FINAL_SCRIPT+= '''}

#endif //PARANOID_SGX_BENCHMARK_H
'''

print(M_FINAL_SCRIPT)

with open("../src/benchmark.h", "w") as f:
    f.write(M_FINAL_SCRIPT)