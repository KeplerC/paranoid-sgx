
def proc_put(line):
	print("put(\"{}\", \"{}\");".format(line[1], line[2].replace("\"", "").replace("\\", "")))

def proc_get(line):
	return
	print("get(\"{}\");".format(line[1]))
	
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
        
