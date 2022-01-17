
#apt install -y git
#MY_PROJECT=~/paranoid-sgx
#git clone https://github.com/KeplerC/paranoid-sgx.git "${MY_PROJECT}"


#sudo groupadd docker
#sudo usermod -aG docker $USER
#newgrp docker

echo "[installing sgx driver]"
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add
sudo apt-get update
sudo apt-get install -y libsgx-epid libsgx-quote-ex libsgx-dcap-ql

echo "[pulling and running PSL docker image]"
sudo docker run -it --rm \
    --network=host \
    -v bazel-cache:/root/.cache/bazel \
    -v "${MY_PROJECT}":/opt/my-project \
    -w /opt/my-project \
    keplerc/paranoid-asylo:latest