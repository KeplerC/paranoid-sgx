#include "zmq_comm.hpp"
// #define _CAPSULE_DB

[[noreturn]] void zmq_comm::run_server(){
    zmq::context_t context (1);
    // socket for join requests
    zmq::socket_t socket_join (context, ZMQ_PULL);
    socket_join.bind ("tcp://*:" + std::to_string(NET_SERVER_JOIN_PORT));
    // socket for new mcast messages
    zmq::socket_t socket_msg (context, ZMQ_PULL);
    socket_msg.bind ("tcp://*:" + std::to_string(NET_SERVER_MCAST_PORT));


    //poll join and mcast messages
    std::vector<zmq::pollitem_t> pollitems = {
            { static_cast<void *>(socket_join), 0, ZMQ_POLLIN, 0 },
            { static_cast<void *>(socket_msg), 0, ZMQ_POLLIN, 0 },
    };
    //std::cout << "Start polling" << std::endl;

    while (true) {
        zmq::poll(pollitems.data(), pollitems.size(), 0);
        // Join Request
        if (pollitems[0].revents & ZMQ_POLLIN){
            //Get the address
            std::string msg = this->recv_string(&socket_join);
            LOG(INFO)  << "[SERVER] JOIN FROM " + msg ;
            this->group_addresses.push_back(msg);

            //create a socket to the client and save
            zmq::socket_t* socket_ptr  = new  zmq::socket_t( context, ZMQ_PUSH);
            socket_ptr -> connect (msg);
            this->group_sockets.push_back(socket_ptr);
            //this->send_string("Ack Join", socket_ptr);
        }

        //receive new message to mcast
        if (pollitems[1].revents & ZMQ_POLLIN){
            std::string msg = this->recv_string(&socket_msg);
            LOGI << "[SERVER] Mcast Message: " + msg ;
            //mcast to all the clients
            for (zmq::socket_t* socket : this -> group_sockets) {
                this->send_string(msg, socket);
            }
        }
    }
}

[[noreturn]] void zmq_comm::run_client(){
    zmq::context_t context (1);

    zmq::socket_t socket_from_server (context, ZMQ_PULL);
    socket_from_server.bind ("tcp://*:" + m_port);


    //send join request to seed server
    zmq::socket_t* socket_join  = new  zmq::socket_t( context, ZMQ_PUSH);
    socket_join -> connect ("tcp://" + m_seed_server_ip + ":" + m_seed_server_join_port);
    this->send_string(m_addr, socket_join);

    //a socket to server to multicast
    zmq::socket_t* socket_send  = new  zmq::socket_t( context, ZMQ_PUSH);
    socket_send -> connect ("tcp://" + m_seed_server_ip + ":" + m_seed_server_mcast_port);

    LOG(INFO) << "tcp://" + m_seed_server_ip + ":" + m_seed_server_mcast_port;
    LOG(INFO) << "tcp://" + m_seed_server_ip + ":" + m_seed_server_join_port;

    // poll for new messages
    std::vector<zmq::pollitem_t> pollitems = {
            { static_cast<void *>(socket_from_server), 0, ZMQ_POLLIN, 0 },
    };


    //start enclave
    while (true) {
        // LOG(INFO) << "Start zmq"; 
        zmq::poll(pollitems.data(), pollitems.size(), 0);
        // Join Request
        if (pollitems[0].revents & ZMQ_POLLIN) {
            //Get the address
            std::string msg = this->recv_string(&socket_from_server);
            // LOG(INFO) << "[Client " << m_addr << "]:  " + msg ;
            // this -> send_string(m_port , socket_send);
            #ifdef _CAPSULE_DB
            LOG(INFO) << "[Client " << m_addr << "]:  " + msg ;
            // this->m_db->handle(dc)
            #else
            this->m_sgx->send_to_sgx(msg);
            #endif
        }
    }
}