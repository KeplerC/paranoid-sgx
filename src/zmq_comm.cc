#include "zmq_comm.hpp"

[[noreturn]] void ZmqServer::run() {
    // socket for join requests
    zmq::socket_t socket_join (context, ZMQ_PULL);
    socket_join.bind ("tcp://*:" + std::to_string(NET_SERVER_JOIN_PORT));
    // socket for new mcast messages
    zmq::socket_t socket_msg (context, ZMQ_PULL);
    socket_msg.bind ("tcp://*:" + std::to_string(NET_SERVER_MCAST_PORT));

    zmq::socket_t socket_control (context, ZMQ_PULL);
    socket_control.bind ("tcp://*:" + std::to_string(NET_SERVER_CONTROL_PORT));
    zmq::socket_t socket_result (context, ZMQ_PULL);
    socket_result.bind ("tcp://*:" + std::to_string(NET_SERVER_RESULT_PORT));


    //poll join and mcast messages
    std::vector<zmq::pollitem_t> pollitems = {
            { static_cast<void *>(socket_join), 0, ZMQ_POLLIN, 0 },
            { static_cast<void *>(socket_msg), 0, ZMQ_POLLIN, 0 },
            { static_cast<void *>(socket_control), 0, ZMQ_POLLIN, 0 },
            { static_cast<void *>(socket_result), 0, ZMQ_POLLIN, 0 },
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

        if (pollitems[2].revents & ZMQ_POLLIN){
            std::string coordinator_addr = this->recv_string(&socket_control);
            LOGI << "[SERVER] REV CONTRL Message from" << coordinator_addr ;
            zmq::socket_t* socket_ptr  = new  zmq::socket_t( context, ZMQ_PUSH);
            socket_ptr -> connect (coordinator_addr + std::to_string(3010));
            this->send_string(this->serialize_group_addresses(), socket_ptr);
            this->m_coordinator = coordinator_addr;
        }

        if (pollitems[3].revents & ZMQ_POLLIN){
            std::string result = this->recv_string(&socket_result);
            LOGI << "[SERVER] REV result Message: " + result ;
            zmq::socket_t* socket_ptr  = new  zmq::socket_t( context, ZMQ_PUSH);
            socket_ptr -> connect (this->m_coordinator+ std::to_string(3011));
            this->send_string(result, socket_ptr);
        }
    }
}

[[noreturn]] void ZmqRouter::run() {
    // socket for join requests
    zmq::socket_t socket_join (context, ZMQ_PULL);
    socket_join.bind ("tcp://*:" + std::to_string(NET_SERVER_JOIN_PORT));
    // socket for new mcast messages
    zmq::socket_t socket_msg (context, ZMQ_PULL);
    socket_msg.bind ("tcp://*:" + std::to_string(NET_SERVER_MCAST_PORT));

    zmq::socket_t socket_control (context, ZMQ_PULL);
    socket_control.bind ("tcp://*:" + std::to_string(NET_SERVER_CONTROL_PORT));
    zmq::socket_t socket_result (context, ZMQ_PULL);
    socket_result.bind ("tcp://*:" + std::to_string(NET_SERVER_RESULT_PORT));


    //poll join and mcast messages
    std::vector<zmq::pollitem_t> pollitems = {
            { static_cast<void *>(socket_join), 0, ZMQ_POLLIN, 0 },
            { static_cast<void *>(socket_msg), 0, ZMQ_POLLIN, 0 },
            { static_cast<void *>(socket_control), 0, ZMQ_POLLIN, 0 },
            { static_cast<void *>(socket_result), 0, ZMQ_POLLIN, 0 },
    };
    //std::cout << "Start polling" << std::endl;

    while (true) {
        zmq::poll(pollitems.data(), pollitems.size(), 0);
        // Join Request
        // Curr: have router/worker node ask to join the parent
        if (pollitems[0].revents & ZMQ_POLLIN){
            std::string msg = this->recv_string(&socket_join);
            LOG(INFO)  << "[SERVER] JOIN FROM " + msg ;

            zmq::socket_t* socket_ptr  = new  zmq::socket_t( context, ZMQ_PUSH);
            socket_ptr -> connect (msg);
            this->child_sockets.push_back(socket_ptr);
            //this->send_string("Ack Join", socket_ptr);
        }

        //receive new message by worker or another router to mcast
        if (pollitems[1].revents & ZMQ_POLLIN){
            std::string msg = this->recv_string(&socket_msg);
            LOGI << "[ROUTER] Mcast Message: " + msg ;
            //TODO: mcast to children nodes (filtering)
            for (zmq::socket_t* socket : this -> child_sockets) {
                this->send_string(msg, socket);
            }
            // Forward message up the tree
            this->send_string(msg, this->parent_socket);

        }

        // Handle messages from coordinator node
        if (pollitems[2].revents & ZMQ_POLLIN){
            std::string response;

            // TODO: Tokenize message to include sender addr, operation, metadata
            std::string msg = this->recv_string(&socket_control);
            std::string coordinator_addr = "";
            LOGI << "[SERVER] REV CONTRL Message from" << coordinator_addr ;
            // TODO: Parse msg body, send JOIN request to addr specified in message

            // Always set whoever messages this port to be the new coordinator.
            zmq::socket_t* socket_ptr  = new  zmq::socket_t( context, ZMQ_PUSH);
            socket_ptr -> connect (coordinator_addr + std::to_string(3010));
            this->m_coordinator = coordinator_addr;

            // Send response to coordinator based on operation
            this->send_string(response, socket_ptr);
        }

        // Message the coordinator
        // Handles DISCONNECT requests to notify coordinator to update tree as necessary.
        if (pollitems[3].revents & ZMQ_POLLIN){
            std::string result = this->recv_string(&socket_result);
            LOGI << "[SERVER] REV result Message: " + result ;
            zmq::socket_t* socket_ptr  = new  zmq::socket_t( context, ZMQ_PUSH);
            socket_ptr -> connect (this->m_coordinator+ std::to_string(3011));
            this->send_string(result, socket_ptr);
        }
    }
}

ZmqClient::ZmqClient(std::string ip, unsigned thread_id, Asylo_SGX* sgx)
                     : zmq_comm(ip, thread_id, sgx)
                     , socket_from_server(context, ZMQ_PULL)
                     , socket_join(context, ZMQ_PUSH)
                     , socket_send(context, ZMQ_PUSH) {
    socket_from_server.bind ("tcp://*:" + m_port);
    socket_join.connect ("tcp://" + m_seed_server_ip + ":" + m_seed_server_join_port);
    socket_send.connect ("tcp://" + m_seed_server_ip + ":" + m_seed_server_mcast_port);
}

[[noreturn]] void ZmqClient::run() {
    LOG(INFO) << "tcp://" + m_seed_server_ip + ":" + m_seed_server_mcast_port;
    LOG(INFO) << "tcp://" + m_seed_server_ip + ":" + m_seed_server_join_port;

    //send join request to seed server
    this->send_string(m_addr, &socket_join);

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
            this->m_sgx->send_to_sgx(msg);
        }
    }
}


ZmqJsClient::ZmqJsClient(std::string ip, unsigned thread_id, Asylo_SGX* sgx)
                         : zmq_comm(ip, thread_id, sgx)
                         , socket_from_server(context, ZMQ_PULL)
                         , socket_code(context, ZMQ_PULL)
                         , socket_join(context, ZMQ_PUSH)
                         , socket_send(context, ZMQ_PUSH) {
    socket_from_server.bind ("tcp://*:" + m_port);
    socket_join.connect ("tcp://" + m_seed_server_ip + ":" + m_seed_server_join_port);
    //a socket to server to multicast
    socket_send.connect ("tcp://" + m_seed_server_ip + ":" + m_seed_server_mcast_port);
    socket_code.bind ("tcp://*:3006");
}

[[noreturn]] void ZmqJsClient::run() {
    LOG(INFO) << "tcp://" + m_seed_server_ip + ":" + m_seed_server_mcast_port;
    LOG(INFO) << "tcp://" + m_seed_server_ip + ":" + m_seed_server_join_port;

    //send join request to seed server
    this->send_string(m_addr, &socket_join);

    // poll for new messages
    std::vector<zmq::pollitem_t> pollitems = {
            { static_cast<void *>(&socket_from_server), 0, ZMQ_POLLIN, 0 },
            { static_cast<void *>(&socket_code), 0, ZMQ_POLLIN, 0 },
    };

    //start enclave
    while (true) {
        // LOG(INFO) << "Start zmq";
        zmq::poll(pollitems.data(), pollitems.size(), 0);
        // Join Request
        if (pollitems[0].revents & ZMQ_POLLIN) {
            //Get the address
            std::string msg = this->recv_string(&socket_from_server);
            LOG(INFO) << "[Client " << m_addr << "]:  " + msg ;
            // this -> send_string(m_port , socket_send);
            this->m_sgx->send_to_sgx(msg);
        }
        if (pollitems[1].revents & ZMQ_POLLIN) {
            //Get the address
            std::string msg = this->recv_string(&socket_code);
            // LOG(INFO) << "[Client " << m_addr << "]:  " + msg ;
            // this -> send_string(m_port , socket_send);
            this->m_sgx->execute_js_code(msg);
        }
    }
}
