#include "zmq_comm.hpp"
#define _CAPSULE_DB

[[noreturn]] void zmq_comm::run_server(){
    zmq::context_t context (1);
    // socket for join requests
    zmq::socket_t socket_join (context, ZMQ_PULL);
    socket_join.bind ("tcp://*:" + std::to_string(NET_SERVER_JOIN_PORT));
    // socket for new mcast messages
    zmq::socket_t socket_msg (context, ZMQ_PULL);
    socket_msg.bind ("tcp://*:" + std::to_string(NET_SERVER_MCAST_PORT));
    std::cout << "Bound multicast port" << std::endl;

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

            // Make sure no repeated joins
            if (std::find(this->group_addresses.begin(), this->group_addresses.end(), msg) == this->group_addresses.end()) {
                this->group_addresses.push_back(msg);

                //create a socket to the client and save
                zmq::socket_t* socket_ptr  = new  zmq::socket_t( context, ZMQ_PUSH);
                socket_ptr -> connect (msg);
                this->group_sockets.push_back(socket_ptr);
                //this->send_string("Ack Join", socket_ptr);
            }
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
            socket_ptr -> connect (coordinator_addr + std::to_string(NET_COORDINATOR_RECV_MEMBERSHIP_PORT));
            this->send_string(this->serialize_group_addresses(), socket_ptr);
            this->m_coordinator = coordinator_addr;
        }

        if (pollitems[3].revents & ZMQ_POLLIN){
            std::string result = this->recv_string(&socket_result);
            LOGI << "[SERVER] REV result Message: " + result ;
            zmq::socket_t* socket_ptr  = new  zmq::socket_t( context, ZMQ_PUSH);
            socket_ptr -> connect (this->m_coordinator+ std::to_string(NET_COORDINATOR_RECV_RESULT_PORT));
            this->send_string(result, socket_ptr);
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
            LOG(INFO) << "[Client " << m_addr << "]:  " + msg ;
            this->m_sgx->send_to_sgx(msg);
        }
    }
}


[[noreturn]] void zmq_comm::run_js_client(){
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

    zmq::socket_t socket_code (context, ZMQ_PULL);
    socket_code.bind ("tcp://*:" + m_recv_code_port);

    LOG(INFO) << "tcp://" + m_seed_server_ip + ":" + m_seed_server_mcast_port;
    LOG(INFO) << "tcp://" + m_seed_server_ip + ":" + m_seed_server_join_port;

    // poll for new messages
    std::vector<zmq::pollitem_t> pollitems = {
            { static_cast<void *>(socket_from_server), 0, ZMQ_POLLIN, 0 },
            { static_cast<void *>(socket_code), 0, ZMQ_POLLIN, 0 },
    };


    //start enclave
    while (true) {
        // LOG(INFO) << "Start zmq";
        zmq::poll(pollitems.data(), pollitems.size(), 0);
        // Send to server
        if (pollitems[0].revents & ZMQ_POLLIN) {
            //Get the address
            std::string msg = this->recv_string(&socket_from_server);
            LOGI << "[Client " << m_addr << "]:  " + msg ;
            // this -> send_string(m_port , socket_send);
            this->m_sgx->send_to_sgx(msg);
        }
        if (pollitems[1].revents & ZMQ_POLLIN) {
            //Get the address
            std::string msg = this->recv_string(&socket_code);
            // LOGI << "[Client " << m_addr << "]:  " + msg ;
            // LOG(INFO) << "[Client " << m_addr << "]:  " + msg ;
            // this -> send_string(m_port , socket_send);
            this->m_sgx->execute_js_code(msg);
        }
    }
}

[[noreturn]] void zmq_comm::run_cdb_client(){
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
            LOGI << "[CapsuleDB client " << m_addr << "]:  " + msg ;
            // Convert message to protobuf
            hello_world::CapsulePDU in_dc;
            in_dc.ParseFromString(msg);

            hello_world::CapsulePDU out_dc = this->m_db->handle(in_dc);
            if (out_dc.has_payload_in_transit()) {
                // Has contents to return (non-empty payload)
                LOGI << "Got response, return to mcast tree";

                // Convert to zmq message
                std::string out_s;
                out_dc.SerializeToString(&out_s);

                zmq::message_t msg(out_s.size());
                memcpy(msg.data(), out_s.c_str(), out_s.size());

                socket_send->send(msg);
            }
            /*
            // Old client semantics (directly forward to requester)
            if (out_dc.has_payload_in_transit()) {
                // Has contents to return (non-empty payload)
                LOG(INFO) << "Got response, return to " << in_dc.retaddr();
                
                // Connect to return socket
                zmq::socket_t* socket_ret = new zmq::socket_t( context, ZMQ_PUSH);
                socket_ret -> connect (in_dc.retaddr());

                // Convert to zmq message
                std::string out_s;
                out_dc.SerializeToString(&out_s);

                zmq::message_t msg(out_s.size());
                memcpy(msg.data(), out_s.c_str(), out_s.size());

                socket_ret->send(msg);
                delete socket_ret;
            }
            */
        }
    }
}


