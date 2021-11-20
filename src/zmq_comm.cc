#include "zmq_comm.hpp"

ZmqServer::ZmqServer(std::string ip, unsigned thread_id)
                     : ZmqComm(ip, thread_id, {
                        { static_cast<void *>(socket_join_), 0, ZMQ_POLLIN, 0 },
                        { static_cast<void *>(socket_msg_), 0, ZMQ_POLLIN, 0 },
                        { static_cast<void *>(socket_control_), 0, ZMQ_POLLIN, 0 },
                        { static_cast<void *>(socket_result_), 0, ZMQ_POLLIN, 0 },
                     })
                     , socket_join_(context_, ZMQ_PULL)
                     , socket_msg_(context_, ZMQ_PULL)
                     , socket_control_(context_, ZMQ_PULL)
                     , socket_result_(context_, ZMQ_PULL)
                     , wsocket_msg_(&socket_msg_, thread_id) {
    socket_join_.bind("tcp://*:" + std::to_string(NET_SERVER_JOIN_PORT));
    socket_msg_.bind("tcp://*:" + std::to_string(NET_SERVER_MCAST_PORT));
    socket_control_.bind("tcp://*:" + std::to_string(NET_SERVER_CONTROL_PORT));
    socket_result_.bind("tcp://*:" + std::to_string(NET_SERVER_RESULT_PORT));
}

void ZmqServer::net_setup() {
}

void ZmqServer::net_handler() {
    //std::cout << "Start polling" << std::endl;
    // Join Request
    if (pollitems_[0].revents & ZMQ_POLLIN){
        //Get the address
        std::string msg = this->recv_string(&socket_join_);
        LOG(INFO)  << "[SERVER] JOIN FROM " + msg ;
        this->group_addresses_.push_back(msg);

        //create a socket to the client and save
        zmq::socket_t* socket_ptr  = new  zmq::socket_t( context_, ZMQ_PUSH);
        socket_ptr -> connect (msg);
        this->group_sockets_.push_back(socket_ptr);
        //this->send_string("Ack Join", socket_ptr);
    }

    //receive new message to mcast
    if (pollitems_[1].revents & ZMQ_POLLIN){
        std::string msg = this->recv_string(&socket_msg_);
        LOGI << "[SERVER] Mcast Message: " + msg ;
        //mcast to all the clients
        for (zmq::socket_t* socket : this->group_sockets_) {
            this->send_string(msg, socket);
        }
    }

    if (pollitems_[2].revents & ZMQ_POLLIN){
        std::string coordinator_addr = this->recv_string(&socket_control_);
        LOGI << "[SERVER] REV CONTRL Message from" << coordinator_addr ;
        zmq::socket_t* socket_ptr  = new  zmq::socket_t( context_, ZMQ_PUSH);
        socket_ptr -> connect (coordinator_addr + std::to_string(3010));
        this->send_string(this->serialize_group_addresses(), socket_ptr);
        this->coordinator_ = coordinator_addr;
    }

    if (pollitems_[3].revents & ZMQ_POLLIN){
        std::string result = this->recv_string(&socket_result_);
        LOGI << "[SERVER] REV result Message: " + result ;
        zmq::socket_t* socket_ptr  = new  zmq::socket_t( context_, ZMQ_PUSH);
        socket_ptr -> connect (this->coordinator_ + std::to_string(3011));
        this->send_string(result, socket_ptr);
    }
}

ZmqRouter::ZmqRouter(std::string ip, unsigned thread_id)
                     : ZmqComm(ip, thread_id, {
                        { static_cast<void *>(socket_join_), 0, ZMQ_POLLIN, 0 },
                        { static_cast<void *>(socket_msg_), 0, ZMQ_POLLIN, 0 },
                        { static_cast<void *>(socket_control_), 0, ZMQ_POLLIN, 0 },
                        { static_cast<void *>(socket_result_), 0, ZMQ_POLLIN, 0 },
                     })
                     , socket_join_(context_, ZMQ_PULL)
                     , socket_msg_(context_, ZMQ_PULL)
                     , socket_control_(context_, ZMQ_PULL)
                     , socket_result_(context_, ZMQ_PULL) {
    socket_join_.bind ("tcp://*:" + std::to_string(NET_SERVER_JOIN_PORT));
    socket_msg_.bind ("tcp://*:" + std::to_string(NET_SERVER_MCAST_PORT));
    socket_control_.bind ("tcp://*:" + std::to_string(NET_SERVER_CONTROL_PORT));
    socket_result_.bind ("tcp://*:" + std::to_string(NET_SERVER_RESULT_PORT));
}

void ZmqRouter::net_setup() {
}

void ZmqRouter::net_handler() {
    //std::cout << "Start polling" << std::endl;
    //poll join and mcast messages

    // Join Request
    // Curr: have router/worker node ask to join the parent
    if (pollitems_[0].revents & ZMQ_POLLIN){
        std::string msg = this->recv_string(&socket_join_);
        LOGI << "[SERVER] JOIN FROM " + msg ;

        zmq::socket_t* socket_ptr  = new  zmq::socket_t( context_, ZMQ_PUSH);
        socket_ptr -> connect (msg);
        this->child_sockets_.push_back(socket_ptr);
        //this->send_string("Ack Join", socket_ptr);
    }

    //receive new message by worker or another router to mcast
    if (pollitems_[1].revents & ZMQ_POLLIN){
        std::string msg = this->recv_string(&socket_msg_);
        LOGI << "[ROUTER] Mcast Message: " + msg;
        //TODO: mcast to children nodes (filtering)
        for (zmq::socket_t* socket : this -> child_sockets_) {
            this->send_string(msg, socket);
        }
        // Forward message up the tree
        this->send_string(msg, this->parent_socket_);
    }

    // Handle messages from coordinator node
    if (pollitems_[2].revents & ZMQ_POLLIN){
        std::string response;

        // TODO: Tokenize message to include sender addr, operation, metadata
        std::string msg = this->recv_string(&socket_control_);
        std::string coordinator_addr = "";
        LOGI << "[SERVER] REV CONTRL Message from" << coordinator_addr ;
        // TODO: Parse msg body, send JOIN request to addr specified in message

        // Always set whoever messages this port to be the new coordinator.
        zmq::socket_t* socket_ptr  = new  zmq::socket_t(context_, ZMQ_PUSH);
        socket_ptr -> connect (coordinator_addr + std::to_string(3010));
        this->coordinator_ = coordinator_addr;

        // Send response to coordinator based on operation
        this->send_string(response, socket_ptr);
    }

    // Message the coordinator
    // Handles DISCONNECT requests to notify coordinator to update tree as necessary.
    if (pollitems_[3].revents & ZMQ_POLLIN){
        std::string result = this->recv_string(&socket_result_);
        LOGI << "[SERVER] REV result Message: " + result ;
        zmq::socket_t* socket_ptr  = new  zmq::socket_t(context_, ZMQ_PUSH);
        socket_ptr -> connect (this->coordinator_+ std::to_string(3011));
        this->send_string(result, socket_ptr);
    }
}

ZmqClient::ZmqClient(std::string ip, unsigned thread_id, Asylo_SGX* sgx)
                     : ZmqComm(ip, thread_id, {
                        { static_cast<void *>(socket_from_server_), 0, ZMQ_POLLIN, 0 },
                     })
                     , sgx_(sgx)
                     , socket_join_(context_, ZMQ_PUSH)
                     , socket_from_server_(context_, ZMQ_PULL)
                     , socket_send_(context_, ZMQ_PUSH)
                     , wsocket_from_server_(&socket_from_server_, thread_id) {
    socket_from_server_.bind ("tcp://*:" + port_);
    socket_join_.connect ("tcp://" + seed_server_ip_ + ":" + seed_server_join_port_);
    socket_send_.connect ("tcp://" + seed_server_ip_ + ":" + seed_server_mcast_port_);
}

void ZmqClient::net_setup() {
    LOG(INFO) << "tcp://" + seed_server_ip_ + ":" + seed_server_mcast_port_;
    LOG(INFO) << "tcp://" + seed_server_ip_ + ":" + seed_server_join_port_;

    //send join request to seed server
    this->send_string(addr_, &socket_join_);
}

void ZmqClient::net_handler() {
    //start enclave
    // LOG(INFO) << "Start zmq";
    // Join Request
    if (pollitems_[0].revents & ZMQ_POLLIN) {
        //Get the address
        std::string msg = this->recv_string(&socket_from_server_);
        LOGI << "[Client " << addr_ << "]:  " + msg ;
        // this -> send_string(port_ , socket_send_);
        this->sgx_->send_to_sgx(msg);
    }
}

ZmqJsClient::ZmqJsClient(std::string ip, unsigned thread_id, Asylo_SGX* sgx)
                         : ZmqComm(ip, thread_id, {
                            { static_cast<void *>(&socket_from_server_), 0, ZMQ_POLLIN, 0 },
                            { static_cast<void *>(&socket_code_), 0, ZMQ_POLLIN, 0 },
                         })
                         , sgx_(sgx)
                         , socket_join_(context_, ZMQ_PUSH)
                         , socket_from_server_(context_, ZMQ_PULL)
                         , socket_code_(context_, ZMQ_PULL)
                         , socket_send_(context_, ZMQ_PUSH)
                         , wsocket_from_server_(&socket_from_server_, thread_id)
                         , wsocket_code_(&socket_code_, thread_id) {
    socket_join_.connect ("tcp://" + seed_server_ip_ + ":" + seed_server_join_port_);
    socket_from_server_.bind ("tcp://*:" + port_);
    socket_send_.connect ("tcp://" + seed_server_ip_ + ":" + seed_server_mcast_port_);
    socket_code_.bind ("tcp://*:3006");
}

void ZmqJsClient::net_setup() {
    LOGI << "tcp://" + seed_server_ip_ + ":" + seed_server_mcast_port_;
    LOGI << "tcp://" + seed_server_ip_ + ":" + seed_server_join_port_;

    //send join request to seed server
    send_string(addr_, &socket_join_);
}

void ZmqJsClient::net_handler() {
    //start enclave
    // LOG(INFO) << "Start zmq";
    // Join Request
    if (pollitems_[0].revents & ZMQ_POLLIN) {
        //Get the address
        std::string msg = this->recv_string(&socket_from_server_);
        LOGI << "[Client " << addr_ << "]:  " + msg ;
        // this -> send_string(port_ , socket_send_);
        sgx_->send_to_sgx(msg);
    }

    if (pollitems_[1].revents & ZMQ_POLLIN) {
        //Get the address
        //std::string msg = this->recv_string(&socket_code_);
        auto proto = wsocket_code_.recv();
        auto body = proto->mutable_body();
        assert(body->has_code());

        const std::string& msg = body->code().str();
        
        LOG(INFO) << "[Client " << addr_ << "]:  " + msg ;
        // this -> send_string(port_ , socket_send_);
        sgx_->execute_js_code(msg);
    }
}
