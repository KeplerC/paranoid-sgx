#include "zmq_comm.hpp"

ZmqComm::ZmqComm(std::string ip, unsigned thread_id)
            : thread_id_(thread_id)
            , context_(1)
            , seed_server_ip_(NET_SEED_ROUTER_IP)
            , seed_server_join_port_(std::to_string(NET_SERVER_JOIN_PORT))
            , seed_server_mcast_port_(std::to_string(NET_SERVER_MCAST_PORT))
            , enclave_seq_number_(0)
            , coordinator_("") {
    port_ = std::to_string(NET_CLIENT_BASE_PORT + thread_id);
    addr_ = "tcp://" + ip +":" + port_;
    LOGI << "[ZmqComm] Constructing agent: ID "<<thread_id
         << ", Address " << addr_;
}

[[noreturn]] void ZmqComm::run() {
    net_setup();
    while (true) {
        poll();
        net_handler();
    }
}

void ZmqComm::poll() {
    zmq::poll(pollitems_.data(), pollitems_.size(), 0);
}

ZmqServer::ZmqServer(std::string ip, unsigned thread_id)
                     : ZmqComm(ip, thread_id)
                     , zsock_join_(context_, ZMQ_PULL)
                     , zsock_msg_(context_, ZMQ_PULL)
                     , zsock_control_(context_, ZMQ_PULL)
                     , zsock_result_(context_, ZMQ_PULL)
                     , socket_join_(&zsock_join_, thread_id)
                     , socket_msg_(&zsock_msg_, thread_id)
                     , socket_control_(&zsock_control_, thread_id)
                     , socket_result_(&zsock_result_, thread_id) {
    socket_join_.bind("tcp://*:" + seed_server_join_port_);//std::to_string(NET_SERVER_JOIN_PORT));
    socket_msg_.bind("tcp://*:" + std::to_string(NET_SERVER_MCAST_PORT));
    socket_control_.bind("tcp://*:" + std::to_string(NET_SERVER_CONTROL_PORT));
    socket_result_.bind("tcp://*:" + std::to_string(NET_SERVER_RESULT_PORT));
    LOGI << "[ZmqComm] Finished constructing ZmqServer";

    max_child_routers = MAX_CHILD_ROUTERS;
}

void ZmqServer::net_setup() {
    pollitems_ = std::vector<zmq::pollitem_t>({
        { static_cast<void *>(zsock_join_), 0, ZMQ_POLLIN, 0 },
        { static_cast<void *>(zsock_msg_), 0, ZMQ_POLLIN, 0 },
        { static_cast<void *>(zsock_control_), 0, ZMQ_POLLIN, 0 },
        { static_cast<void *>(zsock_result_), 0, ZMQ_POLLIN, 0 }
    });
    //this->pollitems_ = new_pollitems;
}

void handle_join_request(std::vector<ProtoSocket> &router_sockets_, 
        std::vector<ProtoSocket> &client_sockets_, 
        std::string msg,
        std::string personal_address,
        int node_type,
        long unsigned int max_child_routers,
        bool isServerRoot,
        zmq::context_t &context_,
        int thread_id_
        ) {

    std::string header = isServerRoot ? "SERVER" : "ROUTER";
    if(node_type == 0) {
        // If there are routers underneath this one,
        // pass the buck to them 
        if(router_sockets_.size() > 0) {
            // Pass down to the first router in the list, a bad implementation.
            router_sockets_[0].send_join(msg, 0); 
        }
        // Otherwise, client becomes a direct child of this one 
        else {
            // TODO: Need to clean up the memory leak induced by this allocation 
            LOGI << "[" << header << "] JOIN FROM CLIENT " + msg ;

            zmq::socket_t* socket_ptr  = new  zmq::socket_t(context_, ZMQ_PUSH);
            socket_ptr -> connect (msg);
            client_sockets_.emplace_back(socket_ptr, thread_id_);
            //client_addresses_.push_back(msg);

            client_sockets_[client_sockets_.size() - 1].send_assign_parent(personal_address);
        }
    }
    else if(node_type == 1) {
        // If the current node has the maximum # of routers, then pass down to the next level 
        if(router_sockets_.size() >= max_child_routers) {
            router_sockets_[0].send_join(msg, 1); 
        }
        // If we haven't hit the maximum router count, then append the router to this one 
        else {
            LOGI << "[" << header << "] JOIN FROM ROUTER " + msg ;

            zmq::socket_t* socket_ptr  = new  zmq::socket_t(context_, ZMQ_PUSH);
            socket_ptr -> connect (msg);
            router_sockets_.emplace_back(socket_ptr, thread_id_);
            //router_addresses_.push_back(msg);

            router_sockets_[router_sockets_.size() - 1].send_assign_parent(personal_address);
        }
    }
    else {
            LOGI << "[" << header << "] ERROR, unknown node type attempting to join multicast tree.";
    }
}


void ZmqServer::net_handler() {
    //std::cout << "Start polling" << std::endl;
    // Join Request
    if (pollitems_[0].revents & ZMQ_POLLIN){
        ///Get the address
        int node_type;

        MulticastMessage::ControlMessage recv(socket_join_.recv());

        std::string msg = MulticastMessage::unpack_join(recv, &node_type);

        // TODO: Should change from localhost...
        std::string personal_address = "tcp://localhost:" + std::to_string(NET_SERVER_MCAST_PORT);
        handle_join_request(router_sockets_, client_sockets_, msg, personal_address, node_type, max_child_routers, true, context_, thread_id_);
    }

    //receive new message to mcast
    if (pollitems_[1].revents & ZMQ_POLLIN){
        MulticastMessage::ControlMessage msg(socket_msg_.recv());

        assert(msg.has_body());

        // TODO: Assert that message is of the form "raw bytes"
        msg.mutable_body()->mutable_raw_bytes()->set_route_up(false); // Server must route all messages down. 

        LOGI << "[SERVER] Mcast Message: " + msg.ShortDebugString();

        //mcast to all child routers and clients
        for(auto it = this->router_sockets_.begin(); it != this->router_sockets_.end(); it++) {
            it->send(msg);
        }
        for(auto it = this->client_sockets_.begin(); it != this->client_sockets_.end(); it++) {
            it->send(msg);
        }

    }

    if (pollitems_[2].revents & ZMQ_POLLIN){
        std::string coordinator_addr = MulticastMessage::unpack_raw_str(socket_control_.recv());
        LOGI << "[SERVER] REV CONTRL Message from" << coordinator_addr ;

        zmq::socket_t* socket_ptr  = new  zmq::socket_t(context_, ZMQ_PUSH);
        ProtoSocket socket(socket_ptr, thread_id_);
        socket.connect(coordinator_addr + std::to_string(3010));

        socket.send_raw_str(this->serialize_group_addresses());
        this->coordinator_ = coordinator_addr;
    }

    if (pollitems_[3].revents & ZMQ_POLLIN){
        std::string result = MulticastMessage::unpack_raw_str(socket_result_.recv());
        LOGI << "[SERVER] REV result Message: " + result ;

        zmq::socket_t* socket_ptr  = new  zmq::socket_t(context_, ZMQ_PUSH);
        ProtoSocket socket(socket_ptr, thread_id_);
        socket.connect(this->coordinator_ + std::to_string(3011));

        socket.send_raw_str(result);
    }
}

ZmqRouter::ZmqRouter(std::string ip, unsigned thread_id)
                         : ZmqComm(ip, thread_id) 
                         , zsock_join_(context_, ZMQ_PUSH)
                         , zsock_from_server_(context_, ZMQ_PULL)
                         , socket_join_(&zsock_join_, thread_id)
                         , socket_from_server_(&zsock_from_server_, thread_id) {
    socket_join_.connect ("tcp://" + seed_server_ip_ + ":" + seed_server_join_port_);
    socket_from_server_.bind ("tcp://*:" + port_);
    LOGI << "[ZmqComm] Finished constructing ZmqRouter";


    //parent_socket_ = nullptr;

    max_child_routers = MAX_CHILD_ROUTERS;
}

void ZmqRouter::net_setup() {
    pollitems_ = std::vector<zmq::pollitem_t>({
        { static_cast<void *>(zsock_from_server_), 0, ZMQ_POLLIN, 0 } 
    });

    socket_join_.send_join(addr_, 1);
}

void ZmqRouter::net_handler() {
    //std::cout << "Start polling" << std::endl;
    //poll join and mcast messages

    //receive new message by worker or another router to mcast
    if (pollitems_[0].revents & ZMQ_POLLIN) {
        // Multiplex to handle several types of message

        MulticastMessage::ControlMessage recv = socket_from_server_.recv(); 

        auto body = recv.mutable_body();
        if(body->has_assign_parent()) {

            std::string parent = unpack_assign_parent(recv);

            zsock_parent_.reset(new zmq::socket_t(context_, ZMQ_PUSH));
            parent_socket_.reset(new ProtoSocket(zsock_parent_.get(), thread_id_));
            parent_socket_->connect (parent);
            LOGI << "[Router " << addr_ << "] has new parent:  " << parent;
        } 
        else if(body->has_join()) {
            int node_type;
            std::string msg = MulticastMessage::unpack_join(recv, &node_type);
            std::string personal_address = "tcp://localhost:" + port_;
            handle_join_request(router_sockets_, client_sockets_, msg, personal_address, node_type, max_child_routers, false, context_, thread_id_);
        }
        else if(body->has_raw_bytes()) {
            std::string msg = MulticastMessage::unpack_raw_bytes(recv);
            LOGI << "[Router " << addr_ << "] routing message:  " + msg ;

            //mcast to all child routers and clients
            for(auto it = this->router_sockets_.begin(); it != this->router_sockets_.end(); it++) {
                it->send(recv);
            }
            for(auto it = this->client_sockets_.begin(); it != this->client_sockets_.end(); it++) {
                it->send(recv);
            }

        }
        else {
            LOGI << "[Router " << addr_ << "] error: got unknown message type.";
        }

    }
}

std::string ZmqServer::serialize_group_addresses() {
    std::string ret;
    // TODO: Fix this!!!
    
    //for( const std::string& s : group_addresses_ ) {
    //    ret += GROUP_ADDR_DELIMIT + s;
    //}
    return ret;
}

std::vector<std::string> ZmqServer::deserialize_group_addresses(std::string group_addresses) {
    // TODO: Fix this!
    std::vector<std::string> ret = absl::StrSplit(group_addresses, "@@@", absl::SkipEmpty());
    return ret;
}

ZmqClient::ZmqClient(std::string ip, unsigned thread_id, Asylo_SGX* sgx)
                     : ZmqComm(ip, thread_id)
                     , sgx_(sgx)
                     , zsock_join_(context_, ZMQ_PUSH)
                     , zsock_from_server_(context_, ZMQ_PULL)
                     , zsock_send_(context_, ZMQ_PUSH)
                     , socket_join_(&zsock_join_, thread_id)
                     , socket_from_server_(&zsock_from_server_, thread_id)
                     , socket_send_(&zsock_send_, thread_id) {
    socket_from_server_.bind ("tcp://*:" + port_);
    socket_join_.connect ("tcp://" + seed_server_ip_ + ":" + seed_server_join_port_);
    socket_send_.connect ("tcp://" + seed_server_ip_ + ":" + seed_server_mcast_port_);
    LOGI << "[ZmqComm] Finished constructing ZmqClient";
}

void ZmqClient::net_setup() {
    LOG(INFO) << "tcp://" + seed_server_ip_ + ":" + seed_server_mcast_port_;
    LOG(INFO) << "tcp://" + seed_server_ip_ + ":" + seed_server_join_port_;

    pollitems_ = std::vector<zmq::pollitem_t>({
            { static_cast<void *>(zsock_from_server_), 0, ZMQ_POLLIN, 0 }
    });

    //send join request to seed server
    socket_join_.send_join(addr_, 0);
}

void ZmqClient::net_handler() {
    //start enclave
    // LOG(INFO) << "Start zmq";
    if (pollitems_[0].revents & ZMQ_POLLIN) {
        //Get the address
        std::string msg = MulticastMessage::unpack_raw_str(socket_from_server_.recv());
        LOGI << "[Client " << addr_ << "]:  " + msg ;
        // this -> send_string(port_ , socket_send_);
        this->sgx_->send_to_sgx(msg);
    }
}

ZmqJsClient::ZmqJsClient(std::string ip, unsigned thread_id, Asylo_SGX* sgx)
                         : ZmqComm(ip, thread_id)
                         , sgx_(sgx)
                         , zsock_join_(context_, ZMQ_PUSH)
                         , zsock_from_server_(context_, ZMQ_PULL)
                         , zsock_code_(context_, ZMQ_PULL)
                         , zsock_send_(context_, ZMQ_PULL)
                         , socket_join_(&zsock_join_, thread_id)
                         , socket_from_server_(&zsock_from_server_, thread_id)
                         , socket_code_(&zsock_code_, thread_id)
                         , socket_send_(&zsock_send_, thread_id) {
    socket_join_.connect ("tcp://" + seed_server_ip_ + ":" + seed_server_join_port_);
    socket_from_server_.bind ("tcp://*:" + port_);
    socket_send_.bind ("tcp://*:" + std::to_string(NET_SERVER_MCAST_PORT + thread_id));
    socket_code_.bind ("tcp://*:" + std::to_string(3006 + thread_id));
    LOGI << "[ZmqComm] Finished constructing ZmqJsClient";
}

void ZmqJsClient::net_setup() {
    pollitems_ = std::vector<zmq::pollitem_t>({
        { static_cast<void *>(zsock_from_server_), 0, ZMQ_POLLIN, 0 },
        { static_cast<void *>(zsock_code_), 0, ZMQ_POLLIN, 0 },
        { static_cast<void *>(zsock_send_), 0, ZMQ_POLLIN, 0 }
    });

    //send join request to seed server
    socket_join_.send_join(addr_, 0);
}

void ZmqJsClient::net_handler() {
    if (pollitems_[0].revents & ZMQ_POLLIN) {
        // Multiplex to handle several types of message

        MulticastMessage::ControlMessage recv = socket_from_server_.recv(); 

        auto body = recv.mutable_body();
        if(body->has_assign_parent()) {

            std::string parent = unpack_assign_parent(recv);

            zsock_parent_.reset(new zmq::socket_t(context_, ZMQ_PUSH));
            parent_socket_.reset(new ProtoSocket(zsock_parent_.get(), thread_id_));
            parent_socket_->connect (parent);

            LOGI << "[JSClient " << addr_ << "] has new parent:  " << parent;
        } 
        else if(body->has_raw_bytes()) {
            std::string msg = MulticastMessage::unpack_raw_bytes(recv);
            assert(body->mutable_raw_bytes()->has_route_up());

            if(body->mutable_raw_bytes()->route_up()) {
                LOGI << "[JSClient " << addr_ << "] routing message up tree:  " + msg ;

            }
            else {
                LOGI << "[JSClient " << addr_ << "] sending message to enclave:  " + msg ;

                sgx_->send_to_sgx(msg);
            }
        }

    }

    if (pollitems_[1].revents & ZMQ_POLLIN) {
        //Get the address
        std::string msg = MulticastMessage::unpack_exec_code(socket_code_.recv());
        LOG(INFO) << "[JSClient " << addr_ << "]:  " + msg ;

        // this -> send_string(port_ , socket_send_);
        sgx_->execute_js_code(msg);
    }

    if (pollitems_[2].revents & ZMQ_POLLIN) {
        //Get the address
        MulticastMessage::ControlMessage recv = socket_send_.recv(); 
        std::string msg = MulticastMessage::unpack_raw_bytes(recv);

        LOG(INFO) << "[JSClient " << addr_ << "]: mcast message:" + msg ;
        // TODO multicast to rest of tree here
    }
}