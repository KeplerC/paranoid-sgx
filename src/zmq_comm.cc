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

void ZmqServer::net_handler() {
    //std::cout << "Start polling" << std::endl;
    // Join Request
    if (pollitems_[0].revents & ZMQ_POLLIN){
        ///Get the address
        std::string msg = MulticastMessage::unpack_join(socket_join_.recv());
        LOGI << "[SERVER] JOIN FROM " + msg ;

        ////create a socket to the client and save
        zmq::socket_t* socket_ptr  = new  zmq::socket_t(context_, ZMQ_PUSH);

        socket_ptr -> connect (msg);
        this->group_sockets_.push_back(socket_ptr);
        //this->send_string("Ack Join", socket_ptr);
    }

    //receive new message to mcast
    if (pollitems_[1].revents & ZMQ_POLLIN){
        MulticastMessage::ControlMessage msg(socket_msg_.recv());
        LOGI << "[SERVER] Mcast Message: " + msg.ShortDebugString();
        //mcast to all the clients
        for (zmq::socket_t* socket : this->group_sockets_) {
            // TODO convert group_sockets_ to a vector of ProtoSockets
            ProtoSocket proto_socket(socket, thread_id_);
            proto_socket.send(msg);
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
                     , zsock_join_(context_, ZMQ_PULL)
                     , zsock_msg_(context_, ZMQ_PULL)
                     , zsock_control_(context_, ZMQ_PULL)
                     , zsock_result_(context_, ZMQ_PULL)
                     , socket_join_(&zsock_join_, thread_id)
                     , socket_msg_(&zsock_msg_, thread_id)
                     , socket_control_(&zsock_control_, thread_id)
                     , socket_result_(&zsock_result_, thread_id) {
                         
    socket_join_.bind("tcp://*:" + seed_server_join_port_);//std::to_string(NET_SERVER_JOIN_PORT));
    socket_msg_.bind ("tcp://*:" + std::to_string(NET_SERVER_MCAST_PORT));
    socket_control_.bind ("tcp://*:" + std::to_string(NET_SERVER_CONTROL_PORT));
    socket_result_.bind ("tcp://*:" + std::to_string(NET_SERVER_RESULT_PORT));
    LOGI << "[ZmqComm] Finished constructing ZmqRouter";
}

void ZmqRouter::net_setup() {
    pollitems_ = std::vector<zmq::pollitem_t>({
        { static_cast<void *>(zsock_join_), 0, ZMQ_POLLIN, 0 },
        { static_cast<void *>(zsock_msg_), 0, ZMQ_POLLIN, 0 },
        { static_cast<void *>(zsock_control_), 0, ZMQ_POLLIN, 0 },
        { static_cast<void *>(zsock_result_), 0, ZMQ_POLLIN, 0 }
    });
}

void ZmqRouter::net_handler() {
    //std::cout << "Start polling" << std::endl;
    //poll join and mcast messages

    // Join Request
    // Curr: have router/worker node ask to join the parent
    if (pollitems_[0].revents & ZMQ_POLLIN){
        //std::string msg = this->recv_string(&zsock_join_);
        std::string msg = MulticastMessage::unpack_join(socket_join_.recv());
        LOGI << "[SERVER] JOIN FROM " + msg ;

        zmq::socket_t* socket_ptr  = new  zmq::socket_t(context_, ZMQ_PUSH);
        socket_ptr -> connect (msg);
        this->child_sockets_.push_back(socket_ptr);
        //this->send_string("Ack Join", socket_ptr);
    }

    //receive new message by worker or another router to mcast
    if (pollitems_[1].revents & ZMQ_POLLIN){
        MulticastMessage::ControlMessage msg(socket_msg_.recv());
        LOGI << "[SERVER] Mcast Message: " + msg.ShortDebugString();
        //mcast to all the clients
        for (zmq::socket_t* socket : this->child_sockets_) {
            // TODO convert group_sockets_ to a vector of ProtoSockets
            ProtoSocket proto_socket(socket, thread_id_);
            proto_socket.send(msg);
        }
    }

    // Handle messages from coordinator node
    if (pollitems_[2].revents & ZMQ_POLLIN){
        std::string response;

        // TODO: Tokenize message to include sender addr, operation, metadata
        std::string msg = this->recv_string(&zsock_control_);
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
        std::string result = this->recv_string(&zsock_result_);
        LOGI << "[SERVER] REV result Message: " + result ;
        zmq::socket_t* socket_ptr  = new  zmq::socket_t(context_, ZMQ_PUSH);
        socket_ptr -> connect (this->coordinator_+ std::to_string(3011));
        this->send_string(result, socket_ptr);
    }
}

std::string ZmqServer::serialize_group_addresses() {
    std::string ret;
    for( const std::string& s : group_addresses_ ) {
        ret += GROUP_ADDR_DELIMIT + s;
    }
    return ret;
}

std::vector<std::string> ZmqServer::deserialize_group_addresses(std::string group_addresses) {
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
    socket_join_.send_join(addr_);
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
                         , zsock_send_(context_, ZMQ_PUSH)
                         , socket_join_(&zsock_join_, thread_id)
                         , socket_from_server_(&zsock_from_server_, thread_id)
                         , socket_code_(&zsock_code_, thread_id)
                         , socket_send_(&zsock_send_, thread_id) {
    socket_join_.connect ("tcp://" + seed_server_ip_ + ":" + seed_server_join_port_);
    socket_from_server_.bind ("tcp://*:" + port_);
    socket_send_.connect ("tcp://" + seed_server_ip_ + ":" + seed_server_mcast_port_);
    socket_code_.bind ("tcp://*:3006");
    LOGI << "[ZmqComm] Finished constructing ZmqJsClient";
}

void ZmqJsClient::net_setup() {
    LOGI << "tcp://" + seed_server_ip_ + ":" + seed_server_mcast_port_;
    LOGI << "tcp://" + seed_server_ip_ + ":" + seed_server_join_port_;

    pollitems_ = std::vector<zmq::pollitem_t>({
        { static_cast<void *>(zsock_from_server_), 0, ZMQ_POLLIN, 0 },
        { static_cast<void *>(zsock_code_), 0, ZMQ_POLLIN, 0 }
    });

    //send join request to seed server
    socket_join_.send_join(addr_);
}

void ZmqJsClient::net_handler() {
    if (pollitems_[0].revents & ZMQ_POLLIN) {
        //Get the address
        std::string msg = MulticastMessage::unpack_raw_bytes(socket_from_server_.recv());
        LOGI << "[Client " << addr_ << "]:  " + msg ;

        // this -> send_string(port_ , zsock_send_);
        sgx_->send_to_sgx(msg);
    }

    if (pollitems_[1].revents & ZMQ_POLLIN) {
        //Get the address
        std::string msg = MulticastMessage::unpack_exec_code(socket_code_.recv());
        LOG(INFO) << "[Client " << addr_ << "]:  " + msg ;

        // this -> send_string(port_ , socket_send_);
        sgx_->execute_js_code(msg);
    }
}
