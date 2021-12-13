#include "proto_comm.hpp"

#include <cassert>

#include <chrono>

ProtoSocket::ProtoSocket(zmq::socket_t* socket, uint64_t id)
    : socket_(socket), id_(id), log_to_file_(true)
    {
    using std::ios;
    if (log_to_file_) {
        log_file_.open("proto_log.out", // TODO parameterize this somehow
                       ios::binary | ios::out | ios::app);
    }
}

void ProtoSocket::connect(std::string endpoint) {
    endpoint_ = endpoint;
    socket_->connect(endpoint_);
}

void ProtoSocket::bind(std::string endpoint) {
    endpoint_ = endpoint;
    socket_->bind(endpoint_);
}

void ProtoSocket::send(MulticastMessage::ControlMessage& msg) {
    send_proto(msg);
}

MulticastMessage::ControlMessage ProtoSocket::recv() {
    return recv_proto();
}

void ProtoSocket::recv(MulticastMessage::ControlMessage* msg) {
    *msg = recv_proto();
}

void ProtoSocket::send_error(uint64_t error_code) {
    MulticastMessage::ControlMessage message;
    MulticastMessage::MessageBody* body = message.mutable_body();
    MulticastMessage::ErrorMsg* error = body->mutable_error();

    error->set_errorcode(error_code);

    send_proto(message);
}

void ProtoSocket::send_join(std::string addr, int node_type) {
    MulticastMessage::ControlMessage message;
    MulticastMessage::MessageBody* body = message.mutable_body();
    MulticastMessage::JoinMsg* join = body->mutable_join();

    join->set_addr(addr);
    join->set_node_type(node_type);

    send_proto(message);
}

void ProtoSocket::send_assign_id(uint64_t new_id) {
    MulticastMessage::ControlMessage message;
    MulticastMessage::MessageBody* body = message.mutable_body();
    MulticastMessage::AssignIdMsg* assignid = body->mutable_assignid();

    assignid->set_newid(new_id);

    send_proto(message);
}

void ProtoSocket::send_exec_code(std::string code) {
    MulticastMessage::ControlMessage message;
    MulticastMessage::MessageBody* body = message.mutable_body();
    MulticastMessage::ExecCodeMsg* givecode = body->mutable_code();

    givecode->set_str(code);

    send_proto(message);
}

void ProtoSocket::send_raw_str(std::string code) {
    MulticastMessage::ControlMessage message;
    MulticastMessage::MessageBody* body = message.mutable_body();
    MulticastMessage::RawStrMsg* raw_str = body->mutable_raw_str();

    raw_str->set_str(code);

    send_proto(message);
}


void ProtoSocket::send_raw_bytes(std::string bytes) {
    MulticastMessage::ControlMessage message;
    MulticastMessage::MessageBody* body = message.mutable_body();
    MulticastMessage::RawBytesMsg* raw_bytes = body->mutable_raw_bytes();

    raw_bytes->set_bytestr(bytes);

    send_proto(message);
}

void ProtoSocket::send_raw_bytes(std::string bytes, bool route_up) {
    MulticastMessage::ControlMessage message;
    MulticastMessage::MessageBody* body = message.mutable_body();
    MulticastMessage::RawBytesMsg* raw_bytes = body->mutable_raw_bytes();

    raw_bytes->set_bytestr(bytes);
    raw_bytes->set_route_up(route_up);

    send_proto(message);
}

MulticastMessage::ControlMessage ProtoSocket::recv_proto() {
    zmq::message_t msg;
    socket_->recv(&msg);
    std::string str (static_cast<const char*>(msg.data()), msg.size());

    MulticastMessage::ControlMessage proto;
    proto.ParseFromString(str);

    assert(proto.has_body());
    assert(proto.has_timestamp());
    assert(proto.has_sender_id());

    //LOGI<<"[Proto] Receiving via "<<endpoint_<<": ["
    //    <<proto.ShortDebugString()<<"]"<<std::endl;

    return proto;
}

void ProtoSocket::send_proto(MulticastMessage::ControlMessage& proto) {
    // TODO shouldn't this be a lamport clock or something
    using namespace std::chrono;
    int64_t timestamp = duration_cast<milliseconds>(
                            system_clock::now().time_since_epoch()).count();

    // Set message header
    proto.set_timestamp(timestamp);
    proto.set_sender_id(id_);

    // Serialize into wire format
    std::string str;
    proto.SerializeToString(&str);

    // Create and send packet via ZMQ
    zmq::message_t msg(str.size());
    memcpy(msg.data(), str.c_str(), str.size());
    socket_->send(msg);

    //LOGI<<"[Proto] Sending to "<<endpoint_<<": ["
    //    <<proto.ShortDebugString()<<"]"<<std::endl;
    if (log_to_file_) {
        log_file_ << str;
        log_file_.flush();
    }
}

std::string MulticastMessage::unpack_join(MulticastMessage::ControlMessage& msg, int* type) {
    auto body = msg.mutable_body();
    assert(body->has_join());

    *type = (body->mutable_join()->node_type());
    return *(body->mutable_join()->mutable_addr());
}

std::string MulticastMessage::unpack_exec_code(MulticastMessage::ControlMessage&& msg) {
    auto body = msg.mutable_body();
    assert(body->has_code());

    return *(body->mutable_code()->mutable_str());
}

std::string MulticastMessage::unpack_raw_str(MulticastMessage::ControlMessage&& msg) {
    auto body = msg.mutable_body();
    assert(body->has_raw_str());

    return *(body->mutable_raw_str()->mutable_str());
}

std::string MulticastMessage::unpack_raw_bytes(MulticastMessage::ControlMessage &msg) {
    auto body = msg.mutable_body();
    assert(body->has_raw_bytes());

    return *(body->mutable_raw_bytes()->mutable_bytestr());
}


void ProtoSocket::send_assign_parent(std::string parent_addr) {
    MulticastMessage::ControlMessage message;
    MulticastMessage::MessageBody* body = message.mutable_body();
    MulticastMessage::AssignParentMsg* raw_str = body->mutable_assign_parent();
    raw_str->set_parent(parent_addr);

    send_proto(message);
}


std::string MulticastMessage::unpack_assign_parent(MulticastMessage::ControlMessage &msg) {
    auto body = msg.mutable_body();
    assert(body->has_assign_parent());
    return *(body->mutable_assign_parent()->mutable_parent());
}


zmq::socket_t* ProtoSocket::get_zmq_socket() {
    return socket_;
}