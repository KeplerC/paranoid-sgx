#include "proto_comm.hpp"

#include <cassert>

#include <chrono>

void ProtoSocket::connect(std::string endpoint) {
    socket_->connect(endpoint);
}

void ProtoSocket::bind(std::string endpoint) {
    socket_->bind(endpoint);
}

// TODO reference semantics, or do we just rely on move optimization here?
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

void ProtoSocket::send_join(std::string addr) {
    MulticastMessage::ControlMessage message;
    MulticastMessage::MessageBody* body = message.mutable_body();
    MulticastMessage::JoinMsg* join = body->mutable_join();

    join->set_addr(addr);

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

MulticastMessage::ControlMessage ProtoSocket::recv_proto() {
    zmq::message_t message;
    socket_->recv(&message);
    std::string str (static_cast<const char*>(message.data()), message.size());

    MulticastMessage::ControlMessage msg;
    msg.ParseFromString(str);

    assert(msg.has_body());
    assert(msg.has_timestamp());
    assert(msg.has_sender_id());

    LOGI<<"Received proto: "<<msg.ShortDebugString()<<std::endl;

    return msg;
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

    LOGI<<"Sent proto: "<<proto.ShortDebugString()<<std::endl;
}

std::string MulticastMessage::unpack_join(ProtoSocket& sock) {
    ControlMessage msg(sock.recv());
    return *unpack_join(msg);
}

std::string MulticastMessage::unpack_exec_code(ProtoSocket& sock) {
    ControlMessage msg = sock.recv();
    return *unpack_exec_code(msg);
}

std::string* MulticastMessage::unpack_join(MulticastMessage::ControlMessage& msg) {
    auto body = msg.mutable_body();
    assert(body->has_join());

    return body->mutable_join()->mutable_addr();
}

std::string* MulticastMessage::unpack_exec_code(MulticastMessage::ControlMessage& msg) {
    auto body = msg.mutable_body();
    assert(body->has_code());

    return body->mutable_code()->mutable_str();
}
