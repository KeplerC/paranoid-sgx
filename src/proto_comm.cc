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
void ProtoSocket::send(const MulticastMessage::ControlMessage* msg) {
    std::string str;
    msg->SerializeToString(&str);
    send_string(str);
}

MulticastMessage::ControlMessage* ProtoSocket::recv() {
    return recv_proto();
}

void ProtoSocket::recv(MulticastMessage::ControlMessage* msg) {
    *msg = *recv_proto(); // TODO this still copies internally
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

std::string ProtoSocket::recv_string() {
    zmq::message_t message;
    socket_->recv(&message);
    return std::string(static_cast<const char*>(message.data()),
                       message.size());
}

MulticastMessage::ControlMessage* ProtoSocket::recv_proto() {
    std::string str = recv_string();

    // TODO use unique pointers
    MulticastMessage::ControlMessage* msg = new MulticastMessage::ControlMessage();
    msg->ParseFromString(str);

    assert(msg->has_body());
    assert(msg->has_timestamp());
    assert(msg->has_sender_id());

    return msg;
}

void ProtoSocket::send_string(const std::string& s) {
    zmq::message_t msg(s.size());
    memcpy(msg.data(), s.c_str(), s.size());
    socket_->send(msg);
}

void ProtoSocket::send_proto(MulticastMessage::ControlMessage& msg) {
    // TODO shouldn't this be a lamport clock or something
    using namespace std::chrono;
    int64_t timestamp = duration_cast<milliseconds>(
                            system_clock::now().time_since_epoch()).count();

    // Set message header
    msg.set_timestamp(timestamp);
    msg.set_sender_id(id_);

    send(&msg);
}

std::string MulticastMessage::unpack_join(ProtoSocket& sock) {
    ControlMessage* msg = sock.recv();
    std::string str(*unpack_join(msg));
    // TODO free the msg pointer
    return str;
}

std::string MulticastMessage::unpack_exec_code(ProtoSocket& sock) {
    ControlMessage* msg = sock.recv();
    std::string addr(*unpack_exec_code(msg));
    // TODO free the msg pointer
    return addr;
}

std::string* MulticastMessage::unpack_join(MulticastMessage::ControlMessage* msg) {
    auto body = msg->mutable_body();
    assert(body->has_join());

    return body->mutable_join()->mutable_addr();
}

std::string* MulticastMessage::unpack_exec_code(MulticastMessage::ControlMessage* msg) {
    auto body = msg->mutable_body();
    assert(body->has_code());

    return body->mutable_code()->mutable_str();
}
