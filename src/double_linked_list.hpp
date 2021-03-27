#ifndef _DLL_H
#define _DLL_H

#include "absl/strings/str_cat.h"
#include <cstdio>
#include "capsule.h"

struct Node
{
    capsule_pdu dc; 
    Node* next;
    Node* prev;
    Node(capsule_pdu *);
};
 
class DoublyLinkedList
{
public:
    DoublyLinkedList();
    ~DoublyLinkedList();
    void insert_front(capsule_pdu *);
    void insert_back(capsule_pdu *);
    capsule_pdu *  delete_front();
    void  delete_back();
    bool is_empty();
    void display();
    int length();
    capsule_pdu * search(int);
 
private:
    Node* head;
    Node* tail;
    int size;
 
};
#endif