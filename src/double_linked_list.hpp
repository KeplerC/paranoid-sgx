#ifndef _DLL_H
#define _DLL_H

#include "absl/strings/str_cat.h"
#include <cstdio>
#include "gdp.h"

struct Node
{
    data_capsule_t dc; 
    Node* next;
    Node* prev;
    Node(data_capsule_t *);
};
 
class DoublyLinkedList
{
public:
    DoublyLinkedList();
    ~DoublyLinkedList();
    void insert_front(data_capsule_t *);
    void insert_back(data_capsule_t *);
    data_capsule_t *  delete_front();
    void  delete_back();
    bool is_empty();
    void display();
    int length();
    data_capsule_t * search(int);
 
private:
    Node* head;
    Node* tail;
    int size;
 
};
#endif