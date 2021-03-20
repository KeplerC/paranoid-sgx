#include <cstdio>
#include "gdp.h"

struct Node
{
    data_capsule_t dc; 
    Node* next;
    Node* prev;
    Node(data_capsule_t *);
};
 
Node::Node(data_capsule_t *dc_arg)       //Parameterized Constructor
{
    memcpy(&dc, dc_arg, sizeof(data_capsule_t));
    next = prev = NULL;
}
 
class DoublyLinkedList
{
public:
    DoublyLinkedList();
    ~DoublyLinkedList();
    void insert_front(data_capsule_t *);
    void insert_back(data_capsule_t *);
    data_capsule_t *  delete_front();
    data_capsule_t *  delete_back();
    bool is_empty();
    void display();
    int length();
    data_capsule_t * search(int);
 
private:
    Node* head;
    Node* tail;
    int size;
 
};
 
DoublyLinkedList::DoublyLinkedList()
{
    head = tail = NULL;
    size = 0;
}
 
DoublyLinkedList::~DoublyLinkedList()
{
}
 
void DoublyLinkedList::insert_front(data_capsule_t *value)
{
    Node* temp = new Node(value);
 
    if (head == NULL)
        head = tail = temp;
    else
    {
        head->prev = temp;
        temp->next = head;
        head = temp;
    }
    size++;
}
 
void DoublyLinkedList::insert_back(data_capsule_t *value)
{
    Node* temp = new Node(value);
 
    if (tail == NULL)
        head = tail = temp;
    else
    {
        tail->next = temp;
        temp->prev = tail;
        tail = temp;
    }
    size++;
}
 
data_capsule_t * DoublyLinkedList::delete_front()
{
    if (!is_empty())
    {
        Node* temp = head;
        if (head == tail)
        {
            tail = NULL;
        }
        data_capsule_t * delValue = &temp->dc;
        head = head->next;
 
        // delete temp;
 
        size--;
 
        return delValue;
 
    }
    return 0;
}
 
data_capsule_t * DoublyLinkedList::delete_back()
{
    if (!is_empty())
    {
        Node* temp = tail;
        if (head == tail)
        {
            head = NULL;
        }
        data_capsule_t * delValue = &temp->dc;
        tail->next = NULL;
        tail = tail->prev;
 
        // delete temp;
 
        size--;
 
        return delValue;
 
    }
    return 0;
}
 
bool DoublyLinkedList::is_empty()
{
    if (size <= 0)
    {
        return true;
    }
 
    return false;
}
 
void DoublyLinkedList::display()
{
    Node* temp = head;
 
    while (temp != NULL)
    {
        temp = temp->next;
    }
}
 
int DoublyLinkedList::length()
{
    return size;
}
 
data_capsule_t * DoublyLinkedList::search(int value)
{
    if (!is_empty())
    {
        Node* temp = head;
        while (temp)
        {
            if (temp->dc.id == value)
            {
                /* 
                1) If prev && next are NULL, then nothing happens
                2) If prev exists, set prev->next to next node
                3) If next exists, set next->prev 
                */
                // if(temp->prev){
                //     temp->prev->next = temp->next; 
                // }

                // if(temp->next){
                //     temp->next->prev = temp->prev; 
                // }

                return &temp->dc; 
                break;
            }
            temp = temp->next;
        }
    }
    else
    {
        return NULL;
    }

    return NULL; 
}