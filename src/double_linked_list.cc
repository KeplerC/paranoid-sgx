#include "double_linked_list.hpp"

Node::Node(data_capsule_t *dc_arg)       //Parameterized Constructor
{
    memcpy(&dc, dc_arg, sizeof(data_capsule_t));
    next = prev = NULL;
}
 
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
 
void DoublyLinkedList::delete_back()
{
    if (!is_empty())
    {
        Node* temp = tail;
        if (head == tail)
        {
            head = tail = NULL;
        } else{
            tail->prev->next = NULL;
            tail = tail->prev;
        }

        delete temp; 
        size--;
 
        return;
 
    }
    return;
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
