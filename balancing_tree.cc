#typdef uid long int;

class TreeNode {
public:
    vector<TreeNode*> children;
    TreeNode* parent;
    uid id;
    int max_children;
    int total_successors;
    zmq::socket_t* socket_ptr; 

    TreeNode(uid id, TreeNode* parent, int max_children) {
        this->id = id;
        this->parent = parent;
        this->max_children = max_children;
        total_successors = 0;
    }

    // Adds a successor to this node and returns it. This is a super naive
    // implementation that works recursively. As long as there are no deletes, 
    // it should keep the tree balanced.
    TreeNode* add_successor(uid id) {
        if(children.size() < max_children) {
            TreeNode* node = new TreeNode(id, this, max_children);
            children.push_back(node);
            node->parent = this;
        }
        else {
            // Tack on the node to a new node with the fewest successors
            TreeNode* minNode;

            for(auto it = children.begin(); it != children.end(); it++) {
                if(minNode == nullptr || it->total_successors < minNode->total_successors) {
                    minNode = *it;
                }
            }

            minNode->add_successor(id);
        }
        total_successors++;
    } 
};

/*
 * This structure is intended to be used only by the coordinator root. 
 */
class CoordinatorKaryTree{
    TreeNode* root;  
    uid latest_uid;

    CoordinateKaryTree() {
        root = new TreeNode(0);
        latest_uid = 1;
    }

    void add_node() {
        root->add_successor(id);
    }

    void rebalance() {

    } 
};

