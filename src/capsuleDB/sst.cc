/* 
 * This file defines an SST which is stored in a DataCapsule.  
 */

class CapsuleBlock {
    public:
        int metadata;
        int keyIndex;
        int datablock;

        /*
         * This function takes a prepared SST and pushes it to the DataCapusle.
         * Input: None
         * Output: DataCapsule transaction hash.
         */
        string writeOut() {
            return "Test";
        }

        /*
         * This function reads in a CapsuleBlock SST file from the DataCapusle.  This is useful for reads.
         * 
         * Input: Transaction hash of the requested block.
         * Output: Error code or zero on success.
         */
        void readIn(string transactionHash) {
            return 0;
        }
};