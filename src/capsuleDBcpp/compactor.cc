/*
 * This file manages compaction and the moving of data between levels for CapsuleDB.
 */

/*
 * This function manages the compaction process.  It assumes that compaction is needed and does not check the size of the level.
 * It wil recursively handle further compactions if necessary.
 * 
 * Input: Level to compact.
 * Output: Error code or 0 on success.
 */
int compact(int level) {
    return 0;
}

/* 
 * This function takes a run of keys and sorts them.  If two values are present for the same key, the newer one is used.  
 * 
 * Input: Two arrays of keys and their values.
 * Output: A single sorted array of keys and values.
 */
void sort(int arr1[], int arr2[]){
    return;
}