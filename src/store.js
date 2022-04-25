// This file provides an example application for the release consistent locking mechanism.  
// Imagine an online store that sells something with a limitied stock, say Cori-chella tickets, 
// graphics cards, or shoes.  While PSL's eventual consistency model would avoid correctness issues,
// order matters.  While I would be allowed to do a put to a value, if someone else did it first their
// request should take precedent, not mine irregardless of the order of information received.  
// This example is used for correctness to demonstrate how the release consistent locking mechanism works.

function getRandomInt(max) {
    return Math.floor(Math.random() * max) + 1;
}

function buyItem(item, numberOfItems) {
    let currStock = parseInt(psl_get(item), 10);
    if (currStock - numberOfItems > 0) {
        let newStock = currStock - numberOfItems;
        psl_put(item, newStock.toString());
        return numberOfItems;
    } else {
        print("Failed to buy item, out of stock!");
        return 0;
    }
}

// Main method
// Setup store
var TOTAL_STOCK = "1000";
psl_put("Item 1", TOTAL_STOCK);

// Purchase items
print("Starting Test");
let numBought = 0;
for (let i = 0; i < 500; i++) {
    let numToBuy = getRandomInt(5);
    let numReceived = buyItem("Item 1", numToBuy);
    numBought += numReceived;
}

print("Number items bought: ");
print(numBought);
print("Current stock: ");
print(psl_get("Item 1"));
print("Total original stock: ");
print(TOTAL_STOCK);