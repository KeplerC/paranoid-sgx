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
    var currStock = parseInt(psl_get(item).val, 10);
    if (currStock - numberOfItems > 0) {
        var newStock = currStock - numberOfItems;
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
var numBought = 0;
for (var i = 0; i < 500; i++) {
    var numToBuy = getRandomInt(5);
    var numReceived = buyItem("Item 1", numToBuy);
    numBought += numReceived;
}

print("Number items bought: ");
print(numBought);
print("Current stock: ");
print(psl_get("Item 1").val);
print("Total original stock: ");
print(TOTAL_STOCK);