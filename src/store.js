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
        // print("Failed to buy item, out of stock!");
        return 0;
    }
}

// Main method
// Setup store
var TOTAL_STOCK = "1000";
psl_put("1", TOTAL_STOCK);
psl_put("2", TOTAL_STOCK);
psl_put("3", TOTAL_STOCK);
psl_put("4", TOTAL_STOCK);
psl_put("5", TOTAL_STOCK);
psl_put("6", TOTAL_STOCK);
psl_put("7", TOTAL_STOCK);
psl_put("8", TOTAL_STOCK);
psl_put("9", TOTAL_STOCK);
psl_put("10", TOTAL_STOCK);

// Purchase items
print("Starting Test");
var numBought = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
for (var i = 0; i < 1000; i++) {
    var numToBuy = getRandomInt(20);
    var itemToBuy = getRandomInt(10);
    var numReceived = buyItem(itemToBuy.toString(), numToBuy);
    numBought[itemToBuy] += numReceived;
}

print("Number items bought: ");
print(numBought);
// print("Current stock: ");
// print(psl_get("Item 1").val);
// print("Total original stock: ");
// print(TOTAL_STOCK);