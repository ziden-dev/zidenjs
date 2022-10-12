pragma circom 2.0.0;
include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../node_modules/circomlib/circuits/mux3.circom";
include "../../../node_modules/circomlib/circuits/mux1.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";

/*
    Hash1 = H(1 | key | value)
 */

template QuinSMTHash1() {
    signal input key;
    signal input value;
    signal output out;

    component h = Poseidon(3);   // Constant
    h.inputs[0] <== key;
    h.inputs[1] <== value;
    h.inputs[2] <== 1;

    out <== h.out;
}

/*
    This component is used to create the 5 nodes.

    Hash5 = H(H0 | H1 | H2 | H3 | H4)
 */

template QuinSMTHash5() {
    signal input siblings[4];
    signal input child;
    signal input indexBits[3];
    signal output out;

    component splicer = Splicer();
    for(var i = 0; i< 4; i++){
        splicer.in[i] <== siblings[i];
    }
    for(var i = 0; i< 3; i++){
        splicer.indexBits[i] <== indexBits[i];
    }
    splicer.leaf <== child;
    
    component hasher = Poseidon(5);   // Constant
    for (var i = 0; i < 5; i++){
        hasher.inputs[i] <== splicer.out[i];
    }

    out <== hasher.out;
}
/*
 * Given a list of 5 items and an index, output the item at the position denoted
 * by the index. 
 * Assert that index < 5
 */
template QuinSelector() {
    signal input in[5];
    signal input index;
    signal output out;

    component mux = Mux3();
    for(var i = 0; i< 5; i++){
        mux.c[i] <== in[i];
    }
    mux.c[5] <== 0;
    mux.c[6] <== 0;
    mux.c[7] <== 0;

    // assert index < 5
    component lt = LessThan(3);
    lt.in[0] <== index;
    lt.in[1] <== 5;
    lt.out === 1;
    
    component indexBits = Num2Bits(3);
    indexBits.in <== index;

    for(var i = 0; i< 3; i++){
        mux.s[i] <== indexBits.out[i];
    }

    out <== mux.out;
}

/*
 * The output array contains the input items, with the the leaf inserted at the
 * specified index. For example, if input = [0, 20, 30, 40], index = 3, and
 * leaf = 10, the output will be [0, 20, 30, 10, 40].
 */
template Splicer(){
    var numItems = 4;
        // Since we only insert one item, the number of output items is 1 +
    // numItems
    var NUM_OUTPUT_ITEMS = numItems + 1;

    signal input in[numItems];
    signal input leaf;
    signal input indexBits[3];
    signal output out[NUM_OUTPUT_ITEMS];

    component greaterThan[NUM_OUTPUT_ITEMS];
    component isLeafIndex[NUM_OUTPUT_ITEMS];
    component quinSelectors[NUM_OUTPUT_ITEMS];
    component muxes[NUM_OUTPUT_ITEMS];

    var i;
    var j;


    component bits2Num = Bits2Num(3);
    for(var i = 0; i < 3; i++){
        bits2Num.in[i] <== indexBits[i];
    }

    signal index <== bits2Num.out;

    /*
        There is a loop where the goal is to assign values to the output
        signal.

        | output[0] | output[1] | output[2] | ...

        We can either assign the leaf, or an item from the `items` signal, to
        the output. We use this using Mux1(). Mux1's selector is 0 or 1
        depending on whether the index is equal to the loop counter.

        i --> [IsEqual] <-- index
                    |
                    v
        leaf ---> [Mux1] <--- <item from in>
                    |
                    v
                output[m]

        To obtain the value from <item from in>, we need to compute an item
        index (let it be `s`).

        1. if index = 2 and i = 0, then s = 0
        2. if index = 2 and i = 1, then s = 1
        3. if index = 2 and i = 2, then s = 2
        4. if index = 2 and i = 3, then s = 2
        5. if index = 2 and i = 4, then s = 3

        We then wire `s`, as well as each item in `in` to a QuinSelector.
        The output signal from the QuinSelector is <item from in> and gets
        wired to Mux1 (as above).
    */
    for (i = 0; i < numItems + 1; i ++) {
        // greaterThen[i].out will be 1 if the i is greater than the index
        greaterThan[i] = GreaterThan(3);
        greaterThan[i].in[0] <== i;
        greaterThan[i].in[1] <== index;

        quinSelectors[i] = QuinSelector();

        // Select the value from `in` at index i - greaterThan[i].out.
        // e.g. if index = 2 and i = 1, greaterThan[i].out = 0, so 1 - 0 = 0
        // but if index = 2 and i = 3, greaterThan[i].out = 1, so 3 - 1 = 2
        quinSelectors[i].index <== i - greaterThan[i].out;

        for (j = 0; j < numItems; j ++) {
            quinSelectors[i].in[j] <== in[j];
        }
        quinSelectors[i].in[numItems] <== 0;

        isLeafIndex[i] = IsEqual();
        isLeafIndex[i].in[0] <== index;
        isLeafIndex[i].in[1] <== i;

        muxes[i] = Mux1();
        muxes[i].s <== isLeafIndex[i].out;
        muxes[i].c[0] <== quinSelectors[i].out;
        muxes[i].c[1] <== leaf;

        out[i] <== muxes[i].out;
    }
}