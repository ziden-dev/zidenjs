/*
    Copyright 2018 0KIMS association.

    This file is part of circom (Zero Knowledge Circuit Compiler).

    circom is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    circom is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with circom. If not, see <https://www.gnu.org/licenses/>.
*/

/******

SMTProcessorLevel

This circuit has 2 hash

Outputs according to the state.

State        oldRoot                    newRoot
=====        =======                    =======
top          H'(oldChild, sibling)       H'(newChild, sibling)
old0         0                           new1leaf
bot          old1leaf                    H'(newChild, 0)
new1         old1leaf                    H'(new1leaf, old1leaf)
na           0                           0

upd          old1leaf                    new1leaf

H' is the Hash function with the inputs shifted acordingly.

*****/
pragma circom 2.0.0;
include "quinHashers.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";

template SMTProcessorLevel() {
    signal input st_top;
    signal input st_old0;
    signal input st_bot;
    signal input st_new1;
    signal input st_na;
    signal input st_upd;

    signal output oldRoot;
    signal output newRoot;
    signal input siblings[4];
    signal input index;
    signal input oldIndex;
    signal input old1leaf;
    signal input new1leaf;
    signal input oldChild;
    signal input newChild;

    signal aux[11];

    // Old side

    component oldProofHash = QuinSMTHash5();

    for(var i = 0; i< 4; i++){
        oldProofHash.siblings[i] <== siblings[i];
    }
    oldProofHash.index <== index;
    oldProofHash.child <== oldChild;

    aux[0] <== old1leaf * (st_bot + st_new1 + st_upd);
    oldRoot <== aux[0] +  oldProofHash.out * st_top;

    // New side

    component newProofHashTopBot = QuinSMTHash5();
    component newProofHashNew1 = QuinSMTHash5With2Children();

    newProofHashTopBot.child <== newChild;
    newProofHashTopBot.index <== index;
    for(var i = 0; i < 4; i++){
        newProofHashTopBot.siblings[i] <== siblings[i] * st_top;
    }
    aux[1] <== newProofHashTopBot.out * (st_bot + st_top);
    
    newProofHashNew1.child0 <== newChild;
    newProofHashNew1.child1 <== old1leaf;
    newProofHashNew1.index0 <== index;
    newProofHashNew1.index1 <== oldIndex;
    for(var i = 0; i < 3; i++){
        newProofHashNew1.siblings[i] <== 0;
    }

    aux[2] <== newProofHashNew1.out * st_new1;

    newRoot <==  aux[1] + aux[2] + new1leaf * (st_old0 + st_upd);
}
