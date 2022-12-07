import * as Scalar from "./scalar.js";
import {default as buildBn128} from "./bn128.js";

const bn128r = Scalar.e("21888242871839275222246405745257275088548364400416034343698204186575808495617");
const bn128q = Scalar.e("21888242871839275222246405745257275088696311157297823662689037894645226208583");

export async function getCurveFromR(r, singleThread, plugins) {
    let curve;
    if (Scalar.eq(r, bn128r)) {
        curve = await buildBn128(singleThread, plugins);
    } else {
        throw new Error(`Curve not supported: ${Scalar.toString(r)}`);
    }
    return curve;
}

export async function getCurveFromQ(q, singleThread, plugins) {
    let curve;
    if (Scalar.eq(q, bn128q)) {
        curve = await buildBn128(singleThread, plugins);
    } else {
        throw new Error(`Curve not supported: ${Scalar.toString(q, 16)}`);
    }
    return curve;
}

export async function getCurveFromName(name, singleThread, plugins) {
    let curve;
    const normName = normalizeName(name);
    if (["BN128", "BN254", "ALTBN128"].indexOf(normName) >= 0) {
        curve = await buildBn128(singleThread, plugins);
    } else {
        throw new Error(`Curve not supported: ${name}`);
    }
    return curve;

    function normalizeName(n) {
        return n.toUpperCase().match(/[A-Za-z0-9]+/g).join("");
    }

}