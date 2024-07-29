import { Constants } from "../constant/Constants.js";
import jsonld from 'jsonld';
import crypto from 'crypto';

export const URDNA2015Canonicalizer = async (jsonldObject) => {
    const jsonldProof = { ...jsonldObject["proof"] };
    delete jsonldProof["jws"];
    jsonldProof["@context"] = jsonldObject["@context"];

    const jsonldObjectClone = { ...jsonldObject };
    delete jsonldObjectClone["proof"];

    const expandedJsonldObject = await jsonld.expand(jsonldObjectClone);
    let normalizedJsonldObject = await jsonld.canonize(expandedJsonldObject, {
        algorithm: Constants.NORMALISED_ALGO_CONST
    });
    
    const expandedJsonldProof = await jsonld.expand(jsonldProof);
    let normalizedJsonldProof = await jsonld.canonize(expandedJsonldProof, {
        algorithm: Constants.NORMALISED_ALGO_CONST
    });

    const canonicalizationResult = Buffer.alloc(64);
    Buffer.concat([
        crypto.createHash('sha256').update(normalizedJsonldProof).digest(),
        crypto.createHash('sha256').update(normalizedJsonldObject).digest()
    ]).copy(canonicalizationResult, 0);

    return canonicalizationResult;
}