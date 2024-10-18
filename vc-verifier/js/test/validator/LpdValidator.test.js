import { jest } from '@jest/globals';
import {LdpValidator} from "../../src/validator/LdpValidator.js";

describe("validator", () => {
    it("valid vc", () => {  // Corrected here
        const result = LdpValidator().validate("");
        expect(result.verificationStatus).toBe(true);
    });
});