import { expect } from 'chai';
import { Entry } from '../claim/entry.js';
import { buildHasher, buildSnarkField, Hasher, SnarkField } from '../global.js';
import { generateDataFromEntry, generateEntry, getSchemaHashFromSchema, Registry, Schema, schemaPropertiesSlot } from './schema.js';

describe('test schema', async () => {
    let F: SnarkField;
    let hasher: Hasher;
    let data: any;
    let schema: Schema;
    let registry: Registry;
    let claim: Entry;
    it('set up params', async () => {
        F = await buildSnarkField();
        hasher = await buildHasher();
        schema = {
            "title": "US Identity Document Claim",
            "properties": {
              "documentId": {
                "title": "Document ID",
                "type": "string"
              },
              "documentType": {
                "title": "Document Type",
                "type": "string"
              },
              "name": {
                "title": "Full Name",
                "type": "string"
              },
              "dateOfBirth": {
                "title": "Date Of Birth",
                "type": "datetime"
              },
              "nationality": {
                "title": "Nationality",
                "type": "integer",
                "minimum": "0",
                "maximum": "10000"
              },
              "countryOfResidence": {
                "title": "Country Of Residence",
                "type": "integer",
                "minimum": "0",
                "maximum": "10000"
              },
              "address": {
                "title": "Address",
                "type": "string"
              },
              "zipCode5": {
                "title": "ZIP code 5",
                "type": "float"
              },
              "zipCodePlus4": {
                "title": "ZIP code +4",
                "type": "boolean"
              }
            },
            "index": ["documentId", "documentType"],
            "value": ["name", "dateOfBirth", "nationality", "countryOfResidence", "address", "zipCode5", "zipCodePlus4"],
            "required": ["documentId", "documentType", "name", "dateOfBirth", "nationality", "countryOfResidence", "address", "zipCode5"]
        };
        registry = {
            "schemaHash": "123456",
            "issuerId": "789100",
            "description": "This is for test only.",
            "expiration": 86400000,
            "updatable": false,
            "idPosition": 1,
            "proofType": "mtp"
        };

        data = {
            "userId": "123",
            "documentId": "123",
            "documentType": "Id Card",
            "name": "Hdt",
            "dateOfBirth": 20012002010101,
            "nationality": 123,
            "countryOfResidence": 123,
            "address": "Ha Noi, Viet Nam",
            "zipCode5": 10.504999999999999999999999999999999999999999999999999999,
            "zipCodePlus4": false
        }
    });

    it('test generate entry from data', async () => {
        claim = generateEntry(data, schema, registry, F, hasher);
        console.log(claim);
    });

    it('test convert entry to data', async () => {
        let dataFromEntry = generateDataFromEntry(claim, schema);
        console.log(dataFromEntry);
        expect(dataFromEntry["userId"]).to.be.equal(data["userId"]);
        expect(dataFromEntry["dateOfBirth"]).to.be.equal(data["dateOfBirth"]);
        expect(dataFromEntry["nationality"]).to.be.equal(data["nationality"]);
        expect(dataFromEntry["countryOfResidence"]).to.be.equal(data["countryOfResidence"]);
        expect(Math.abs(dataFromEntry["zipCode5"] - data["zipCode5"]) <= 1e-6).to.be.true;
        expect(dataFromEntry["zipCodePlus4"]).to.be.equal(data["zipCodePlus4"]);
    });

    it('test hash schema', async () => {
        let schemaHash = getSchemaHashFromSchema(schema, F, hasher);
        console.log(schemaHash);
        
    });

    it('test get properties slot', async () => {
        let propertiesSlot = schemaPropertiesSlot(schema);
        console.log(propertiesSlot);
    })
}).timeout(10000);