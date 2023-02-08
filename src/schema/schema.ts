import { newClaim, schemaHashFromBigInt, withIndexData, withValueData } from '../claim/entry.js';
import { getZidenParams } from '../global.js';
import {
  bitsToNum,
  floatToBuffer,
  hexToBuffer,
  numToBits,
  setBits,
  stringToHex,
} from '../utils.js';

export function getSchemaHashFromSchema(schema: any): string {
  let hashData = getZidenParams()
    .F.toObject(getZidenParams().hasher([BigInt(stringToHex(JSON.stringify(schema)))]))
    .toString(2);
  let bitRemove = hashData.length < 128 ? 0 : hashData.length - 128;
  let hashDataFixed = BigInt('0b' + hashData.slice(0, hashData.length - bitRemove));
  let value = BigInt(hashDataFixed);
  return value.toString();
}

enum Type {
  str = "std:str",
  int =  "std:int",
  double = "std:double",
  obj = "std:obj",
  bool = "std:bool",
  date = "std:date"
}

enum Slot {
  val1 = "std-pos:val-1",
  val2 = "std-pos:val-2",
  idx1 = "std-pos:idx-1",
  idx2 = "std-pos:idx-2",
}

function checkInEnum(x: any, y: any) {
  return Object.values(y).includes(x as typeof y);
}

export function getInputSchema(schema: any) {
  try {
    let primitiveSchema: any = {
      "@name": schema["@name"],
      "@id": schema["@id"],
      "@hash": schema["@hash"],
      "@required": schema["@required"]
    };

    const schemaRaw: any = schema;

    const listContext = schema["@context"];
    let map: any = {};

    listContext.forEach((context: any) => {
        const keys = Object.keys(context);
        const id = context["@id"];
        if (id == undefined) {
            return;
        }
        keys.forEach((key: string) => {
            if (key == undefined || key[0] == '@') {
                return;
            }
            map[id + ":" + key] = context[key];
        });
    });

    const keys = Object.keys(schemaRaw);

    for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        if (key[0] == '@' || key == "_doc") {
            continue;
        }
        let obj = schemaRaw[key];
        let type = obj["@type"];
        let id = obj["@id"];
        if (type == undefined || id == undefined) {
            continue;
        }

        while (!checkInEnum(type, Type)) {
            const context = map[type];
            if (context == undefined || !context["@type"]) {
                break;
            }
            type = context["@type"];
            obj = context;
        }
        obj["@id"] = id;
        if (checkInEnum(type, Type)) {
            if (type != Type.obj) {
                primitiveSchema[key] = obj;
            } else {
                let objValue: any = {};
                objValue["@id"] = id;
                const keys = Object.keys(obj);
                keys.forEach((key) => {
                    if (key[0] == '@') {
                        objValue[key] = obj[key];
                    } else {
                        let typeValue = obj[key]["@type"];
                        if (typeValue == undefined) {
                            return;
                        }
                        if (checkInEnum(typeValue, Type)) {
                            objValue[key] = obj[key];
                        } else {
                            let objValProperty: any = {};
                            while(!checkInEnum(typeValue, Type)) {
                                const subContext = map[typeValue];
                                if (subContext["@type"] == undefined) {
                                    break;
                                }
                                typeValue = subContext["@type"];
                                objValProperty = subContext;
                            }

                            if (checkInEnum(typeValue, Type)) {
                                objValue[key] = objValProperty;
                            }
                        }
                    }
                });
                primitiveSchema[key] = objValue;
            }
        }
    }
    return primitiveSchema;
  } catch (err) {
    throw("Invalid schema!");
  }
}

export function schemaPropertiesSlot(schemaRaw: any) {
  try {
    let propertiesSlot: any = {};

    const schema = getInputSchema(schemaRaw);
    const propertiesKey = Object.keys(schema);

    let bitStart = [0, 0, 0, 0, 0, 0, 0, 0];

    propertiesKey.forEach(key => {
      if (key[0] == '@') {
        return;        
      }

      const property = schema[key];
      const propertyType = property["@type"];
      const propertyId = property["@id"];

      if (propertyType == undefined || propertyId == undefined || !checkInEnum(propertyId, Slot) || !checkInEnum(propertyType, Type)) {
        return;
      }

      let slot = 0;
      switch(propertyId) {
        case Slot.idx1:
          slot = 2;
          break;
        case Slot.idx2:
          slot = 3;
          break;
        case Slot.val1:
          slot = 6;
          break;
        case Slot.val2:
          slot = 7;
          break;
      }

      if (propertyType == Type.obj) {
        propertiesSlot[key] = {};
        const keysProp = Object.keys(property);
        keysProp.forEach(keyProp => {
          let type = property[keyProp]["@type"];
          if (type == undefined || keyProp[0] == '@') {
            return
          }
          let size = getBitFromType(type);
          if (size > 0) {
            if (bitStart[slot] + size > 253) {
              throw("Schema too large!");
            }
            propertiesSlot[key][keyProp] = {
              "type": type,
              "slot": slot,
              "begin": bitStart[slot],
              "end": bitStart[slot] + size - 1
            };
            bitStart[slot] += size;
          }
        })
      }
      else {
        let size = getBitFromType(propertyType);
        if (size > 0) {
          if (bitStart[slot] + size > 253) {
            throw("Schema too large!");
          }
          propertiesSlot[key] = {
            "type": propertyType,
            "slot": slot,
            "begin": bitStart[slot],
            "end": bitStart[slot] + size - 1
          };
          bitStart[slot] += size;
        }
      }
    });

    return propertiesSlot;

  } catch (err) {
    throw(err);
  }
}

function getBitFromType(type: string) {
  switch(type) {
    case Type.str:
      return 125;
    case Type.bool:
      return 4;
    case Type.date:
      return 32;
    case Type.int:
      return 32;
    case Type.double:
      return 64;
  }
  return 0;
}

function getBigIntValue(type: string,  data: any) {
  let value: BigInt = BigInt(0);
  switch(type) {
    case Type.str:
      let hashData = getZidenParams()
          .F.toObject(getZidenParams().hasher([BigInt(stringToHex(data ?? ''))]))
          .toString(2);
      let bitRemove = hashData.length < 125 ? 0 : hashData.length - 125;
      let hashDataFixed = BigInt('0b' + hashData.slice(0, hashData.length - bitRemove));
      value = BigInt(hashDataFixed);
      break;
    case Type.bool:
      value = data ? BigInt(1): BigInt(0);
      break;
    case Type.date:
      value = BigInt((data?? 0).toString());
      break;
    case Type.int:
      value = BigInt((data?? 0).toString());
      break;
    case Type.double:
      value = bitsToNum(floatToBuffer(data ?? 0));
      break;
    }
  return value;
}

export function buildEntryFromSchema(userData: any, userId: string, schemaRaw: any, registry: any) {
  try {
    const propertySlot = schemaPropertiesSlot(schemaRaw);
    const schema = getInputSchema(schemaRaw);
    let entry: Array<BigInt> = [ BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0) ];
    const keys = Object.keys(propertySlot);
    keys.forEach(key => {
      const type = propertySlot[key]["type"];
      const slot = propertySlot[key]["slot"];
      const begin = propertySlot[key]["begin"];

      if (type != Type.obj) {
        const data = userData[key];
        if (data == undefined) {
          if (schema["@required"].includes(key))
            throw("Invalid data, required " + key);
        }
        else {
          let value = getBigIntValue(type, data);
          entry[slot] = setBits(entry[slot], begin, value);
        }

      } else {
        const propsKeys = Object.keys(propertySlot[key]);
        propsKeys.forEach(propKey => {
          const typeProp = propertySlot[key][propKey]["type"];
          const beginProp = propertySlot[key][propKey]["begin"];
          const data = userData[key];
          if (data == undefined) {
            if (schema["@required"].includes(key))
              throw("Invalid data, required " + key);
          }
          else {
            let dataValue = data[propKey];
            if (dataValue == undefined) {
              return;
            }
            
            let value = getBigIntValue(typeProp, data);
            entry[slot] = setBits(entry[slot], beginProp, value);
          }
        })
      }
    })

    const claim = newClaim(
      schemaHashFromBigInt(BigInt(registry.schemaHash?? '123456789')),
      withIndexData(numToBits(entry[2], 32), numToBits(entry[3], 32)),
      withValueData(numToBits(entry[6], 32), numToBits(entry[7], 32))
    );

    if (userId) {
      claim.setIndexID(hexToBuffer(userId, 31));
    }
    if (registry.expiration && registry.expiration > 0) {
      claim.setFlagExpirable(true);
      claim.setExpirationDate(BigInt(Date.now() + registry.expiration));
    }

    if (registry.updatable) {
      claim.setFlagUpdatable(true);
    }

    return claim;
  } catch (err) {
    throw(err)
  }
}