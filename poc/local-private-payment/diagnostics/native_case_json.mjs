// Only a representation boundary for native CASE integer JSON; no range/financial authority.
import {strictJson} from '../chain/json.mjs';
export function nativeCaseJson(raw){
 strictJson(raw); // Keep the existing UTF8/duplicate-field/grammar checks.
 const text=Buffer.isBuffer(raw)?raw.toString('utf8'):raw;
 return JSON.parse(text,(_key,value,context)=>{
  if(typeof value!=='number')return value;
  if(!context||typeof context.source!=='string'||!/^\-?(?:0|[1-9][0-9]*)$/.test(context.source))throw new Error('native CASE requires exact integer JSON tokens');
  return Number.isSafeInteger(value)?value:BigInt(context.source).toString();
 });
}
