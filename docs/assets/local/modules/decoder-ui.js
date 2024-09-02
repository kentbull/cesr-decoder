import { CesrDecoder } from "./cesr-decoder.js";
import { Utf8 } from "./utf8.js";

function replacer(k, v) {
    if (v instanceof Uint8Array) {
        return Utf8.decode(v);
    }
    return v;
}
function toJson(obj) {
    return JSON.stringify(obj, replacer, 2);
}
function fromJson(json) {
    return JSON.parse(json);
}

function formatHeader(code) {
    const parts = [];
    parts.push(code.header.value);
    parts.push(code.header.typeName ?? code.header.serial);
    for (const i of ["leadBytes", "size", "count", "version", "index", "ondex"]) {
        if (Object.hasOwn(code.header, i)) {
            parts.push(`${i}=${code.header[i]}`);
        }
    }
    return parts.join(" ");
}

function formatJsonHeader(code, json) {
    const parts = [];
    parts.push(code.header.value);
    parts.push(code.header.proto);
    parts.push(`size=${code.header.size}`);
    switch (code.header.proto) {
        case "KERI10":
            for (const i of ["t", "i", "r"]) {
                if (Object.hasOwn(json, i)) {
                    parts.push(`${i}=${json[i]}`);
                }
            }
            break;
        case "ACDC10":
            for (const i of ["i", "s"]) {
                if (Object.hasOwn(json, i)) {
                    parts.push(`${i}=${json[i]}`);
                }
            }
            break;
    }
    return parts.join(" ");
}


export class DecoderUi extends CesrDecoder {
    /**
     * @param {CesrProtocol} protocol
     */
    constructor(protocol) {
        super(protocol);
    }
    mapDefault(frame, group, cesrValue, offset, header) {
        const parent = (group?.value ?? frame.value);
        const details = document.createElement("details");
        details.setAttribute("data-start", offset.start);
        details.setAttribute("data-end", offset.start + offset.length);
        const summary = document.createElement("summary");
        header ??= formatHeader(cesrValue);
        summary.innerText = header;
        details.appendChild(summary);
        parent.appendChild(details);
        return details;
    }
    mapJsonFrame(frame, group, cesrValue, offset) {
        const json = fromJson(Utf8.decode(cesrValue.value));
        const details = this.mapDefault(frame, group, cesrValue, offset, formatJsonHeader(cesrValue, json));
        details.classList.add("frame", "json");
        const section = document.createElement("section");
        section.classList.add("value");
        const value = document.createElement("code");
        value.innerText = toJson(json);
        section.appendChild(value);
        details.appendChild(section);
        return details;
    }
    mapCesrFrame(frame, group, cesrValue, offset) {
        const details = this.mapDefault(frame, group, cesrValue, offset);
        details.classList.add("frame", "cesr");
        const section = document.createElement("section");
        section.classList.add("value");
        details.appendChild(section);
        return section;
    }
    mapCesrGroup(frame, group, cesrValue, offset) {
        const details = this.mapDefault(frame, group, cesrValue, offset);
        details.classList.add("group");
        const section = document.createElement("section");
        section.classList.add("value");
        details.appendChild(section);
        return section;
    }
    mapCesrLeaf(frame, group, cesrValue, offset) {
        const details = this.mapDefault(frame, group, cesrValue, offset);
        details.classList.add("leaf");
        const section = document.createElement("section");
        section.classList.add("value");
        const value = document.createElement("code");
        value.innerText = Utf8.decode(cesrValue.value);
        section.appendChild(value);
        details.appendChild(section);
        return section;
    }
}

export { DecoderState } from "./cesr-decoder.js";
