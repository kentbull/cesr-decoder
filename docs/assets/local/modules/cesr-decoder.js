import {
    getCesrValue,
    getCesrFrame,
    CesrProtocol,
    CesrValue,
    Serials,
    CesrVersionHeader
} from "../../common/modules/cesr.js";

/**
 * A grouped primitive
 */
class Group {
    /** @type {Group} */
    next;
    /** @type {CesrProtocol} */
    protocol;
    /** @type {object} */
    value;
    constructor(obj) {
        this.next = obj?.next;
        this.protocol = obj?.protocol;
        this.value = obj?.value;
    }
    toJSON() {
        return `Group(protocol=${this.protocol?.name})`;
    }
}

/**
 * A {Frame} is a self-framing value from a CESR stream including a reference to the next {Frame}
 * in a sequence of Frames.
 */
class Frame {
    /** @type {Frame} */
    next;
    /** @type {number} */
    end;
    /**
     * Either {@link getCesrValue} or {@link getCesrFrame}
     * @type {getCesrValue | getCesrFrame}
     * */
    valueGetter;
    /** @type {Group} */
    group;
    /** @type {object} */
    value;
    constructor(obj) {
        this.next = obj?.next;
        this.end = obj?.end;
        this.valueGetter = obj?.valueGetter;
        this.group = obj?.group;
        this.value = obj?.value;
    }
    toJSON() {
        return `Frame(end=${this.end})`;
    }
}

export class DecoderState {
    /** @type {Frame} */
    currentFrame;
    /** @type {Group} */
    get currentGroup() { return this.currentFrame.group; }
    /** @type {number} */
    start;
    /** @type {number} */
    get end() { return this.currentFrame.end; }
    /** @type {boolean} */
    get isEmpty() { return this.currentFrame.next === null; }
    /**
     * @param {object} value
     */
    constructor(value) {
        this.currentFrame = new Frame({
            next: null,
            end: undefined,
            valueGetter: getCesrFrame,
            group: null,
            value: value
        });
        this.start = 0;
    }
    /**
     * @param {number} end
     * @param {object} value
     */
    pushFrame(end, value) {
        this.currentFrame = new Frame({
            next: this.currentFrame,
            end: end,
            valueGetter: getCesrValue,
            group: null,
            value: value
        });
    }
    popFrame() {
        if (this.isEmpty) throw Error("DecoderState.popFrame");
        this.currentFrame = this.currentFrame.next;
    }
    /**
     * @param {number} count
     * @param {CesrProtocol} protocol
     * @param {object} value
     */
    pushGroup(count, protocol, value) {
        for (let i = 0; i < count; i++) {
            this.currentFrame.group = new Group({
                next: this.currentFrame.group,
                protocol: protocol,
                value: value,
            });
        }
    }
    /**
     * @returns {Group}
     */
    popGroup() {
        const group = this.currentFrame.group;
        this.currentFrame.group = this.currentFrame.group?.next;
        return group;
    }
}

export class CesrDecoder {
    /**
     * The code tables read in from Disk
     * @type {CesrProtocol}
     */
    #protocol;
    /**
     * @param {CesrProtocol} protocol
     */
    constructor(protocol) {
        if (protocol === null || protocol === undefined) throw new TypeError(`CesrDecoder(protocol): invalid argument`);
        this.#protocol = protocol;
    }
    /**
     * @param {Frame} frame
     * @param {Group} group
     * @param {CesrValue} code
     * @param {number} offset
     * @returns {object}
     */
    mapDefault(frame, group, code, offset) { return code; }
    mapJsonFrame(frame, group, code, offset) { return this.mapDefault(frame, group, code, offset); }
    mapCesrFrame(frame, group, code, offset) { return this.mapDefault(frame, group, code, offset); }
    mapCesrGroup(frame, group, code, offset) { return this.mapDefault(frame, group, code, offset); }
    mapCesrLeaf(frame, group, code, offset) { return this.mapDefault(frame, group, code, offset); }

    /**
     * Returns the next slice of bytes based on the count of bytes between the start and end state.
     * A cold start returns the entire stream of bytes. Each iteration of the {CesrDecoder.values()}
     * generator updates the start and end based on the size of the primitive encountered.
     * @param {DecoderState} state
     * @param {Uint8Array} input
     */
    nextSlice(state, input) {
        while (true) {
            const slice = input.slice(state.start, state.end);
            if (slice.length > 0) return slice;
            if (state.isEmpty) return slice;
            state.popFrame();
        }
    }
    /**
     * Generator function that yields each encountered self-framing value in a CESR stream.
     * @param {DecoderState} state - The state of the parser window on the `input` stream bytes.
     * @param {Uint8Array} input - The CESR stream
     */
    *values(state, input) {
        let serial = 'JSON';
        let version = '';
        while (true) {
            const slice = this.nextSlice(state, input);
            if (slice.length == 0) break;
            const frame = state.currentFrame;
            const group = state.popGroup();
            const protocol = group?.protocol ?? this.#protocol;
            const getValue = frame.valueGetter;
            const frameValue = getValue(protocol, slice);
            if(frameValue.header instanceof CesrVersionHeader) {
                serial = frameValue.header.serial;
                version = frameValue.header.proto;
            }
            let length = frameValue.length;
            let result = undefined;

            if(frameValue.header.serial) {
                switch (frameValue.header.serial) {
                    case Serials.json:
                        result = this.mapJsonFrame(frame, group, frameValue, {start: state.start, length: length});
                        break;
                    default:
                        throw new Error(`Unsupported serialization type: ${frameValue.header.serial}`)
                }
            } else if (frameValue.header.selector) {
                frameValue.header.serial = serial; // set attachment serialization to stream header serialization
                frameValue.header.version = version;
                if (protocol.isFrame(frameValue.header)) {
                    length = frameValue.header.length;
                    result = this.mapCesrFrame(frame, group, frameValue, { start: state.start, length: length });
                    state.pushFrame(state.start + frameValue.length, result);
                } else if (protocol.isGroup(frameValue.header)) {
                    result = this.mapCesrGroup(frame, group, frameValue, { start: state.start, length: length });
                    const p = protocol.hasContext(frameValue.header) ? protocol.getContext(frameValue.header) : null;
                    state.pushGroup(frameValue.header.count, p, result);
                } else {
                    result = this.mapCesrLeaf(frame, group, frameValue, { start: state.start, length: length });
                }
            } else {
                throw new Error(`Unsupported header type: ${JSON.stringify(frameValue.header)}`)
            }
            yield result;
            state.start += length; // move the frame forward
        }
    }
}
