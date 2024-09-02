/**
 * Fetch json
 * @param {string} uri
 * @returns {object}
 */
async function get_json(uri) {
    uri = new URL(uri, import.meta.url);
    const response = await fetch(uri);
    if (!response.ok) throw new Error(`GET ${uri}: ${response.status ?? "failed"}`);
    return await response.json();
}

/**
 * Load count table, field
 * Transform regex patterns in default_sizes.json
 * @param {Promise} default_sizes_promise
 * @returns {object}
 */
async function transform_patterns(default_sizes_promise) {
    const default_sizes = await default_sizes_promise;
    for (const i of Object.values(default_sizes)) {
        for (const j of Object.values(i)) {
            if ("hard_pattern" in j) {
                j["hard_pattern"] = transform_pattern(j["hard_pattern"]);
            }
            if ("soft_pattern" in j) {
                j["soft_pattern"] = transform_pattern(j["soft_pattern"]);
            }
        }
    }
    return default_sizes;
}

/**
 * Transform single regex pattern
 * @param {string} pattern
 * @returns {string}
 */
function transform_pattern(pattern) {
    pattern = pattern.replace("[:alpha:]", "[A-Za-z]");
    pattern = pattern.replace("[:base64:]", "[A-Za-z0-9_-]");
    pattern = pattern.replace("(?P<", "(?<");
    return pattern;
}

/**
 * Combine patterns to single pattern with named groups
 * @param {object} default_sizes
 * @returns {string}
 */
function hard_pattern(default_sizes) {
    const t = [];
    for (const i of Object.values(default_sizes)) {
        for (const [k, v] of Object.entries(i)) {
            // (?<OneCharFixedSize>[A-Za-z]{1})
            t.push(`(?<${k}>${v.hard_pattern})`);
        }
    }
    return `^(${t.join("|")})`;
}

/**
 * The set of CESR code tables as read from JSON schema files for material codes, count codes, and index codes
 */
export class CesrTables {
    /** codex.json */
    codex;
    /** sizes.json */
    sizes;
    /** counter.json */
    counter;
    /** default_sizes.json */
    default_sizes;
    /**
     * @returns {CesrTables}
     */
    static async load() {
        const codex = get_json("../schema/codex.json");
        const sizes = get_json("../schema/sizes.json");
        const counter = get_json("../schema/counter.json");
        const default_sizes = transform_patterns(get_json("../schema/default_sizes.json"));
        const tables = new CesrTables();
        tables.codex = Object.freeze(await codex);
        tables.sizes = Object.freeze(await sizes);
        tables.counter = Object.freeze(await counter);
        tables.default_sizes = Object.freeze(await default_sizes);
        return Object.freeze(tables);
    }
    /**
     * Create context by selecting named entries (Matter, Counter, Indexer, etc)
     * @param  {...string} names
     * @returns {CesrContext}
     */
    context(...names) {
        return CesrContext.create(this, ...names);
    }
}

/**
 * Context is subset of CesrTables that contains either Matter, Indexer, or Counter codes or a combination of these.
 */
export class CesrContext {
    /** codex.json */
    codex;
    /** sizes.json */
    sizes;
    /** counter.json */
    counter;
    /** default_sizes.json */
    default_sizes;
    /** hard_pattern combined */
    hard_pattern;
    /**
     * Create context by selecting named entries (Matter, Counter, Indexer, etc)
     * @param {KeriTables} tables
     * @param  {...string} names
     * @returns {CesrContext}
     */
    static create(tables, ...names) {
        const context = new CesrContext();
        context.codex = {};
        context.sizes = {};
        context.counter = {};
        context.default_sizes = {};
        for (const name of names) {
            if (name in tables.codex) {
                context.codex[name] = tables.codex[name];
            }
            if (name in tables.sizes) {
                context.sizes[name] = tables.sizes[name];
            }
            if (name in tables.counter) {
                context.counter[name] = tables.counter[name];
            }
            if (name in tables.default_sizes) {
                context.default_sizes[name] = tables.default_sizes[name];
            }
        }
        Object.freeze(context.codex);
        Object.freeze(context.sizes);
        Object.freeze(context.counter);
        Object.freeze(context.default_sizes);
        context.hard_pattern = new RegExp(hard_pattern(context.default_sizes));
        return Object.freeze(context);
    }
    /**
     * Lookup code spec.
     * @param {string} code
     * @returns {object}
     */
    lookup(code) {
        const result = this.lookup_table(code);
        if (result === null) return null;
        const name = this.lookup_name(code, result);
        if (name !== null) result["name"] = name;
        const sizes = this.lookup_sizes(code, result);
        if (sizes !== null) result["sizes"] = sizes;
        const counter = this.lookup_counter(code, result);
        if (counter !== null) result["counter"] = counter;
        return result;
    }
    /**
     * Match code to hard_pattern. Lookup matching entry from default_sizes.json
     * @param {string} code
     * @returns {object | null}
     */
    lookup_table(code) {
        const result = this.hard_pattern.exec(code);
        for (const [k, v] of Object.entries(result.groups)) {
            if (v !== undefined) {
                for (const i of Object.values(this.default_sizes)) {
                    if (k in i) {
                        return {
                            table_type: k,
                            default_size: i[k]
                        };
                    }
                }
            }
        }
        return null;
    }
    /**
     * Match code hard part. Lookup matching entry from codex.json
     * @param {string} code
     * @param {object} table
     * @returns {object | null}
     */
    lookup_name(code, table) {
        const hard = code.slice(0, table.default_size.hs);
        for (const i of Object.values(this.codex)) {
            if (hard in i) {
                return i[hard];
            }
        }
        return null;
    }
    /**
     * Match code hard part. Lookup matching entry from sizes.json
     * @param {string} code
     * @param {object} table
     * @returns {object | null}
     */
    lookup_sizes(code, table) {
        const hard = code.slice(0, table.default_size.hs);
        for (const i of Object.values(this.sizes)) {
            if (hard in i) {
                return i[hard];
            }
        }
        return null;
    }
    /**
     * Match code hard part. Lookup matching entry from counter.json
     * @param {string} code
     * @param {object} table
     * @returns {object | null}
     */
    lookup_counter(code, table) {
        const hard = code.slice(0, table.default_size.hs);
        for (const i of Object.values(this.counter)) {
            if (hard in i) {
                return i[hard];
            }
        }
        return null;
    }
}
