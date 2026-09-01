// What client_index.js must do, checked without a game: the script is loaded
// into a stub of the RAGE Multiplayer client API with a clock under test
// control, and every path is driven directly.
//
//   node tools/acceptance/probe_test.js
"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const SOURCE = fs.readFileSync(path.join(__dirname, "client_index.js"), "utf8");

// Flipping the switch must reorder the run, not break it.
const STREAM_FIRST_SOURCE = SOURCE.replace(
    "var NATIVES_FIRST = true;",
    "var NATIVES_FIRST = false;",
);
assert.notStrictEqual(STREAM_FIRST_SOURCE, SOURCE, "the NATIVES_FIRST switch moved or was renamed");

// The DLC model must never reach the streamer: requesting it kills this build.
const DLC_HASH = 3292967587;
const STOCK_HASH = 2515846680;

// A stub of the client API. `natives` maps each model-info call to a value to
// return, or a function that may throw or end the run.
function harness(natives, source) {
    const sent = [];
    const calls = [];
    const state = { clock: 0, dead: false };

    const nativeCall = (name) => (hash) => {
        if (state.dead) {
            throw new Error("called a native after the process died");
        }
        calls.push({ name, hash, at: state.clock });
        const behaviour = natives[name];
        if (typeof behaviour === "function") {
            return behaviour(hash, state, calls);
        }
        return behaviour;
    };

    const handlers = {};
    const mp = {
        events: {
            add: (event, fn) => {
                handlers[event] = fn;
            },
            callRemote: (event, ...args) => {
                // A dead process sends nothing more; the stub cannot stop the
                // script mid-frame, so it drops what would not reach the wire.
                if (state.dead) {
                    return;
                }
                sent.push({ event, args, at: state.clock });
            },
        },
        gui: { chat: { push: () => {} } },
        game: {
            joaat: (name) => (name === "volga5" ? 3292967587 : 2515846680),
            streaming: {
                requestModel: nativeCall("requestModel"),
                hasModelLoaded: nativeCall("hasModelLoaded"),
                isModelInCdimage: nativeCall("isModelInCdimage"),
            },
            vehicle: {
                getVehicleClassFromName: nativeCall("getVehicleClassFromName"),
            },
        },
    };

    const timers = [];
    const context = vm.createContext({
        mp,
        Date: { now: () => state.clock },
        setTimeout: (fn, delay) => {
            timers.push({ at: state.clock + delay, fn });
        },
        console,
    });
    vm.runInContext(source || SOURCE, context, { filename: "client_index.js" });

    // One frame of the render loop, at 60 fps, for as long as asked. More than
    // one native call in a frame means the tick is looping.
    const run = (ms) => {
        const until = state.clock + ms;
        while (state.clock < until && !state.dead) {
            const before = calls.length;
            handlers.render();
            assert.ok(
                calls.length - before <= 1,
                `a single frame made ${calls.length - before} native calls; the tick is looping`,
            );
            state.clock += 16;
        }
    };

    // The same machine driven by its other clock, with the render tick never
    // called: a probe with one clock can be silent.
    const runTimers = (ms) => {
        const until = state.clock + ms;
        while (state.clock < until && !state.dead) {
            const dueNow = timers.filter((t) => t.at <= state.clock);
            for (const t of dueNow) {
                timers.splice(timers.indexOf(t), 1);
                const before = calls.length;
                t.fn();
                assert.ok(
                    calls.length - before <= 1,
                    `a single timer made ${calls.length - before} native calls`,
                );
            }
            state.clock += 16;
        }
    };

    return {
        mp, handlers, sent, calls, state, run, runTimers, timers,
        join: () => handlers.playerReady(),
    };
}

const events = (sent) => sent.map((s) => `${s.event} ${s.args.join(" ")}`);
const only = (sent, name) => sent.filter((s) => s.event === name);

// One streaming cycle, as the probe reports it: announce, request, announce,
// poll, report. There are two per run — the stock model, then the pack's own.
const cycle = (sent, model, index) => {
    const report = only(sent, "rpf:streamed")[index];
    return [
        `rpf:probe stage=pre_request model=${model}`,
        "rpf:probe stage=post_request",
        "rpf:probe stage=pre_poll",
        `rpf:streamed model=${model} ${report.args[1]} ${report.args[2]}`,
    ];
};

// --- 1. the whole run, in its shipped order -------------------------------
{
    let polls = 0;
    const h = harness({
        requestModel: undefined,
        hasModelLoaded: () => ++polls >= 3,
        isModelInCdimage: true,
        getVehicleClassFromName: 1,
    });
    h.join();
    h.run(8000);

    assert.deepStrictEqual(events(h.sent), [
        "rpf:joined model=volga5 hash=3292967587",
        "rpf:probe stage=pre_natives",
        "rpf:probe stage=post_cdimage in_cdimage=true",
        "rpf:acceptance in_cdimage=true class=1",
        ...cycle(h.sent, "adder", 0),
        ...cycle(h.sent, "volga5", 1),
    ], "the class line comes first, then the stock control, then the pack's model");
    assert.ok(polls >= 3, "the streamer was asked once per poll interval");

    // The stock model is asked FIRST and the pack's own second: a death on the
    // second is then attributable, and the first says the probe works.
    const streamCalls = h.calls.filter(
        (c) => c.name === "requestModel" || c.name === "hasModelLoaded",
    );
    assert.strictEqual(streamCalls[0].hash, STOCK_HASH, "the stock model goes first");
    assert.strictEqual(
        streamCalls[streamCalls.length - 1].hash,
        DLC_HASH,
        "the pack's own model is asked last",
    );
    for (const call of h.calls) {
        if (call.name === "isModelInCdimage" || call.name === "getVehicleClassFromName") {
            assert.strictEqual(call.hash, DLC_HASH, call.name + " must ask about the DLC model");
        }
    }
}

// --- 2. the model never streams: the ceiling still reports ----------------
{
    const h = harness({
        requestModel: undefined,
        hasModelLoaded: () => false,
        isModelInCdimage: true,
        getVehicleClassFromName: 7,
    });
    h.join();
    h.run(30000);

    const streamed = only(h.sent, "rpf:streamed");
    assert.strictEqual(streamed.length, 2, "each model reports once at the ceiling");
    for (const s2 of streamed) {
        assert.strictEqual(s2.args[1], "model_loaded=false");
        const waited = Number(s2.args[2].split("=")[1]);
        assert.ok(waited >= 8000 && waited < 9000, `the ceiling is ~8s, got ${waited}ms`);
    }
    assert.deepStrictEqual(
        streamed.map((s2) => s2.args[0]),
        ["model=adder", "model=volga5"],
        "the stock model first, the pack's own second",
    );
    assert.deepStrictEqual(
        events(h.sent).slice(0, 4),
        [
            "rpf:joined model=volga5 hash=3292967587",
            "rpf:probe stage=pre_natives",
            "rpf:probe stage=post_cdimage in_cdimage=true",
            "rpf:acceptance in_cdimage=true class=7",
        ],
        "the class line is emitted before the streaming half, one call a frame",
    );
}

// --- 3. a native throws: the throw is reported, and the run continues ------
{
    const h = harness({
        requestModel: () => {
            throw new Error("native blew up");
        },
        isModelInCdimage: false,
        getVehicleClassFromName: -1,
    });
    h.join();
    h.run(6000);

    const errors = only(h.sent, "rpf:error");
    assert.strictEqual(errors.length, 1, "the throw is reported once");
    assert.strictEqual(errors[0].args[0], "where=request_model");
    assert.ok(errors[0].args[1].startsWith("message=native_blew_up"));
    assert.ok(
        events(h.sent).includes("rpf:acceptance in_cdimage=false class=-1"),
        "a thrown streamer does not cost the acceptance line",
    );
}

// --- 4. a native ends the process: the breadcrumb is already on the wire ---
// The probe must announce what it is about to do far enough ahead that the
// packet leaves before a faulting native ends the client.
{
    const h = harness({
        requestModel: (_hash, state) => {
            state.dead = true;
        },
    });
    h.join();
    h.run(6000);

    const said = events(h.sent);
    assert.strictEqual(
        said[said.length - 1],
        "rpf:probe stage=pre_request model=adder",
        "the last thing said names the call that killed the client",
    );
    assert.ok(
        said.some((l) => l.startsWith("rpf:acceptance ")),
        "the class line was already out before the fatal call",
    );

    const announced = only(h.sent, "rpf:probe").pop().at;
    const request = h.calls.filter((c) => c.name === "requestModel")[0];
    const killed = request.at;
    assert.ok(
        killed - announced >= 300,
        `only ${killed - announced}ms between the breadcrumb and the call it announced`,
    );
}

// --- 4b. the render tick is missing: the timer carries the whole run --------
{
    let polls = 0;
    const h = harness({
        requestModel: undefined,
        hasModelLoaded: () => ++polls >= 2,
        isModelInCdimage: true,
        getVehicleClassFromName: 1,
    });
    h.join();
    h.runTimers(6000);

    assert.deepStrictEqual(events(h.sent), [
        "rpf:joined model=volga5 hash=3292967587",
        "rpf:probe stage=pre_natives",
        "rpf:probe stage=post_cdimage in_cdimage=true",
        "rpf:acceptance in_cdimage=true class=1",
        ...cycle(h.sent, "adder", 0),
        ...cycle(h.sent, "volga5", 1),
    ], "setTimeout alone drives the whole sequence");
}

// --- 4c. the switch reorders the run and loses nothing --------------------
{
    let polls = 0;
    const h = harness({
        requestModel: undefined,
        hasModelLoaded: () => ++polls >= 2,
        isModelInCdimage: true,
        getVehicleClassFromName: 1,
    }, STREAM_FIRST_SOURCE);
    h.join();
    h.run(8000);

    assert.deepStrictEqual(events(h.sent), [
        "rpf:joined model=volga5 hash=3292967587",
        ...cycle(h.sent, "adder", 0),
        ...cycle(h.sent, "volga5", 1),
        "rpf:probe stage=pre_natives",
        "rpf:probe stage=post_cdimage in_cdimage=true",
        "rpf:acceptance in_cdimage=true class=1",
    ], "the switch puts the streaming half first and loses nothing");
}

// --- 5. every path says something -----------------------------------------
// Whatever the natives do, the probe speaks again after `joined`.
for (const [name, natives] of [
    ["loads", { hasModelLoaded: () => true, isModelInCdimage: true, getVehicleClassFromName: 1 }],
    ["never loads", { hasModelLoaded: () => false, isModelInCdimage: true, getVehicleClassFromName: 7 }],
    ["throws", { hasModelLoaded: () => { throw new Error("x"); }, isModelInCdimage: true, getVehicleClassFromName: 1 }],
    ["dies", { requestModel: (_h, s) => { s.dead = true; } }],
]) {
    const h = harness(Object.assign({ requestModel: undefined }, natives));
    h.join();
    h.run(20000);
    assert.ok(
        h.sent.length >= 2,
        `"${name}" reported only ${h.sent.length} line(s); silence after joining is the one outcome that must be impossible`,
    );
}

console.log("probe_test: 7 checks passed");
