// What client_index.js must do, checked without a game.
//
// The probe cannot be exercised by joining: a join costs a person an elevation
// prompt and a two-minute game launch, and the failure it exists to prevent —
// silence — is exactly what a bad probe produces there. So the script is loaded
// into a stub of the RAGE Multiplayer client API with a clock under test
// control, and the four paths are driven directly.
//
//   node tools/acceptance/probe_test.js
"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const SOURCE = fs.readFileSync(path.join(__dirname, "client_index.js"), "utf8");

// The switch client_index.js documents for the day REQUEST_MODEL is the call
// that ends the client. Flipping it must reorder the run, not break it.
const STREAM_FIRST_SOURCE = SOURCE.replace(
    "var NATIVES_FIRST = true;",
    "var NATIVES_FIRST = false;",
);
assert.notStrictEqual(STREAM_FIRST_SOURCE, SOURCE, "the NATIVES_FIRST switch moved or was renamed");

// The DLC model must never reach the streamer: requesting it kills this build,
// on the untouched control as much as on anything this tool wrote.
const DLC_HASH = 3292967587;
const STOCK_HASH = 2515846680;

// A stub of the client API. `natives` decides what each model-info call does:
// a value to return, or a function that may throw or end the run the way a
// process death does.
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
                // A process that has died sends nothing more. The stub cannot
                // stop the script mid-frame the way an access violation does,
                // so it drops what a dead client could not have put on the wire.
                if (state.dead) {
                    return;
                }
                sent.push({ event, args, at: state.clock });
            },
        },
        gui: { chat: { push: () => {} } },
        game: {
            joaat: (name) => (name === "meringls63amg24" ? 3292967587 : 2515846680),
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

    // One frame of the render loop, at 60 fps, for as long as asked. The frame
    // budget is asserted rather than assumed: a tick that looped would show up
    // as more than one native call in a single frame.
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
    // called: a probe with one clock is a probe that can be silent.
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

    const waited = only(h.sent, "rpf:streamed")[0].args[2].split("=")[1];
    assert.deepStrictEqual(events(h.sent), [
        "rpf:joined model=meringls63amg24 hash=3292967587",
        "rpf:probe stage=pre_natives",
        "rpf:probe stage=post_cdimage in_cdimage=true",
        "rpf:acceptance in_cdimage=true class=1",
        "rpf:probe stage=pre_request model=adder",
        "rpf:probe stage=post_request",
        "rpf:probe stage=pre_poll",
        "rpf:streamed model=adder model_loaded=true waited_ms=" + waited,
    ], "the class line comes first, then the streaming control");
    assert.strictEqual(polls, 3, "the streamer was asked once per poll interval");

    // The one thing that must never happen: the DLC model reaching the streamer.
    for (const call of h.calls) {
        if (call.name === "requestModel" || call.name === "hasModelLoaded") {
            assert.strictEqual(call.hash, STOCK_HASH, call.name + " was given the DLC model");
        }
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
    assert.strictEqual(streamed.length, 1, "the ceiling reports exactly once");
    assert.strictEqual(streamed[0].args[1], "model_loaded=false");
    const waited = Number(streamed[0].args[2].split("=")[1]);
    assert.ok(waited >= 8000 && waited < 9000, `the ceiling is ~8s, got ${waited}ms`);
    assert.deepStrictEqual(
        events(h.sent).slice(0, 4),
        [
            "rpf:joined model=meringls63amg24 hash=3292967587",
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
// This is the 2026-09-01 failure. REQUEST_MODEL faulted the client at module
// offset 0xf4cb31 and nothing after it ever ran; the probe must have said what
// it was about to do, far enough ahead that the packet left.
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
        "rpf:joined model=meringls63amg24 hash=3292967587",
        "rpf:probe stage=pre_natives",
        "rpf:probe stage=post_cdimage in_cdimage=true",
        "rpf:acceptance in_cdimage=true class=1",
        "rpf:probe stage=pre_request model=adder",
        "rpf:probe stage=post_request",
        "rpf:probe stage=pre_poll",
        "rpf:streamed model=adder model_loaded=true waited_ms="
            + only(h.sent, "rpf:streamed")[0].args[2].split("=")[1],
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
        "rpf:joined model=meringls63amg24 hash=3292967587",
        "rpf:probe stage=pre_request model=adder",
        "rpf:probe stage=post_request",
        "rpf:probe stage=pre_poll",
        "rpf:streamed model=adder model_loaded=true waited_ms="
            + only(h.sent, "rpf:streamed")[0].args[2].split("=")[1],
        "rpf:probe stage=pre_natives",
        "rpf:probe stage=post_cdimage in_cdimage=true",
        "rpf:acceptance in_cdimage=true class=1",
    ], "the switch puts the streaming half first and loses nothing");
}

// --- 5. every path says something -----------------------------------------
// The failure this file exists to make impossible: a join that reports nothing
// after `joined`. Whatever the natives do, the probe speaks again.
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
