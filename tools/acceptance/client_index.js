// The acceptance loop's client half. It reports what the game found in the
// mounted archive; it never reads the archive itself.
//
// WHY THIS FILE IS SHAPED THE WAY IT IS
//
// A native call on this model can kill the client outright. Measured twice:
// 2026-08-30, an access violation at module offset 0xf4cb31 about a second
// after IS_MODEL_IN_CDIMAGE and GET_VEHICLE_CLASS_FROM_NAME (docs/acceptance.md
// §13); 2026-09-01, the same offset, this time with REQUEST_MODEL as the only
// native the script had reached. So the rule is not "those two calls are
// dangerous" — it is that any model-info lookup on this model may end the
// process, and a probe that only speaks at the end of a sequence will be
// killed before it says anything. Silence then means either "the payload did
// not load" or "the probe never ran", which are opposite conclusions.
//
// Hence: every risky call is ANNOUNCED before it is made, and made a beat
// later, so the announcement is on the wire before the call that may end the
// process. Every path — success, ceiling, thrown error — reports. Nothing
// spins: the clock is the render tick, which returns every frame, so the
// network thread keeps servicing the connection.
const MODEL_NAME = "meringls63amg24";
const MODEL = mp.game.joaat(MODEL_NAME);

// The model the STREAMING half asks about, which is deliberately NOT the DLC's.
//
// Measured 2026-09-01 on the CONTROL — the untouched sample: REQUEST_MODEL on
// `meringls63amg24` returned, `stage=post_request` reached the server, and the
// client was dead before `stage=pre_poll` 400 ms later, at the same 0xf4cb31
// the two earlier crashes hit. Streaming this mod's vehicle kills this game
// build whatever archive it came out of, so an observable built on it cannot
// classify anything: it fails identically on a good archive and a bad one.
//
// So the streaming half asks about a stock model instead. That measures the
// PROBE — that requesting and polling works here at all and does not fault —
// which is what makes a future `model_loaded=false` on a sample whose model
// does stream mean "the payload did not load" rather than "the probe is
// broken". Point it at a DLC model only when that model is known not to fault.
const STREAM_MODEL_NAME = "adder";
const STREAM_MODEL = mp.game.joaat(STREAM_MODEL_NAME);

// The streaming ceiling. Kept well under the server's own drop timeout: the
// server is not configured with one (`conf.json` has no timeout key) and the
// only measurement of it is that a client whose process died was reported
// `playerQuit type=timeout` some seconds later, so the ceiling is chosen to
// finish the whole sequence inside ten seconds rather than to race it.
const STREAM_CEILING_MS = 8000;
// The beat between announcing a risky call and making it, so the announcement
// reaches the server even if the call does not return.
const SETTLE_MS = 400;
// How often the streamer is asked. Each ask is one native call on the render
// tick and nothing else.
const POLL_MS = 250;

// Which half runs first. `true` — the acceptance natives, then the streaming
// control — because a join that dies still has to have produced the `class=`
// line that identifies which archive the game read. `false` puts the streaming
// half first, and is only worth setting when the streamed model is known not
// to fault this build.
var NATIVES_FIRST = true;

function say(event) {
    var args = Array.prototype.slice.call(arguments, 1);
    try {
        mp.gui.chat.push("rpf:" + event + " " + args.join(" "));
    } catch (e) {
        // The chat is a convenience for a person watching; the server line is
        // the evidence. Never let it take the report down with it.
    }
    mp.events.callRemote.apply(mp.events, ["rpf:" + event].concat(args));
}

function fail(where, e) {
    var message;
    try {
        message = String((e && e.message) || e);
    } catch (inner) {
        message = "unprintable";
    }
    say("error", "where=" + where, "message=" + message.replace(/\s+/g, "_"));
}

// A tiny state machine on the render tick. Each step announces what it is about
// to do, waits SETTLE_MS, does it, and moves on. No step loops, and no step
// does more than one native call.
var STEP = {
    ANNOUNCE_REQUEST: 0,
    REQUEST: 1,
    ANNOUNCE_POLL: 2,
    POLL: 3,
    ANNOUNCE_NATIVES: 4,
    NATIVE_CDIMAGE: 5,
    NATIVE_CLASS: 6,
    DONE: 7,
};

var step = STEP.DONE;
var due = 0;
var pollStarted = 0;
var lastPoll = 0;
var broken = false;
var inCdimage;
// Each half runs once, whichever order they run in and however they end. Two
// flags rather than an order-dependent chain, because the error paths join the
// chain too and a cycle there is an infinite one.
var nativesDone = false;
var streamDone = false;

// Two clocks drive the same state machine, because a probe with one clock is a
// probe that can be silent if that clock is missing — the failure this file
// exists to make impossible. `setTimeout` is the primary: it is proven on this
// client, docs/acceptance.md §7 used it. The render tick is the backup and
// costs a comparison a frame. Both call the same guarded step, and JavaScript
// is single-threaded, so a step cannot run twice.
function arm(delay) {
    try {
        if (typeof setTimeout === "function") {
            setTimeout(safeTick, delay + 1);
        }
    } catch (e) {
        // No timer: the render tick carries it.
    }
}

// Where to go when one half finishes: the other half, or the end.
function afterNatives() {
    nativesDone = true;
    return streamDone ? STEP.DONE : STEP.ANNOUNCE_REQUEST;
}

function afterStream() {
    streamDone = true;
    return nativesDone ? STEP.DONE : STEP.ANNOUNCE_NATIVES;
}

function schedule(next, delay) {
    step = next;
    due = Date.now() + delay;
    arm(delay);
}

function tick() {
    if (broken || step === STEP.DONE) {
        return;
    }
    var now = Date.now();
    if (now < due) {
        return;
    }

    switch (step) {
        case STEP.ANNOUNCE_REQUEST:
            say("probe", "stage=pre_request", "model=" + STREAM_MODEL_NAME);
            schedule(STEP.REQUEST, SETTLE_MS);
            return;

        case STEP.REQUEST:
            try {
                mp.game.streaming.requestModel(STREAM_MODEL);
            } catch (e) {
                fail("request_model", e);
                schedule(afterStream(), SETTLE_MS);
                return;
            }
            say("probe", "stage=post_request");
            schedule(STEP.ANNOUNCE_POLL, SETTLE_MS);
            return;

        case STEP.ANNOUNCE_POLL:
            say("probe", "stage=pre_poll");
            pollStarted = now + SETTLE_MS;
            lastPoll = 0;
            schedule(STEP.POLL, SETTLE_MS);
            return;

        case STEP.POLL: {
            if (now - lastPoll < POLL_MS) {
                return;
            }
            lastPoll = now;
            var loaded;
            try {
                loaded = mp.game.streaming.hasModelLoaded(STREAM_MODEL);
            } catch (e) {
                fail("has_model_loaded", e);
                schedule(afterStream(), SETTLE_MS);
                return;
            }
            var waited = now - pollStarted;
            if (!loaded && waited < STREAM_CEILING_MS) {
                arm(POLL_MS);
            }
            if (loaded || waited >= STREAM_CEILING_MS) {
                // Says whether the streamer answers here at all, on a model
                // this build is known to hold. It is not yet evidence about a
                // payload of ours: see STREAM_MODEL_NAME.
                say(
                    "streamed",
                    "model=" + STREAM_MODEL_NAME,
                    "model_loaded=" + loaded,
                    "waited_ms=" + waited
                );
                schedule(afterStream(), SETTLE_MS);
            }
            return;
        }

        case STEP.ANNOUNCE_NATIVES:
            say("probe", "stage=pre_natives");
            schedule(STEP.NATIVE_CDIMAGE, SETTLE_MS);
            return;

        case STEP.NATIVE_CDIMAGE:
            try {
                inCdimage = mp.game.streaming.isModelInCdimage(MODEL);
            } catch (e) {
                fail("is_model_in_cdimage", e);
                schedule(afterNatives(), SETTLE_MS);
                return;
            }
            // Said on its own, one frame before the second call, because either
            // call may end the process and half an answer beats none.
            say("probe", "stage=post_cdimage", "in_cdimage=" + inCdimage);
            schedule(STEP.NATIVE_CLASS, SETTLE_MS);
            return;

        case STEP.NATIVE_CLASS: {
            step = STEP.DONE;
            var vehicleClass;
            try {
                vehicleClass = mp.game.vehicle.getVehicleClassFromName(MODEL);
            } catch (e) {
                fail("get_vehicle_class_from_name", e);
                schedule(afterNatives(), SETTLE_MS);
                return;
            }
            say("acceptance", "in_cdimage=" + inCdimage, "class=" + vehicleClass);
            schedule(afterNatives(), SETTLE_MS);
            return;
        }
    }
}

function safeTick() {
    if (broken) {
        return;
    }
    try {
        tick();
    } catch (e) {
        // Report once and stop, rather than once a frame.
        broken = true;
        fail("tick", e);
    }
}

mp.events.add("render", safeTick);

mp.events.add("playerReady", function () {
    try {
        say("joined", "model=" + MODEL_NAME, "hash=" + MODEL);
        schedule(NATIVES_FIRST ? STEP.ANNOUNCE_NATIVES : STEP.ANNOUNCE_REQUEST, SETTLE_MS);
    } catch (e) {
        fail("player_ready", e);
    }
});
