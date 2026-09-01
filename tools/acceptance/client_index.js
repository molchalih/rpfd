// The acceptance loop's client half. It reports what the game found in the
// mounted archive; it never reads the archive itself.
//
// Any model-info lookup on this model may end the client process, so every
// risky call is announced a beat before it is made and every path reports:
// silence would be indistinguishable from a payload that did not load.
const MODEL_NAME = "volga5";
const MODEL = mp.game.joaat(MODEL_NAME);

// The models the streaming half asks about, in order, and why there are two.
// The first is a stock one: it measures the probe itself, so that a
// `model_loaded=false` on the second means the payload did not load rather than
// the probe is broken. The second is the pack's OWN model, which is the
// question this loop was built to reach — whether the game read a large binary
// payload out of the archive under test.
//
// Asking the pack's model is new and deliberate. The first sample's could not
// be asked: REQUEST_MODEL on `meringls63amg24` ended the client inside 400 ms
// from the untouched archive, three times, at one instruction. This pack is a
// different producer and a 2020 build, so the question is open again — and the
// stock model goes first so that a death on the second is attributable.
const STREAM_MODEL_NAMES = ["adder", MODEL_NAME];
var streamIndex = 0;

function streamName() {
    return STREAM_MODEL_NAMES[streamIndex];
}

function streamModel() {
    return mp.game.joaat(streamName());
}

// The streaming ceiling, chosen to finish the whole sequence inside ten
// seconds rather than race the server's unconfigured drop timeout.
const STREAM_CEILING_MS = 8000;
// The beat between announcing a risky call and making it, so the announcement
// reaches the server even if the call does not return.
const SETTLE_MS = 400;
// How often the streamer is asked: one native call on the render tick.
const POLL_MS = 250;

// Which half runs first. `true` puts the acceptance natives first, so a join
// that dies has still produced the `class=` line naming the archive the game
// read; `false` is only safe when the streamed model cannot fault this build.
var NATIVES_FIRST = true;

function say(event) {
    var args = Array.prototype.slice.call(arguments, 1);
    try {
        mp.gui.chat.push("rpf:" + event + " " + args.join(" "));
    } catch (e) {
        // The chat is a convenience; the server line is the evidence.
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

// A state machine on the render tick: each step announces what it is about to
// do, waits SETTLE_MS, does it. No step loops or makes two native calls.
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
// Each half runs once, in either order. Two flags rather than a chain: the
// error paths rejoin it too, and a cycle there would be infinite.
var nativesDone = false;
var streamDone = false;

// Two clocks drive the same state machine, since a probe with one clock goes
// silent if that clock is missing. Both call the same guarded step, and
// JavaScript is single-threaded, so a step cannot run twice.
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
            say("probe", "stage=pre_request", "model=" + streamName());
            schedule(STEP.REQUEST, SETTLE_MS);
            return;

        case STEP.REQUEST:
            try {
                mp.game.streaming.requestModel(streamModel());
            } catch (e) {
                fail("request_model", e);
                streamIndex = STREAM_MODEL_NAMES.length;
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
                loaded = mp.game.streaming.hasModelLoaded(streamModel());
            } catch (e) {
                fail("has_model_loaded", e);
                streamIndex = STREAM_MODEL_NAMES.length;
                schedule(afterStream(), SETTLE_MS);
                return;
            }
            var waited = now - pollStarted;
            if (!loaded && waited < STREAM_CEILING_MS) {
                arm(POLL_MS);
            }
            if (loaded || waited >= STREAM_CEILING_MS) {
                // For the stock model this says whether the streamer answers
                // at all; for the pack's own it is the large-binary question.
                say(
                    "streamed",
                    "model=" + streamName(),
                    "model_loaded=" + loaded,
                    "waited_ms=" + waited
                );
                streamIndex += 1;
                if (streamIndex < STREAM_MODEL_NAMES.length) {
                    schedule(STEP.ANNOUNCE_REQUEST, SETTLE_MS);
                } else {
                    schedule(afterStream(), SETTLE_MS);
                }
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
            // Said before the second call: either may end the process, and
            // half an answer beats none.
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
