// The acceptance loop's server half. It ships the archive and prints what the
// client found in it; it never parses the archive. docs/acceptance.md.
//
// Every line it prints is prefixed `rpf:` and carries a timestamp, because the
// interval between a report and a disconnect is what separates a client that
// answered and left from a client that died mid-answer. acceptance.sh
// classifies these lines and nothing else interprets anything.
function line(text) {
    console.log("rpf:" + text + " at=" + new Date().toISOString());
}

mp.events.add("rpf:joined", (player, model, hash) => {
    line(`joined player=${player.name} ${model} ${hash}`);
});

// A breadcrumb the client leaves before every native call that has been seen to
// end its process. The last one printed names what it was about to do.
mp.events.add("rpf:probe", (player, stage, detail) => {
    line(`probe ${stage}${detail === undefined ? "" : " " + detail}`);
});

mp.events.add("rpf:streamed", (player, model, modelLoaded, waited) => {
    line(`streamed ${model} ${modelLoaded} ${waited}`);
});

mp.events.add("rpf:acceptance", (player, inCdimage, vehicleClass) => {
    line(`acceptance ${inCdimage} ${vehicleClass}`);
});

mp.events.add("rpf:error", (player, where, message) => {
    line(`error ${where} ${message}`);
});

mp.events.add("playerJoin", (player) => {
    line(`connect player=${player.name}`);
});

mp.events.add("playerQuit", (player, exitType, reason) => {
    line(`quit player=${player.name} type=${exitType} reason=${reason}`);
});
